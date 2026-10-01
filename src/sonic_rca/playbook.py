"""Playbook executor: YAML-defined checks -> evidence-linked findings."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from .archive import SYSLOG_GLOB
from .index import EvidenceIndex
from .keymaps import (get_benign, get_filter, get_fragment, get_map,
                      get_refiner, field_for, norm_field)
from .schema import Finding


@dataclass
class Playbook:
    id: str
    feature: str
    intent_db: str
    intent_pattern: str
    reality_db: str
    reality_map: str
    compare: list[str] = field(default_factory=list)
    correlate: list[dict] = field(default_factory=list)
    severity: str = "medium"
    stage_missing: str = "unknown"
    stage_mismatch: str = "unknown"
    object_type: str = "OBJECT"
    intent_filter: Optional[str] = None
    fragment: str = "last"
    expect: dict = field(default_factory=dict)
    benign: Optional[str] = None
    refine_missing: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "Playbook":
        d = yaml.safe_load(path.read_text())
        od = d.get("on_divergence", {})
        return cls(
            id=d["id"], feature=d.get("feature", d["id"].split(".")[0]),
            intent_db=d["intent"]["db"], intent_pattern=d["intent"]["pattern"],
            reality_db=d["reality"]["db"], reality_map=d["reality"]["map"],
            compare=d.get("compare", []), correlate=d.get("correlate", []),
            severity=od.get("severity", "medium"),
            stage_missing=od.get("stage_missing", "unknown"),
            stage_mismatch=od.get("stage_mismatch", "unknown"),
            object_type=d.get("object_type", d["id"].split(".")[0].upper()),
            intent_filter=d["intent"].get("filter"),
            fragment=d.get("fragment", "last"),
            expect=d["reality"].get("expect", {}),
            benign=d["reality"].get("benign"),
            refine_missing=od.get("refine_missing", []),
        )


def load_playbooks(directory: Path) -> list[Playbook]:
    return [Playbook.load(p) for p in sorted(directory.glob("*.yaml"))]


class PlaybookRunner:
    def __init__(self, index: EvidenceIndex, playbook_dir: Path):
        self.index = index
        self.playbooks = load_playbooks(playbook_dir)
        self._fn = 0
        self.notes: list[dict] = []  # benign expected-state mismatches

    def _next_id(self) -> str:
        self._fn += 1
        return f"F-{self._fn:04d}"

    # ------------------------------------------------------------------

    def run(self, feature: Optional[str] = None) -> list[Finding]:
        findings: list[Finding] = []
        for pb in self.playbooks:
            if feature and pb.feature != feature:
                continue
            findings.extend(self._run_one(pb))
        return findings

    def _run_one(self, pb: Playbook) -> list[Finding]:
        out: list[Finding] = []
        try:
            intents = self.index.db_get(pb.intent_db, pb.intent_pattern)
        except Exception:
            return out  # snapshot absent in this archive; skip check
        mapper = get_map(pb.reality_map)
        keep = get_filter(pb.intent_filter) if pb.intent_filter else None
        for ikey, ival in intents.items():
            if keep is not None and not (keep(ikey, ival, self.index)
                                         if keep.with_index else keep(ikey, ival)):
                continue
            reality_key, note = mapper(self.index, ikey)
            ev = [self.index.cite_db(pb.intent_db, ikey)]
            if reality_key is None:
                ev.append(self.index.register(
                    pb.reality_db.split("_")[0].lower(),
                    self.index.src.db_file(pb.reality_db),
                    f"absent: {note}"))
                out.append(self._finding(pb, ikey, ival, None, None, ev,
                                         missing=True,
                                         stage=self._refine(pb, ikey, ev)))
                continue
            rval = self.index.db_key(pb.reality_db, reality_key) or {}
            diffs_exp, diffs_obs = {}, {}
            for f in pb.compare:
                inf, ref = field_for(pb.intent_db, f), field_for(pb.reality_db, f)
                if inf not in ival or ref not in rval:
                    continue
                a, b = norm_field(f, ival[inf]), norm_field(f, rval[ref])
                if a != b:
                    diffs_exp[f], diffs_obs[f] = ival[inf], rval[ref]
            for f, want in pb.expect.items():
                got = rval.get(field_for(pb.reality_db, f))
                if norm_field(f, got) != norm_field(f, want):
                    diffs_exp[f], diffs_obs[f] = want, got
            if diffs_exp and pb.benign and get_benign(pb.benign)(reality_key, rval):
                self.notes.append({"check": pb.id, "key": ikey,
                                   "rule": pb.benign, "observed": diffs_obs,
                                   "evidence": self.index.cite_db(pb.reality_db,
                                                                  reality_key)})
                continue
            if diffs_exp:
                ev.append(self.index.cite_db(pb.reality_db, reality_key))
                out.append(self._finding(pb, ikey, diffs_exp, diffs_obs,
                                         reality_key, ev, missing=False))
        return out

    def _refine(self, pb: Playbook, key: str, ev: list[str]) -> Optional[str]:
        """First refine_missing rule whose recording condition holds.

        rule: {stage, rec_last: <regex on the newest sairedis.rec line naming
        the object (needle = rec_fragment(key), default the playbook's)>,
        unless_log: <syslog regex; {frag} = log_fragment(key)>}.
        E.g. last op a create and no SAI error logged -> ASIC state changed
        without orchagent asking (reality drift).
        Or {stage, check: <keymaps refiner name>}: a DB-evidence condition.
        """
        for rule in pb.refine_missing:
            if "check" in rule:
                ev_id = get_refiner(rule["check"])(self.index, key)
                if ev_id:
                    ev.append(ev_id)
                    return rule["stage"]
                continue
            needle = get_fragment(rule.get("rec_fragment", pb.fragment))(key)
            hit = self.index.last_rec_op("sairedis", needle)
            if hit is None or not re.search(rule["rec_last"], hit.line):
                continue
            if rule.get("unless_log"):
                frag = get_fragment(rule.get("log_fragment", pb.fragment))(key)
                rx = rule["unless_log"].replace("{frag}", re.escape(frag))
                if self.index.search_logs(rx, SYSLOG_GLOB, limit=1):
                    continue
            ev.append(hit.evidence_id)
            return rule["stage"]
        return None

    def _finding(self, pb: Playbook, key: str, expected, observed,
                 reality_key: Optional[str], ev: list[str],
                 missing: bool, stage: Optional[str] = None) -> Finding:
        correlated = self._correlate(pb, key, ev)
        return Finding(
            id=self._next_id(), check=pb.id, object_type=pb.object_type,
            key=key, layer_expected=f"{pb.intent_db}",
            layer_missing=f"{pb.reality_db}" if missing else None,
            expected=expected if isinstance(expected, dict) else dict(expected or {}),
            observed=observed,
            severity=pb.severity,
            suspected_stage=stage or (pb.stage_missing if missing
                                      else pb.stage_mismatch),
            evidence=ev, correlated=correlated,
        )

    def _correlate(self, pb: Playbook, key: str, ev: list[str]) -> dict:
        """Attach log/recording evidence per the playbook's correlate spec."""
        corr: dict = {}
        frag = get_fragment(pb.fragment)(key)
        for spec in pb.correlate:
            src = spec.get("source", "syslog")
            if src == "syslog":
                rx = spec.get("match", "{frag}").replace("{frag}", re.escape(frag))
                hits = self.index.search_logs(rx, spec.get("files", SYSLOG_GLOB),
                                              limit=5,
                                              newest=bool(spec.get("newest")))
            elif src in ("sairedis.rec", "swss.rec"):
                hits = self.index.search_rec(src.split(".")[0], frag, limit=5)
            else:
                continue
            if hits:
                ids = [h.evidence_id for h in hits]
                corr.setdefault(src, []).extend(ids)
                ev.extend(ids)
        return corr

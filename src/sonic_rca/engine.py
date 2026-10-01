"""Engine: archive -> divergence report; plus cross-layer object tracing."""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .archive import TechsupportSource
from .index import SERVICE_PARENT, EvidenceIndex
from .keymaps import get_fragment, get_map
from .playbook import PlaybookRunner
from .schema import DivergenceReport

DEFAULT_PLAYBOOKS = Path(__file__).resolve().parents[2] / "playbooks"

# pipeline stage token -> container that runs it
STAGE_CONTAINER = {
    "orchagent": "swss", "aclorch": "swss", "vlanmgrd": "swss", "portmgrd": "swss",
    "intfmgrd": "swss", "nbrmgrd": "swss", "neighsyncd": "swss",
    "fdbsyncd": "swss", "portsyncd": "swss", "syncd": "syncd",
    "bgp": "bgp", "frr": "bgp", "zebra": "bgp", "fpmsyncd": "bgp",
    "frrcfgd": "bgp", "staticd": "bgp",
    "teamd": "teamd",
}


def attribute_service_down(findings: list, health: dict) -> None:
    """A finding whose stage runs in a stopped container is a consequence of
    that stop: re-attribute it to the root stopped service (see
    index.SERVICE_PARENT), keep the playbook stage, cite the service line."""
    down = {s["name"]: s for s in health.get("services", [])}
    roots = health.get("root_services", [])
    if not down or not roots:
        return
    for f in findings:
        tokens = [t for t in re.split(r"[|/]", f.suspected_stage) if t]
        hit = [STAGE_CONTAINER[t] for t in tokens
               if STAGE_CONTAINER.get(t) in down]
        if not hit:
            continue
        c = hit[0]
        while c not in roots and SERVICE_PARENT.get(c) in down:
            c = SERVICE_PARENT[c]
        f.correlated["playbook_stage"] = f.suspected_stage
        f.correlated["service_down"] = down[c]["evidence"]
        f.suspected_stage = c
        f.evidence.extend(e for e in down[c]["evidence"] if e not in f.evidence)


class Session:
    """One loaded techsupport source + its evidence index."""

    def __init__(self, path: str, playbook_dir: Optional[Path] = None):
        self.source = TechsupportSource(path)
        self.index = EvidenceIndex(self.source)
        self.playbook_dir = Path(playbook_dir or DEFAULT_PLAYBOOKS)
        self._report: Optional[DivergenceReport] = None

    # ------------------------------------------------------------------

    def report(self, feature: Optional[str] = None,
               refresh: bool = False) -> DivergenceReport:
        if self._report is not None and not refresh and feature is None:
            return self._report
        runner = PlaybookRunner(self.index, self.playbook_dir)
        findings = runner.run(feature)
        health = self.index.health()
        attribute_service_down(findings, health)
        if runner.notes:
            health["notes"] = runner.notes
        rep = DivergenceReport(
            meta={
                "source": "dump",
                "sonic_version": self.source.meta.get("sonic_version", "unknown"),
                "hostname": self.source.meta.get("hostname", "unknown"),
                "captured": self.source.meta.get("captured", "unknown"),
                "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "dbs": self.source.available_dbs(),
                "playbooks": [pb.id for pb in runner.playbooks],
            },
            health=health,
            findings=findings,
            evidence=self.index.evidence,
        )
        if feature is None:
            self._report = rep
        return rep

    # ------------------------------------------------------------------

    def trace(self, key: str) -> dict:
        """Follow one object across layers, citing what is found where."""
        hops: list[dict] = []

        def probe(db: str, k: str):
            val = self.index.db_key(db, k)
            ev = self.index.cite_db(db, k) if val is not None else None
            hops.append({"layer": db, "key": k,
                         "present": val is not None,
                         "value": val, "evidence": ev})
            return val is not None

        def missing(db: str, note: str):
            hops.append({"layer": db, "key": note, "present": False,
                         "value": None, "evidence": None})

        def chain(db: str, mapname: str, k: str):
            nxt, note = get_map(mapname)(self.index, k)
            if nxt:
                probe(db, nxt)
            else:
                missing(db, note)

        frag = key.replace("|", ":").split(":", 1)[-1]
        if key.startswith(("PORT|", "VLAN_MEMBER|", "VLAN|", "INTERFACE|")):
            probe("CONFIG_DB", key)
            table = key.split("|", 1)[0]
            nxt = {"PORT": "port_table", "VLAN_MEMBER": "vlan_member_table",
                   "INTERFACE": "intf_table", "VLAN": None}.get(table)
            if nxt:
                appl_key, _ = get_map(nxt)(self.index, key)
                if appl_key and probe("APPL_DB", appl_key):
                    if table == "PORT":
                        asic, _ = get_map("sai_port_admin")(self.index, appl_key)
                        if asic:
                            probe("ASIC_DB", asic)
                    elif table == "INTERFACE" and key.count("|") == 2:
                        chain("ASIC_DB", "sai_intf_subnet_route", appl_key)
            if table == "VLAN":
                asic, _ = get_map("sai_vlan")(self.index, key)
                if asic:
                    probe("ASIC_DB", asic)
        elif key.startswith(("ROUTE_TABLE:", "RIB|")):
            appl = key
            if key.startswith("RIB|"):
                probe("FRR_RIB", key)
                appl, note = get_map("appl_route_from_rib")(self.index, key)
                if appl is None:
                    missing("APPL_DB", note)
            if appl and probe("APPL_DB", appl):
                chain("ASIC_DB", "sai_route_entry", appl)
            frag = get_fragment("route_dest")(key)
        elif key.startswith("BGP_NEIGHBOR|"):
            if probe("CONFIG_DB", key):
                chain("FRR_BGP", "frr_bgp_peer", key)
            frag = get_fragment("bgp_peer")(key)
        elif key.startswith(("FDB_TABLE|", "FDB_TABLE:")):
            probe("STATE_DB" if "|" in key else "APPL_DB", key)
            chain("ASIC_DB", "sai_fdb_entry", key)
            frag = get_fragment("fdb_mac")(key)
        elif key.startswith("NEIGH_TABLE:"):
            if probe("APPL_DB", key):
                chain("ASIC_DB", "sai_neighbor_entry", key)
            frag = get_fragment("neigh_ip_json")(key)
        else:
            for db in ("CONFIG_DB", "APPL_DB", "STATE_DB", "ASIC_DB"):
                try:
                    probe(db, key)
                except Exception:
                    pass

        recs = self.index.search_rec("sairedis", frag, limit=5)
        return {"key": key, "hops": hops,
                "sairedis": [asdict_hit(h) for h in recs]}


def asdict_hit(h) -> dict:
    return {"file": h.file, "line": h.lineno, "text": h.line,
            "evidence": h.evidence_id}

"""Benchmark harness.

Corpus layout (see corpus/README.md):
  <corpus>/<scenario>/techsupport.tar.gz     (or extracted dir techsupport/)
  <corpus>/<scenario>/ground_truth.yaml      {stage: ..., root_cause: ...}

Arms:
  tools    — model receives the divergence report JSON (deterministic layer
             output) and must answer with cited evidence ids.
  baseline — model receives the raw archive file listing plus bounded raw
             excerpts (syslog tail, DB key listings), no sonic-rca analysis.

Both arms use the same answer contract and the same mechanical scorer.
Results are written per-scenario (answer transcript + score) plus a summary
markdown table. Scores are only meaningful with a real LLM arm on a real
corpus; `--model` omitted runs plumbing only (NullClient), clearly labeled.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from ..archive import SYSLOG_GLOB
from ..engine import Session
from .llm import make_client
from .score import parse_answer, score

_ANSWER_CONTRACT = (
    "Answer ONLY with JSON: {\"root_cause_stage\": <one SONiC stage, e.g. "
    "vlanmgrd|orchagent|syncd|swss|bgp/frr|zebra/fpmsyncd|staticd|portmgrd|"
    "neighorch|intfmgrd|aclorch|reality-drift>, \"summary\": <one sentence>, "
    "\"evidence\": [<evidence ids you rely on>]}. "
    "Cite only evidence ids that exist in the material given. "
    "If evidence is insufficient, say so in summary and cite nothing."
)

_SYSTEM_TOOLS = (
    "You are a SONiC root-cause analyst. You receive a sonic-rca divergence "
    "report: deterministic cross-layer findings with evidence ids. Interpret "
    "it; do not invent objects or evidence. " + _ANSWER_CONTRACT
)

_SYSTEM_BASELINE = (
    "You are a SONiC root-cause analyst. You receive raw excerpts from a "
    "techsupport archive with evidence ids per excerpt. No analysis tooling "
    "is available. " + _ANSWER_CONTRACT
)


def _scenario_source(sc_dir: Path) -> str:
    tb = sc_dir / "techsupport.tar.gz"
    if tb.exists():
        return str(tb)
    d = sc_dir / "techsupport"
    if d.is_dir():
        return str(d)
    raise FileNotFoundError(f"{sc_dir}: no techsupport.tar.gz or techsupport/")


def _baseline_material(session: Session) -> tuple[str, set[str]]:
    """Raw-excerpt material for the no-tools arm, with its own evidence ids."""
    idx = session.index
    parts = ["FILE LISTING:"]
    parts += [f"  dump/{db}.json" for db in session.source.available_dbs()]
    parts += [f"  {session.source.rel(f)}" for f in session.source.log_files()][:40]
    for db in session.source.available_dbs():
        keys = list(idx.db_get(db).keys())[:60]
        ev = idx.register("raw", session.source.db_file(db), "key listing")
        parts.append(f"\n{db} KEYS [{ev}]:")
        parts += [f"  {k}" for k in keys]
    hits = idx.search_logs(r"ERR|WARNING|orchagent|mgrd", SYSLOG_GLOB, limit=40)
    parts.append("\nSYSLOG MATCHES:")
    parts += [f"  [{h.evidence_id}] {h.file}:{h.lineno}: {h.line}" for h in hits]
    return "\n".join(parts), set(idx.evidence.keys())


def run_bench(corpus: str, arm: str = "tools", model: str | None = None,
              out_dir: str = "bench_results") -> str:
    corpus_p, out_p = Path(corpus), Path(out_dir)
    out_p.mkdir(parents=True, exist_ok=True)
    client = make_client(model)
    arms = ["tools", "baseline"] if arm == "both" else [arm]
    rows = []

    for sc_dir in sorted(p for p in corpus_p.iterdir() if p.is_dir()):
        gt_file = sc_dir / "ground_truth.yaml"
        if not gt_file.exists():
            continue
        truth = yaml.safe_load(gt_file.read_text())
        for a in arms:
            session = Session(_scenario_source(sc_dir))
            if a == "tools":
                rep = session.report()
                material = rep.to_json()
                valid = set(rep.evidence.keys())
                system = _SYSTEM_TOOLS
            else:
                material, valid = _baseline_material(session)
                system = _SYSTEM_BASELINE
            raw = client.complete(system, f"Scenario material:\n{material}")
            ans = parse_answer(raw)
            sc = score(ans, truth, valid)
            rows.append({"scenario": sc_dir.name, "arm": a,
                         "model": client.name, **sc,
                         "answer_stage": ans.get("root_cause_stage")})
            (out_p / f"{sc_dir.name}.{a}.json").write_text(json.dumps(
                {"truth": truth, "raw_answer": raw, "parsed": ans, "score": sc},
                indent=2))

    lines = [f"# sonic-rca benchmark — model: {client.name}", "",
             "| scenario | arm | stage answered | exact | loc | evid | honest | total/5 |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['scenario']} | {r['arm']} | {r['answer_stage']} "
                     f"| {r['exact']} | {r['localized']} | {r['evidence']} "
                     f"| {r['honesty']} | {r['total']} |")
    if rows:
        for a in arms:
            sub = [r for r in rows if r["arm"] == a]
            mean = sum(r["total"] for r in sub) / len(sub)
            lines.append(f"\n**{a} arm mean: {mean:.2f}/5 over {len(sub)} scenarios**")
    if model is None:
        lines.append("\n_Plumbing run (no LLM). Not a reportable result._")
    summary = "\n".join(lines)
    (out_p / "SUMMARY.md").write_text(summary)
    return summary

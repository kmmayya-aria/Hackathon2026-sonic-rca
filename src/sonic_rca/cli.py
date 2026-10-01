"""sonic-rca CLI — the no-AI interface.

  sonic-rca report <dump> [--json] [--feature F] [--playbooks DIR]
  sonic-rca trace  <dump> <key>
  sonic-rca logs   <dump> <regex> [--files GLOB]
  sonic-rca serve                       # MCP server over stdio
  sonic-rca bench  <corpus_dir> [...]   # benchmark harness (see bench/)
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from .archive import SYSLOG_GLOB
from .engine import Session


def _fmt_report(rep) -> str:
    lines = [f"sonic-rca divergence report — host={rep.meta.get('hostname')} "
             f"version={rep.meta.get('sonic_version')} "
             f"captured={rep.meta.get('captured')}",
             f"DBs: {', '.join(rep.meta.get('dbs', []))} | "
             f"checks: {', '.join(rep.meta.get('playbooks', []))}", ""]
    h = rep.health
    if h.get("services") or h.get("core_dumps") or h.get("capture") or h.get("notes"):
        lines.append("HEALTH:")
        for s in h.get("services", []):
            lines.append(f"  service {s['name']}: {s['state']}  "
                         f"[{', '.join(s['evidence'])}]")
        if h.get("root_services"):
            lines.append(f"  root stopped service(s): {', '.join(h['root_services'])}")
        for c in h.get("core_dumps", []):
            lines.append(f"  core dump: {c['file']}  [{', '.join(c['evidence'])}]")
        for c in h.get("capture", []):
            lines.append(f"  capture: {c['issue']}  [{', '.join(c['evidence'])}]")
        for n in h.get("notes", []):
            lines.append(f"  note: {n['check']} {n['key']} observed={n['observed']} "
                         f"({n['rule']}, not a pipeline divergence)  [{n['evidence']}]")
        lines.append("")
    if not rep.findings:
        lines.append("No divergence found by enabled playbooks.")
    for f in rep.findings:
        where = (f"pending in {f.layer_expected}, never applied by its consumer"
                 if f.layer_missing == f.layer_expected else
                 f"present in {f.layer_expected}, MISSING in {f.layer_missing}"
                 if f.layer_missing else
                 f"attribute mismatch {f.layer_expected} vs reality")
        lines.append(f"{f.id} [{f.severity}] {f.check} :: {f.key}")
        pbs = f.correlated.get("playbook_stage")
        lines.append(f"     {where}; suspected stage: {f.suspected_stage}"
                     + (f" (container down; playbook stage: {pbs})" if pbs else ""))
        if f.expected:
            lines.append(f"     expected={f.expected} observed={f.observed}")
        lines.append(f"     evidence: {', '.join(f.evidence)}")
    lines.append("")
    lines.append(f"{len(rep.findings)} finding(s), "
                 f"{len(rep.evidence)} evidence item(s). "
                 "Every id resolves via `get_evidence`/report JSON.")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sonic-rca")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("report", help="run playbooks, print divergence report")
    p.add_argument("dump"); p.add_argument("--json", action="store_true")
    p.add_argument("--feature"); p.add_argument("--playbooks")

    p = sub.add_parser("trace", help="follow one object across layers")
    p.add_argument("dump"); p.add_argument("key")

    p = sub.add_parser("logs", help="regex search logs with evidence ids")
    p.add_argument("dump"); p.add_argument("regex")
    p.add_argument("--files", default=SYSLOG_GLOB,
                   help="'|'-separated filename globs under log/")

    sub.add_parser("serve", help="run the MCP server over stdio")

    p = sub.add_parser("bench", help="run the fault-injection benchmark")
    p.add_argument("corpus"); p.add_argument("--arm", default="tools",
                                             choices=["tools", "baseline", "both"])
    p.add_argument("--model", default=None,
                   help="LLM id (requires API access); omit for deterministic-only")
    p.add_argument("--out", default="bench_results")

    a = ap.parse_args(argv)

    if a.cmd == "report":
        s = Session(a.dump, playbook_dir=a.playbooks)
        rep = s.report(feature=a.feature)
        print(rep.to_json() if a.json else _fmt_report(rep))
    elif a.cmd == "trace":
        s = Session(a.dump)
        print(json.dumps(s.trace(a.key), indent=2, default=str))
    elif a.cmd == "logs":
        s = Session(a.dump)
        for h in s.index.search_logs(a.regex, a.files):
            print(f"{h.file}:{h.lineno}: {h.line}   [{h.evidence_id}]")
    elif a.cmd == "serve":
        from .mcp_server import main as serve_main
        serve_main()
    elif a.cmd == "bench":
        from .bench.harness import run_bench
        summary = run_bench(a.corpus, arm=a.arm, model=a.model, out_dir=a.out)
        print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())

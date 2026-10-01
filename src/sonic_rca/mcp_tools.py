"""MCP tool surface (v0) — implementations over a loaded Session.

Every tool is read-only and operates on an archived techsupport tarball
(or extracted dir). `load_dump` must be called first; the other tools
operate on the loaded session. Surface matches docs/DESIGN.md §6.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Optional

from .archive import SYSLOG_GLOB
from .engine import Session

_session: Optional[Session] = None


def _s() -> Session:
    if _session is None:
        raise RuntimeError("no dump loaded — call load_dump(path) first")
    return _session


def load_dump(path: str) -> dict:
    """Open a techsupport tarball (or extracted dir) and index it."""
    global _session
    _session = Session(path)
    return source_info()


def source_info() -> dict:
    s = _s()
    return {"meta": {k: v for k, v in s.source.meta.items()
                     if k != "version_capture"},
            "dbs": s.source.available_dbs(),
            "log_files": len(s.source.log_files()),
            "core_dumps": s.source.core_dumps()}


def get_db(db: str, pattern: str = "*", limit: int = 100) -> dict:
    rows = _s().index.db_get(db, pattern)
    items = dict(list(rows.items())[:limit])
    return {"db": db, "pattern": pattern, "total": len(rows), "items": items}


def trace_object(key: str) -> dict:
    return _s().trace(key)


def diff_pipeline(feature: Optional[str] = None) -> dict:
    rep = _s().report(feature=feature, refresh=feature is not None)
    return {"findings": [asdict(f) for f in rep.findings]}


def search_logs(regex: str, files: str = SYSLOG_GLOB, limit: int = 50) -> dict:
    hits = _s().index.search_logs(regex, files, limit=limit)
    return {"hits": [{"file": h.file, "line": h.lineno, "text": h.line,
                      "evidence": h.evidence_id} for h in hits]}


def service_health() -> dict:
    return _s().index.health()


def get_report() -> dict:
    import json
    return json.loads(_s().report().to_json())


def get_evidence(evidence_id: str) -> dict:
    ev = _s().index.resolve(evidence_id)
    if ev is None:
        return {"error": f"unknown evidence id {evidence_id}"}
    return asdict(ev)


def explain_check(check_id: str) -> dict:
    from .playbook import load_playbooks
    for pb in load_playbooks(_s().playbook_dir):
        if pb.id == check_id:
            return asdict(pb) if hasattr(pb, "__dataclass_fields__") else vars(pb)
    return {"error": f"unknown check {check_id}"}

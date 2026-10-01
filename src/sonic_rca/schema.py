"""Divergence report schema (v0) — frozen at design time.

Design contract: the deterministic layer never emits prose conclusions.
`Finding.suspected_stage` is the only interpretation it makes, derived
mechanically from which layer transition broke. Verdict narrative belongs to
the AI layer and must reference finding/evidence IDs from this report.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional

SCHEMA_VERSION = "0"

# Layers of the SONiC state pipeline, in propagation order.
LAYERS = ("CONFIG_DB", "APPL_DB", "ASIC_DB", "SAI")

# Redis DB snapshots present in a 202605 techsupport archive
# (generate_dump save_redis_info, sonic-utilities branch 202605).
TECHSUPPORT_DBS = (
    "APPL_DB", "ASIC_DB", "COUNTERS_DB", "CONFIG_DB",
    "FLEX_COUNTER_DB", "STATE_DB", "APPL_STATE_DB",
)

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Evidence:
    """One addressable piece of raw evidence inside the archive."""
    id: str                 # e.g. "ev:appl:2214"
    source: str             # archive-relative path, e.g. "dump/APPL_DB.json"
    locator: str            # redis key, line number, or record offset
    excerpt: Optional[str] = None  # short verbatim excerpt (bounded)


@dataclass
class ServiceHealth:
    name: str
    state: str              # "running" | "exited" | "crash-loop" | "absent"
    evidence: list[str] = field(default_factory=list)


@dataclass
class Finding:
    id: str                 # "F-0003"
    check: str              # playbook id, e.g. "route.programming"
    object_type: str        # e.g. "ROUTE_ENTRY"
    key: str                # object identity, e.g. "10.0.0.0/24"
    layer_expected: str     # where intent was found
    layer_missing: Optional[str]   # where reality diverged (None if attr diff)
    expected: Optional[dict]
    observed: Optional[dict]
    severity: str
    suspected_stage: str    # mechanical: e.g. "orchagent", "vlanmgrd", "syncd"
    evidence: list[str] = field(default_factory=list)
    correlated: dict = field(default_factory=dict)


@dataclass
class DivergenceReport:
    meta: dict
    health: dict            # {"services", "core_dumps", "capture", ["notes"]: [...]}
    findings: list[Finding]
    evidence: dict[str, Evidence]
    schema_version: str = SCHEMA_VERSION

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent, default=str)

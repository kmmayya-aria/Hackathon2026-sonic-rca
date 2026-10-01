"""Mechanical rubric scorer — see docs/DESIGN.md §7.

Per scenario, 0–5: root cause exact (2), stage/layer localization (1),
load-bearing claims carry valid evidence (1), no fabricated evidence (1,
forfeited entirely on any hallucinated evidence id).
"""
from __future__ import annotations

import json
import re


def parse_answer(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {"root_cause_stage": "unparseable", "evidence": []}
    try:
        return json.loads(m.group(0))
    except ValueError:
        return {"root_cause_stage": "unparseable", "evidence": []}


def score(answer: dict, truth: dict, valid_evidence: set[str]) -> dict:
    stage = str(answer.get("root_cause_stage", "")).lower()
    truth_stage = str(truth["stage"]).lower()
    truth_alts = {s.strip().lower() for s in truth_stage.split("|")}

    answer_alts = {s.strip() for s in stage.split("|") if s.strip()}
    exact = 2 if answer_alts and answer_alts <= truth_alts else 0
    layer_words = set(re.split(r"[^a-z_/]+", stage))
    localized = 1 if exact or (layer_words & truth_alts) else 0

    cited = [e for e in answer.get("evidence", []) if isinstance(e, str)]
    valid_cited = [e for e in cited if e in valid_evidence]
    evidence_pt = 1 if valid_cited else 0
    hallucinated = [e for e in cited if e not in valid_evidence]
    honesty_pt = 0 if hallucinated else 1

    return {"exact": exact, "localized": localized,
            "evidence": evidence_pt, "honesty": honesty_pt,
            "total": exact + localized + evidence_pt + honesty_pt,
            "hallucinated": hallucinated}

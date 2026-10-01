# sonic-rca — Design & Implementation Plan

Target: community SONiC **202605** (sonic-vs). Status: pre-hackathon design.
Provenance: this document, the repo skeleton, the playbook format, the fault
scenario definitions, and the corpus tooling are **declared prior work**. All
analysis tooling (parsers, walk engine, MCP server, benchmark harness) is
built during the hackathon window (Sep 28 – Oct 1).

---

## 1. Goal & non-goals

**Goal.** Convert an archived `show techsupport` tarball into a root-cause
verdict where every conclusion cites the redis key, log line, or SAI record
supporting it. Fully offline; no switch access of any kind. Deterministic tooling performs the
cross-layer intent-vs-reality analysis; the LLM only interprets the resulting
divergence report.

**Non-goals (hackathon scope).**
- No live-switch mode: input is archived techsupport tarballs only. No switch
  access, read or write.
- No real-ASIC fault classes; the benchmark taxonomy is limited to what
  sonic-vs can express (control-plane and DB-pipeline faults).
- No vendor-specific artifact parsing; vendor sections of an archive are
  treated as opaque and skipped.

## 2. Techsupport inventory (grounded in 202605 `generate_dump`)

Verified against `sonic-utilities` branch `202605`, `scripts/generate_dump`:

**Redis DB snapshots** — `save_redis_info()` dumps, via
`sonic-db-dump -n <DB> -y`, into `dump/<DB>.json` (per-namespace suffixes on
multi-ASIC):
`APPL_DB, ASIC_DB, COUNTERS_DB, CONFIG_DB (secrets scrubbed), FLEX_COUNTER_DB,
STATE_DB, APPL_STATE_DB`.
These seven files are the backbone of the intent-vs-reality walk.

**Logs** — `save_log_files()` sweeps all of `/var/log/` (and `/var/log.tmpfs/`)
into `log/`, gzipping rotations individually. Critically this is how the
recordings arrive: `log/swss/sairedis.rec*` (SAI request/response recording)
and `log/swss/swss.rec*` (orchagent pipeline recording), plus `log/syslog*`,
FRR logs, and teamd logs. Parsers must handle gzipped rotations and
multi-file time ordering (a `files.timestamp.info` listing is included).

**Show-command captures** — dozens of `save_cmd` outputs in `dump/`
(`interface.status`, `ip.interface`, `vlan.summary`, `services.summary`,
`reboot.cause`, `version`, `platform.summary`, FRR `vtysh` captures via
`save_vtysh`, …). These are secondary evidence; primary truth is the DB dumps.

**Other** — `etc/` config snapshots (incl. `config_db.json`), core dumps,
docker/systemd status captures. Core-dump *presence* is a health signal; we
do not analyze core contents in hackathon scope.

**Design consequence:** the archive adapter is manifest-driven (glob patterns
per artifact class), not hardcoded filenames, so version drift across releases
degrades gracefully and unknown/vendor files are ignored by default.

## 3. Architecture

```
techsupport.tar.gz ──> [A] Archive adapter ─> [B] Evidence index
                             (manifest)          (DBs, logs, recs)
                                                      │
                     [C] Walk/Diff engine  <── playbooks (YAML)
                          │ emits
                     Divergence Report (JSON, evidence-linked)
                          │
              ┌───────────┴────────────┐
        [D1] CLI (no AI)         [D2] MCP server
        human-readable report    tools for any MCP client
                                        │
                                 [E] LLM interpret-only:
                                 verdict + narrative, every claim
                                 cites evidence IDs from the report
```

- **[A] Archive adapter.** Opens a techsupport tarball (or extracted dir)
  and presents one normalized read interface over it.
- **[B] Evidence index.** Loads the seven DB json dumps into queryable maps;
  indexes syslog/sairedis.rec/swss.rec by timestamp and object identifiers
  (redis keys, SAI OIDs); assigns every artifact line/key a stable
  `evidence_id`.
- **[C] Walk/Diff engine.** Executes playbooks: per-feature checks that map
  intent (CONFIG_DB) through APPL_DB (mgr daemons) to ASIC_DB (orchagent →
  syncd) and correlate with sairedis.rec at the SAI boundary. Emits findings.
- **[D] Interfaces.** Same engine behind a CLI (fully usable with no AI) and
  an MCP server (any MCP-capable model). LLM replaceability is structural.
- **[E] AI layer.** Receives the divergence report + tool access for targeted
  follow-up queries. Contract: no claim without an `evidence_id`.

**Prior art (reused, credited):** the `sonic-utilities` `dump state` plugin
framework (`dump/match_infra.py`, `dump/plugins/{port,vlan,route,...}.py`,
present on 202605) already encodes per-feature key mappings across
CONFIG/APPL/ASIC/STATE DBs. The walk engine adopts its feature→key-map
knowledge rather than re-deriving it; our addition is diffing, evidence
linking, log correlation, and the report contract.

## 4. Divergence report schema (v0)

```json
{
  "meta": {"source": "dump", "sonic_version": "202605", "generated_at": "..."},
  "health": {
    "services": [{"name": "swss", "state": "crash-loop", "evidence": ["ev:svc:12"]}],
    "core_dumps": [{"binary": "orchagent", "evidence": ["ev:core:1"]}]
  },
  "findings": [
    {
      "id": "F-0003",
      "check": "route.programming",
      "object_type": "ROUTE_ENTRY",
      "key": "10.0.0.0/24",
      "layer_expected": "APPL_DB:ROUTE_TABLE",
      "layer_missing": "ASIC_DB:SAI_OBJECT_TYPE_ROUTE_ENTRY",
      "expected": {"nexthop": "10.1.1.2", "ifname": "Ethernet4"},
      "observed": null,
      "severity": "high",
      "suspected_stage": "orchagent",
      "evidence": ["ev:appl:2214", "ev:asic:scan:route", "ev:rec:sai:99871", "ev:log:syslog:44510"],
      "correlated": {"sai_status": "SAI_STATUS_ITEM_NOT_FOUND", "log_excerpt_ref": "ev:log:syslog:44510"}
    }
  ],
  "evidence": {
    "ev:appl:2214": {"source": "dump/APPL_DB.json", "locator": "ROUTE_TABLE:10.0.0.0/24"},
    "ev:log:syslog:44510": {"source": "log/syslog.2.gz", "locator": "line 44510"}
  }
}
```

Rules: findings never contain prose conclusions; `suspected_stage` is the only
interpretation the deterministic layer makes, derived mechanically from which
layer transition broke. Verdict text is the AI layer's job and must reference
finding/evidence IDs.

## 5. Playbook format

Checks are YAML, not code, so the debugging methodology stays reviewable by
the community. See `playbooks/` for the three seed examples (port admin
state, VLAN membership, route programming). Shape:

```yaml
id: route.programming
feature: route
intent:      {db: APPL_DB,  pattern: "ROUTE_TABLE:*"}      # post-fpmsyncd intent
reality:     {db: ASIC_DB,  map: sai_route_entry}          # via key-map layer
compare:     [nexthop, ifname]
correlate:
  - {source: sairedis.rec, by: object_key, window_s: 30}
  - {source: syslog, match: "orchagent.*(routeorch|SAI_STATUS)", window_s: 30}
on_divergence: {severity: high, stage_rule: "present@intent&absent@reality -> orchagent|syncd"}
```

The `map` layer is where the sonic-utilities dump-plugin key knowledge plugs in.

## 6. MCP tool surface (v0)

`load_dump(path)`, `source_info()`, `get_db(db, pattern, limit)`,
`trace_object(key)` (follow one object CONFIG→APPL→ASIC→sairedis),
`diff_pipeline(feature?)` (run playbooks, return findings),
`search_logs(regex, t0?, t1?, files?)`, `service_health()`,
`get_report()` (full divergence report), `get_evidence(evidence_id)`,
`explain_check(check_id)`.
All tools operate on the loaded archive; there is no live mode.

## 7. Fault taxonomy & benchmark (sonic-vs, 202605)

Ten seed scenarios (definitions in `corpus/scenarios.yaml`; corpus tarballs
are generated pre-window and declared as prior work):

1. Port intent up, admin down applied out-of-band — CONFIG↔APPL mismatch
2. VLAN member present in CONFIG_DB, absent in APPL_DB (vlanmgrd stopped)
3. Routes in APPL_DB, absent in ASIC_DB (orchagent killed mid-install)
4. Static route with unresolvable nexthop (missing neighbor)
5. swss container down / crash-looping service
6. ASIC_DB entry deleted out-of-band (reality drifted under intent)
7. BGP session down from peer misconfig (wrong ASN) — FRR/vtysh + syslog path
8. Interface IP overlap rejected by intfmgrd (error-log correlation)
9. MTU change not propagated end-to-end
10. ACL rule accepted at CONFIG, never programmed (invalid match for vs)

**Protocol.** Each scenario = one techsupport tarball + a sealed ground-truth
card (root cause, faulty stage, key evidence). Two arms per model:
(a) *no-tools baseline*: model gets the extracted file listing plus raw file
read access, no sonic-rca; (b) *tool-assisted*: model gets the MCP server.
Same prompt budget both arms. ≥2 different LLMs.

**Scoring per scenario (0–5):** root cause exact (2), correct stage/layer
localization (1), every load-bearing claim carries valid evidence (1),
no fabricated evidence or invented SONiC objects (1, forfeited entirely on
any hallucination). Report mean ± per-scenario table; publish transcripts.

## 8. Four-day execution plan (window: Sep 28 9:00 PT → Oct 1 23:00 PT)

- **Day 1:** archive adapter + evidence index over the seven DB dumps and
  log sweep (incl. gz rotations); schema module frozen; smoke CLI
  (`sonic-rca report <tarball>` prints health + raw index stats).
- **Day 2:** walk/diff engine + playbook executor; port/vlan/route checks
  green against corpus scenarios 1–4; syslog/sairedis correlation.
- **Day 3:** MCP server end-to-end with a real client; remaining checks;
  benchmark harness (arm runner + scorer); first full scored run.
- **Day 4 (hard stop ~18:00 PT):** second-model run, scoring tables, demo
  recording (tarball in → cited verdict out), presentation with the
  provenance slide, README/docs polish, tag `v0.1`.


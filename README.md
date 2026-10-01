# sonic-rca

**Evidence-cited root cause analysis for SONiC techsupport dumps.**
SONiC Hackathon 2026 · Target: community SONiC **202605** · Design: [`docs/DESIGN.md`](docs/DESIGN.md) · Demo transcript: [`docs/DEMO.md`](docs/DEMO.md)

Input is an archived `show techsupport` tarball — fully offline, no switch
access of any kind. Deterministic tooling walks SONiC's state pipeline
(CONFIG_DB → APPL_DB → ASIC_DB → SAI, plus the FRR/BGP leg) to find where
intent stopped matching reality, and emits an evidence-linked **divergence
report**. An optional AI layer interprets that report: the CLI needs no AI,
and the MCP server accepts any MCP-capable model. **Every claim must cite
an evidence id** that resolves to a concrete redis key, log line, or SAI
record inside the archive.

```
techsupport.tar.gz ──> archive adapter ──> evidence index ──> playbook walk
                                                                  │
                                              divergence report (JSON, cited)
                                                    │
                                     CLI (no AI)         MCP server + any LLM
                                                         (interpret-only)
```

---

## Repository layout

```
src/sonic_rca/
  archive.py      techsupport adapter: dump/<DB>.json snapshots, gzipped
                  log rotations, log/swss/*.rec, version metadata
  captures.py     vtysh text captures (bgp.summary, frr.ip_route.nhg,
                  frr.ip.nht.vrf.all) parsed into pseudo-DBs
                  FRR_BGP / FRR_RIB / FRR_NHT
  index.py        evidence registry — every fact gets a resolvable ev: id
  keymaps.py      cross-layer key maps (CONFIG '|' → APPL ':' → ASIC SAI keys)
  playbook.py     YAML playbook executor → findings
  engine.py       Session: report() and cross-layer trace()
  schema.py       divergence-report dataclasses (schema v0)
  cli.py          sonic-rca report | trace | logs | serve | bench
  mcp_tools.py    the 10 MCP tool implementations
  mcp_server.py   FastMCP stdio server
  bench/          benchmark harness, mechanical scorer, LLM clients
playbooks/        the 13 checks (see "Checks")
corpus/           fault taxonomy (scenarios.yaml) + capture driver
tests/            pytest suite + synthetic-archive fixture builder
```

## Requirements

- Python ≥ 3.9; `pyyaml` (plus `mcp` only for the MCP server)
- Analyzing an archive needs no network, no root, no SONiC image
- A live virtual switch is needed only to *capture* a fault corpus; an LLM
  (API key or Claude Code) only to run the benchmark arms

## Install & quickstart (60 seconds, no switch needed)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e . pytest
python -m pytest tests -q          # 26 passed = install is good

python tests/fixtures.py demo/     # synthetic faulted archive, 202605 layout
sonic-rca report demo/techsupport.tar.gz
```

Abridged output:

```
F-0002 [high] route.programming :: ROUTE_TABLE:10.0.1.0/24
     present in APPL_DB, MISSING in ASIC_DB; suspected stage: orchagent|syncd
     evidence: ev:appl:00015, ev:asic:00016, ev:rec:00019, ev:log:00020, ...
```

Every `ev:` id resolves to a file + locator + excerpt in the `--json` report.

## Analyzing a techsupport tarball

```bash
sonic-rca report  dump.tar.gz                        # human-readable verdict
sonic-rca report  dump.tar.gz --json > report.json   # full evidence-linked report
sonic-rca report  dump.tar.gz --feature route        # one feature only
sonic-rca trace   dump.tar.gz "ROUTE_TABLE:10.0.1.0/24"   # follow one object
sonic-rca logs    dump.tar.gz "SAI_STATUS|ERR"       # cited log search
```

`trace` follows an object layer by layer and shows exactly where it stops
existing. Supported key families: `PORT|…`, `VLAN|…`, `VLAN_MEMBER|…`,
`INTERFACE|…`, `ROUTE_TABLE:…`, `RIB|<vrf>|<prefix>` (FRR RIB → APPL →
ASIC), `BGP_NEIGHBOR|…` (CONFIG → FRR session), `FDB_TABLE|Vlan<N>:<mac>`
(STATE → ASIC), `NEIGH_TABLE:<if>:<ip>` (APPL → ASIC).

Tarballs and already-extracted dump directories are both accepted.
Vendor-specific archive sections are ignored by design — only the
vendor-neutral artifacts are parsed.

## Running it as a drop-box service

Typical deployment: a server that receives techsupport tarballs (from
operators, CI, or support cases) and analyzes them. Nothing ever touches a
switch, and nothing leaves the server.

```bash
# one-time
cd /opt/sonic-rca && tar -xzf sonic-rca-complete.tar.gz --strip-components=1
python3 -m venv .venv && . .venv/bin/activate && pip install -e . mcp

# per tarball dropped into /srv/techsupport/
T=/srv/techsupport/sonic_dump_leaf0_20260928.tar.gz
sonic-rca report "$T" | tee "${T%.tar.gz}.report.txt"
sonic-rca report "$T" --json > "${T%.tar.gz}.report.json"
```

For interactive AI triage, run the MCP server and point any client at it
(absolute paths matter under a venv):

```json
{ "mcpServers": {
    "sonic-rca": { "command": "/opt/sonic-rca/.venv/bin/sonic-rca",
                   "args": ["serve"] } } }
```

The model calls `load_dump("<path>")` and works from there — all 10 tools
(`source_info`, `get_db`, `trace_object`, `diff_pipeline`, `search_logs`,
`service_health`, `get_report`, `get_evidence`, `explain_check`) are
read-only. Swapping the model is a client-config change, zero code.

## The 13 checks

| id | intent -> reality | stage on divergence |
|---|---|---|
| `port.admin_state` | CONFIG_DB `PORT` -> APPL_DB `PORT_TABLE` (admin_status, mtu) | portmgrd |
| `vlan.membership` | CONFIG_DB `VLAN_MEMBER` -> APPL_DB `VLAN_MEMBER_TABLE` | vlanmgrd |
| `vlan.asic_programming` | CONFIG_DB `VLAN` -> ASIC `SAI_OBJECT_TYPE_VLAN` | orchagent\|syncd |
| `route.programming` | APPL_DB `ROUTE_TABLE` -> ASIC `ROUTE_ENTRY` | orchagent\|syncd |
| `appl.unconsumed` | APPL_DB `_<TABLE>:<key>` still queued in `<TABLE>_KEY_SET` -> applied key | orchagent |
| `bgp.session` | CONFIG_DB `BGP_NEIGHBOR` -> `dump/bgp.summary` (asn; state must be Established) | bgp/frr |
| `route.static_to_rib` | CONFIG_DB `STATIC_ROUTE` -> FRR RIB (selected); unresolved nexthop per NHT -> staticd | frrcfgd\|staticd |
| `route.frr_to_appl` | FRR RIB selected `B>`/`S>` -> APPL_DB `ROUTE_TABLE` (nexthop) | zebra/fpmsyncd |
| `fdb.programming` | STATE_DB `FDB_TABLE` (learned MACs) -> ASIC `FDB_ENTRY` | orchagent\|syncd |
| `fdb.programming_static` | APPL_DB `FDB_TABLE` (static/EVPN) -> ASIC `FDB_ENTRY` | orchagent\|syncd |
| `neighbor.programming` | APPL_DB `NEIGH_TABLE` (front-panel/VLAN) -> ASIC `NEIGHBOR_ENTRY` | orchagent\|syncd |
| `intf.subnet_programming` | APPL_DB `INTF_TABLE:<if>:<prefix>` -> ASIC subnet route via that interface's RIF; overlap -> orchagent | orchagent\|syncd |
| `acl.rule_programming` | CONFIG_DB `ACL_RULE` (non-CTRLPLANE) -> STATE_DB status Active | aclorch |

Notes that keep verdicts honest:

- A configured BGP peer that never exchanged a message (`Up/Down=never`,
  `MsgRcvd=0`) is a HEALTH note, not a finding — nothing in the pipeline
  rejected it. `dump/ip.route` is the *kernel* FIB on some images; FRR's
  selected routes come from `dump/frr.ip_route.nhg`.
- **reality-drift**: an object missing from ASIC_DB whose newest
  `sairedis.rec` operation is a successful create/LEARN with no SAI error
  was deleted out-of-band, not refused (`refine_missing` rules).
- **stopped container**: a finding whose stage runs in a stopped container
  (per `dump/docker.ps`) is re-attributed to the root stopped service —
  e.g. `suspected stage: swss (container down; playbook stage: bgp/frr)` —
  with the original stage kept in `correlated.playbook_stage`.
- Correlation specs may name per-daemon logs; `bgp.session` reads
  `log/bgpd.log` where rsyslog routes `bgp#bgpd` separately.

## Tests

```bash
python -m pytest tests/ -v      # 26 tests
```

Coverage, in one list: healthy archive → zero findings; one test per fault
class (VLAN stall, unprogrammed route with sairedis correlation, port
attribute diff, swss-down re-attribution, wrong BGP ASN with the bgpd log
line, RIB→APPL gap, FDB/neighbor missing in ASIC, queued `_ROUTE_TABLE`
write); the FRR capture parsers against real FRR 10.5 output;
real-archive quirks (flat gzipped logs, stale rotations, capture-window
correlation, safe extraction); tarball round-trip; `trace`; CLI JSON; the
full MCP tool surface; a no-LLM plumbing run of the benchmark.
`tests/fixtures.py` builds complete synthetic archives in the 202605 layout
(verified against `sonic-utilities/scripts/generate_dump`, branch 202605) —
every quirk found in real captures is back-ported here as a regression test.

## Building a fault corpus

Run each scenario from `corpus/scenarios.yaml` on a **fresh** virtual
switch:

```bash
sudo corpus/tools/inject.sh s03_route_not_programmed /srv/corpus
```

Each run injects the fault, waits for convergence, captures
`show techsupport`, and writes `<scenario>/techsupport.tar.gz` plus a
sealed `ground_truth.yaml`. Verify supervisor program names against your
image — they drift between releases.

## Running the benchmark

```bash
# Option A — Anthropic API key:
export ANTHROPIC_API_KEY=...
sonic-rca bench /srv/corpus --arm both --model <model-id> --out results_A

# Option B — no API key (Claude Code print mode; sign in once with `claude`):
sonic-rca bench /srv/corpus --arm both --model cc:sonnet --out results_A
sonic-rca bench /srv/corpus --arm both --model cc:haiku  --out results_B
```

Two arms per model: `tools` (the model receives the divergence report) vs.
`baseline` (raw file listings + bounded excerpts, no analysis). Scoring is
mechanical, 0–5 per scenario: root cause exact (2), stage localized (1),
valid evidence cited (1), no fabricated evidence (1 — forfeited entirely on
any hallucinated id). Outputs: per-scenario transcripts and a `SUMMARY.md`
with per-arm means. Without `--model` only the plumbing runs, labeled as
not a reportable result.

## Extending

One new check = one YAML file in `playbooks/`: intent (DB + key pattern) →
reality (DB via a named key map) → compared fields → correlation sources →
stage on divergence. New cross-layer transforms register in `keymaps.py`
with `@keymap("name")`. Optional playbook keys: `intent.filter`,
`reality.expect` (required constant fields), `reality.benign` (downgrade to
a HEALTH note), and `{frag}` in a syslog regex (replaced by the escaped
object fragment).

## Scope & limitations

- Archived techsupport tarballs only — no switch access, read or write.
- Community-SONiC artifacts only; vendor sections are opaque by design.
- Fault taxonomy covers control-plane/DB-pipeline classes expressible on a
  virtual switch; real-ASIC classes are out of benchmark scope (the design
  does not preclude them).
- Validated on one vslib leaf–spine testbed (SONiC main-derivative image,
  FRR 10.5, frrcfgd) plus synthetic 202605-format archives; other releases
  may need manifest-glob adjustments in `archive.py`.

## Status & provenance (SONiC Hackathon 2026)

**COMPLETED.**

- Toolchain and all 13 checks implemented and tested — 26/26.
- Validated end-to-end on real captures from a live virtual leaf–spine
  testbed: **12/12 fault scenarios localized to the ground-truth stage, 0
  false positives on the healthy baseline.** (Caveats: 10/12 against the
  pre-registered taxonomy — two ground-truth stages were relabelled from
  raw artifact evidence; several checks were refined against these same
  captures, so this measures coverage of the captured faults, not
  generalization.)
- LLM benchmark run on two models — tools vs. raw-archive baseline:
  **Sonnet 5.00 vs 1.25, Haiku 4.75 vs 1.50** (0–5 rubric), **0 fabricated
  evidence ids across all 48 published transcripts**. (Caveat: two models,
  one vendor.)
- The MCP tool functions are covered by the test suite; a live end-to-end
  MCP client session was not part of the validation runs (the benchmark
  drives the tools layer directly).

Full validation data (RUNLOG, ACCURACY table, captures with sealed ground
truths, stored reports, traces, benchmark transcripts) ships in the
accompanying results packages. The presentation's prior-work slide
separates pre-existing work from hackathon-window work per event rules.

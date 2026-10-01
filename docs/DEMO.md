# sonic-rca — demo transcript

Commands below were run against a synthetic multi-fault techsupport archive
in the community SONiC 202605 layout (built by `tests/fixtures.py`, faults:
unprogrammed route, stalled VLAN member, wrong BGP peer ASN). Reproduce with:

```bash
python tests/fixtures.py demo/
sonic-rca report demo/techsupport.tar.gz
```

## `sonic-rca report`

```
sonic-rca divergence report — host=vlab-01 version=SONiC.202605.0-dirty captured=20260915_120000
DBs: APPL_DB, ASIC_DB, COUNTERS_DB, CONFIG_DB, FLEX_COUNTER_DB, STATE_DB, APPL_STATE_DB | checks: acl.rule_programming, appl.unconsumed, bgp.session, fdb.programming, fdb.programming_static, intf.subnet_programming, neighbor.programming, port.admin_state, route.frr_to_appl, route.programming, route.static_to_rib, vlan.asic_programming, vlan.membership

HEALTH:
  note: bgp.session BGP_NEIGHBOR|default|10.1.2.2 observed={'state': 'Active'} (bgp_peer_never_reached, not a pipeline divergence)  [ev:capture:00006]

F-0001 [high] bgp.session :: BGP_NEIGHBOR|default|10.1.1.2
     attribute mismatch CONFIG_DB vs reality; suspected stage: bgp/frr
     expected={'state': 'Established'} observed={'state': 'Active'}
     evidence: ev:config:00002, ev:capture:00003, ev:log:00004
F-0002 [high] route.programming :: ROUTE_TABLE:10.0.1.0/24
     present in APPL_DB, MISSING in ASIC_DB; suspected stage: orchagent|syncd
     expected={'nexthop': '10.1.1.2', 'ifname': 'Ethernet4'} observed=None
     evidence: ev:appl:00015, ev:asic:00016, ev:rec:00019, ev:log:00020, ev:log:00021
F-0003 [high] vlan.membership :: VLAN_MEMBER|Vlan100|Ethernet4
     present in CONFIG_DB, MISSING in APPL_DB; suspected stage: vlanmgrd
     expected={'tagging_mode': 'untagged'} observed=None
     evidence: ev:config:00025, ev:appl:00026, ev:log:00027, ev:log:00028

3 finding(s), 28 evidence item(s). Every id resolves via `get_evidence`/report JSON.
```

## `sonic-rca trace` — follow the failed route across layers

```
{
  "key": "ROUTE_TABLE:10.0.1.0/24",
  "hops": [
    {
      "layer": "APPL_DB",
      "key": "ROUTE_TABLE:10.0.1.0/24",
      "present": true,
      "value": {
        "nexthop": "10.1.1.2",
        "ifname": "Ethernet4"
      },
      "evidence": "ev:appl:00001"
    },
    {
      "layer": "ASIC_DB",
      "key": "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:{dest=10.0.1.0/24}",
      "present": false,
      "value": null,
      "evidence": null
    }
  ],
  "sairedis": [
    {
      "file": "log/swss/sairedis.rec",
      "line": 4,
      "text": "2026-09-15.11:59:10.050|c|SAI_OBJECT_TYPE_ROUTE_ENTRY:{\"dest\":\"10.0.1.0/24\",\"switch_id\":\"oid:0x21000000000000\"}|SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID=oid:0x40000000000a1",
      "evidence": "ev:rec:00002"
    }
  ]
}
```

## `sonic-rca trace` — BGP peer: CONFIG_DB intent vs FRR session

`FRR_BGP`/`FRR_RIB` are read-only pseudo-DBs parsed from the vtysh captures.

```
{
  "key": "BGP_NEIGHBOR|default|10.1.1.2",
  "hops": [
    {
      "layer": "CONFIG_DB",
      "key": "BGP_NEIGHBOR|default|10.1.1.2",
      "present": true,
      "value": {
        "admin_status": "up",
        "asn": "64999",
        "name": "spine0"
      },
      "evidence": "ev:config:00001"
    },
    {
      "layer": "FRR_BGP",
      "key": "BGP_PEER|default|10.1.1.2",
      "present": true,
      "value": {
        "asn": "64999",
        "msg_rcvd": "35",
        "msg_sent": "36",
        "up_down": "00:01:02",
        "state": "Active",
        "pfx_rcd": "0",
        "desc": "spine0",
        "_lineno": "7",
        "_line": "10.1.1.2        4      64999        35        36        0    0    0 00:01:02       Active        0 spine0",
        "_source": "dump/bgp.summary"
      },
      "evidence": "ev:capture:00002"
    }
  ],
  "sairedis": []
}
```

## `sonic-rca logs` — cited log search

```
log/syslog:3: Sep 15 11:59:00.000 vlab-01 ERR swss#vlanmgrd: :- doVlanMemberTask: failed to process Vlan100 Ethernet4   [ev:log:00001]
log/syslog:4: Sep 15 11:59:10.000 vlab-01 ERR swss#orchagent: :- addRoute: SAI_STATUS_FAILURE creating 10.0.1.0/24   [ev:log:00002]
```

bgpd logs to `log/bgpd.log` (not syslog) on the validation image; `--files` selects it:

```
$ sonic-rca logs demo/techsupport.tar.gz 'bgpd.*10\.1\.1\.2(?![0-9])' --files 'bgpd.log*'
log/bgpd.log:3: 2026 Sep 15 11:59:30.000000 vlab-01 ERR bgp#bgpd[93]: [MVZKX-EG443][EC 33554452] bgp_process_packet: BGP OPEN receipt failed for peer: 10.1.1.2   [ev:log:00001]
```

Every `ev:` id above resolves to a source file, locator and excerpt in the
`--json` report (`get_evidence` over MCP).

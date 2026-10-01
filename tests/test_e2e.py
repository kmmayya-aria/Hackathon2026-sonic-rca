import datetime as dt
import json
from pathlib import Path

import yaml

from fixtures import build_dump, build_tarball
from sonic_rca.engine import Session
from sonic_rca.cli import main as cli_main
from sonic_rca import mcp_tools as T
from sonic_rca.index import parse_log_ts
from sonic_rca.captures import parse_bgp_summary, parse_frr_nht, parse_frr_routes
from sonic_rca.keymaps import frag_route_dest, route_in_asic_scope, route_prefix


def _findings(rep, check):
    return [f for f in rep.findings if f.check == check]


def test_healthy_dump_has_no_findings(tmp_path):
    root = build_dump(tmp_path, faults=set())
    rep = Session(str(root)).report()
    assert rep.findings == []
    assert rep.meta["sonic_version"].startswith("SONiC.202605")
    assert set(rep.meta["dbs"]) >= {"CONFIG_DB", "APPL_DB", "ASIC_DB"}
    # the never-reached ghost peer is a note, not a finding
    notes = rep.health["notes"]
    assert [(n["check"], n["key"], n["rule"], n["observed"]) for n in notes] == [
        ("bgp.session", "BGP_NEIGHBOR|default|10.1.2.2",
         "bgp_peer_never_reached", {"state": "Active"})]
    ev = rep.evidence[notes[0]["evidence"]]
    assert (ev.source, ev.locator) == ("dump/bgp.summary", "line 8")


def test_bgp_peer_asn_mismatch_found(tmp_path):
    root = build_dump(tmp_path, faults={"bgp_peer_asn"})
    rep = Session(str(root)).report()
    f = _findings(rep, "bgp.session")
    assert [(x.key, x.suspected_stage, x.expected, x.observed) for x in f] == [
        ("BGP_NEIGHBOR|default|10.1.1.2", "bgp/frr",
         {"state": "Established"}, {"state": "Active"})]
    excerpts = [rep.evidence[e].excerpt or "" for e in f[0].evidence]
    assert any("BGP OPEN receipt failed for peer: 10.1.1.2" in x for x in excerpts)
    assert not any("10.1.1.21" in x for x in excerpts)
    assert any(x.startswith("10.1.1.2        4      64999") for x in excerpts)
    assert [x.check for x in rep.findings] == ["bgp.session"]


def test_fpmsyncd_stalled_rib_route_missing_in_appl(tmp_path):
    root = build_dump(tmp_path, faults={"fpmsyncd_stalled"})
    rep = Session(str(root)).report()
    f = _findings(rep, "route.frr_to_appl")
    assert [(x.key, x.layer_missing, x.suspected_stage) for x in f] == [
        ("RIB|default|10.0.2.0/24", "APPL_DB", "zebra/fpmsyncd")]
    ev = rep.evidence[f[0].evidence[0]]
    assert (ev.source, ev.locator) == ("dump/frr.ip_route.nhg", "line 8")
    assert [x.check for x in rep.findings] == ["route.frr_to_appl"]


def test_asic_drift_vs_failed_create(tmp_path):
    root = build_dump(tmp_path, faults={"route_asic_drift", "route_not_programmed"})
    rep = Session(str(root)).report()
    got = {x.key: x.suspected_stage for x in _findings(rep, "route.programming")}
    # 10.0.0.0/24: rec ends with a create, no SAI error -> out-of-band loss;
    # 10.0.1.0/24: create logged SAI_STATUS_FAILURE -> orchagent|syncd
    assert got == {"ROUTE_TABLE:10.0.0.0/24": "reality-drift",
                   "ROUTE_TABLE:10.0.1.0/24": "orchagent|syncd"}


def test_unconsumed_producer_entry_blames_orchagent_not_fpmsyncd(tmp_path):
    root = build_dump(tmp_path, faults={"route_unconsumed"})
    rep = Session(str(root)).report()
    assert [(x.check, x.key, x.layer_missing, x.suspected_stage)
            for x in rep.findings] == [
        ("appl.unconsumed", "_ROUTE_TABLE:10.0.3.0/24", "APPL_DB", "orchagent")]
    notes = [rep.evidence[e].locator for e in rep.findings[0].evidence]
    assert any("still queued in ROUTE_TABLE_KEY_SET" in n for n in notes)


def test_fdb_not_programmed_found(tmp_path):
    root = build_dump(tmp_path, faults={"fdb_not_programmed"})
    rep = Session(str(root)).report()
    assert [(x.check, x.key, x.layer_missing, x.suspected_stage)
            for x in rep.findings] == [
        ("fdb.programming", "FDB_TABLE|Vlan100:00:aa:bb:00:03:01", "ASIC_DB",
         "reality-drift")]
    # the cited rec line is syncd's LEARNED event, not the later neighbor create
    lines = [rep.evidence[e].excerpt or "" for e in rep.findings[0].evidence]
    assert any("SAI_FDB_EVENT_LEARNED" in x for x in lines)


def test_neighbor_not_programmed_found_mgmt_excluded(tmp_path):
    root = build_dump(tmp_path, faults={"neigh_not_programmed"})
    rep = Session(str(root)).report()
    assert [(x.check, x.key, x.layer_missing, x.suspected_stage)
            for x in rep.findings] == [
        ("neighbor.programming", "NEIGH_TABLE:Ethernet4:10.1.1.2", "ASIC_DB",
         "orchagent|syncd")]


def test_intf_subnet_overlap_blames_orchagent(tmp_path):
    s = Session(str(build_dump(tmp_path, faults={"intf_ip_overlap"})))
    rep = s.report()
    assert [(x.check, x.key, x.layer_missing, x.suspected_stage)
            for x in rep.findings] == [
        ("intf.subnet_programming", "INTF_TABLE:Ethernet0:10.1.1.0/31", "ASIC_DB",
         "orchagent")]
    cited = [(rep.evidence[e].source, rep.evidence[e].locator)
             for e in rep.findings[0].evidence]
    assert ("dump/APPL_DB.json", "INTF_TABLE:Ethernet4:10.1.1.1/31") in cited
    assert any("overlaps with 10.1.1.1/31" in (rep.evidence[e].excerpt or "")
               for e in rep.findings[0].evidence)
    assert [(h["layer"], h["present"])
            for h in s.trace("INTERFACE|Ethernet4|10.1.1.1/31")["hops"]] == [
        ("CONFIG_DB", True), ("APPL_DB", True), ("ASIC_DB", True)]
    assert [(h["layer"], h["present"])
            for h in s.trace("INTERFACE|Ethernet0|10.1.1.0/31")["hops"]] == [
        ("CONFIG_DB", True), ("APPL_DB", True), ("ASIC_DB", False)]


def test_acl_rule_inactive_blames_aclorch_ctrlplane_ignored(tmp_path):
    rep = Session(str(build_dump(tmp_path, faults={"acl_rule_rejected"}))).report()
    assert [(x.check, x.key, x.layer_missing, x.suspected_stage, x.expected,
             x.observed) for x in rep.findings] == [
        ("acl.rule_programming", "ACL_RULE|DATA_T|R2", None, "aclorch",
         {"status": "Active"}, {"status": "Inactive"})]
    assert any("doAclRuleTask: Unknown or invalid rule attribute"
               in (rep.evidence[e].excerpt or "") for e in rep.findings[0].evidence)


def test_capture_parsers_real_format():
    text = ("Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  "
            "Up/Down State/PfxRcd   PfxSnt Desc\n"
            "10.0.0.1        4      65200        31        31       50    0    0 "
            "00:21:18           50       50 spine0\n"
            "10.0.1.1        4      65300         0         0        0    0    0 "
            "   never       Active        0 ghost-peer\n")
    rows = parse_bgp_summary(text)
    assert {k: (v["asn"], v["state"], v["pfx_rcd"], v["up_down"], v["desc"],
                v["_lineno"]) for k, v in rows.items()} == {
        "default|10.0.0.1": ("65200", "Established", "50", "00:21:18", "spine0", "2"),
        "default|10.0.1.1": ("65300", "Active", "0", "never", "ghost-peer", "3"),
    }
    rib = parse_frr_routes(
        "IPv4 unicast VRF default:\n"
        "C>* 10.1.0.1/32 (103) is directly connected, Loopback0, weight 1, 00:24:23\n"
        "B>* 198.51.1.0/24 [20/0] (125) via 10.0.0.1, Ethernet1, weight 1, 00:19:08\n"
        "B>* 10.9.0.0/24 [20/0] (125) via 10.0.0.1, Ethernet1, weight 1, 00:19:08\n"
        "  *                        via 10.0.1.1, Ethernet9, weight 1, 00:19:08\n"
        "IPv6 unicast VRF mgmt:\n"
        "C * fe80::/64 (121) is directly connected, eth0, weight 1, 00:24:23\n")
    assert {k: (v["protocol"], v["selected"], v["fib"], v["nexthop"], v["ifname"])
            for k, v in rib.items()} == {
        "default|10.1.0.1/32": ("C", "true", "true", "", "Loopback0"),
        "default|198.51.1.0/24": ("B", "true", "true", "10.0.0.1", "Ethernet1"),
        "default|10.9.0.0/24": ("B", "true", "true", "10.0.0.1,10.0.1.1",
                                "Ethernet1,Ethernet9"),
        "mgmt|fe80::/64": ("C", "false", "true", "", "eth0"),
    }
    nht = parse_frr_nht(
        "\nVRF default:\n Resolve via default: on\n10.0.0.1(Connected)\n"
        " resolved via connected, prefix 10.0.0.0/31\n"
        " is directly connected, Ethernet1 (vrf default), weight 1\n"
        " Client list: static(fd 68) bgp(fd 73)\n10.250.250.250\n unresolved\n"
        " Client list: static(fd 68)\n\nVRF mgmt:\n Resolve via default: on\n")
    assert {k: (v["resolved"], v["via"], v["clients"], v["_lineno"], v["_line"])
            for k, v in nht.items()} == {
        "default|10.0.0.1": ("true", "connected, prefix 10.0.0.0/31",
                             "static,bgp", "4", "10.0.0.1(Connected)"),
        "default|10.250.250.250": ("false", "", "static", "8",
                                   "10.250.250.250 unresolved"),
    }


def test_static_route_unresolved_nexthop_blames_staticd(tmp_path):
    rep = Session(str(build_dump(tmp_path, faults={"static_nh_unresolved"}))).report()
    assert [(x.check, x.key, x.layer_missing, x.suspected_stage)
            for x in rep.findings] == [
        ("route.static_to_rib", "STATIC_ROUTE|default|10.0.9.0/24", "FRR_RIB",
         "staticd")]
    cited = [rep.evidence[e] for e in rep.findings[0].evidence]
    assert any(e.source == "dump/frr.ip.nht.vrf.all" and e.locator == "line 8"
               and e.excerpt == "10.250.250.250 unresolved" for e in cited)


def test_vlan_member_stall_found_with_stage_and_evidence(tmp_path):
    root = build_dump(tmp_path, faults={"vlan_member_stalled"})
    s = Session(str(root))
    rep = s.report()
    f = _findings(rep, "vlan.membership")
    assert len(f) == 1
    f = f[0]
    assert f.key == "VLAN_MEMBER|Vlan100|Ethernet4"
    assert f.layer_missing == "APPL_DB"
    assert f.suspected_stage == "vlanmgrd"
    # every evidence id resolves, and syslog correlation caught the ERR line
    assert f.evidence and all(rep.evidence.get(e) for e in f.evidence)
    excerpts = [rep.evidence[e].excerpt or "" for e in f.evidence]
    assert any("failed to process Vlan100" in x for x in excerpts)


def test_route_not_programmed_found_via_asic_map_and_rec(tmp_path):
    root = build_dump(tmp_path, faults={"route_not_programmed"})
    rep = Session(str(root)).report()
    f = [x for x in _findings(rep, "route.programming")
         if x.key == "ROUTE_TABLE:10.0.1.0/24"]
    assert len(f) == 1
    f = f[0]
    assert f.layer_missing == "ASIC_DB"
    assert "orchagent" in f.suspected_stage
    # healthy route did not fire
    assert not [x for x in _findings(rep, "route.programming")
                if x.key == "ROUTE_TABLE:10.0.0.0/24"]
    # sairedis.rec correlation attached
    assert "sairedis.rec" in f.correlated


def test_port_admin_mismatch_attribute_diff(tmp_path):
    root = build_dump(tmp_path, faults={"port_admin_mismatch"})
    rep = Session(str(root)).report()
    f = _findings(rep, "port.admin_state")
    assert len(f) == 1
    assert f[0].layer_missing is None
    assert f[0].expected == {"admin_status": "up"}
    assert f[0].observed == {"admin_status": "down"}


def test_service_health_from_capture(tmp_path):
    root = build_dump(tmp_path, faults={"swss_down"})
    rep = Session(str(root)).report()
    assert sorted((s["name"], s["state"].split(" ")[0])
                  for s in rep.health["services"]) == [
        ("bgp", "Exited"), ("swss", "unhealthy"), ("syncd", "Exited")]
    assert rep.health["root_services"] == ["swss"]
    # bgp peers and static routes vanish because bgp was stopped with swss:
    # blame swss
    assert [(x.check, x.key, x.suspected_stage,
             x.correlated["playbook_stage"]) for x in rep.findings] == [
        ("bgp.session", "BGP_NEIGHBOR|default|10.1.1.2", "swss", "bgp/frr"),
        ("bgp.session", "BGP_NEIGHBOR|default|10.1.2.2", "swss", "bgp/frr"),
        ("route.static_to_rib", "STATIC_ROUTE|default|10.0.1.0/24", "swss",
         "frrcfgd|staticd")]
    swss_ev = next(s["evidence"] for s in rep.health["services"]
                   if s["name"] == "swss")
    assert all(swss_ev[0] in x.evidence for x in rep.findings)


def test_tarball_roundtrip_and_trace(tmp_path):
    tb = build_tarball(tmp_path, faults={"route_not_programmed"})
    s = Session(str(tb))
    tr = s.trace("ROUTE_TABLE:10.0.1.0/24")
    layers = {h["layer"]: h["present"] for h in tr["hops"]}
    assert layers["APPL_DB"] is True and layers["ASIC_DB"] is False
    assert tr["sairedis"], "rec correlation should surface the SAI create attempt"
    tr2 = s.trace("PORT|Ethernet0")
    got = {h["layer"] for h in tr2["hops"] if h["present"]}
    assert {"CONFIG_DB", "APPL_DB", "ASIC_DB"} <= got


def test_trace_rib_fdb_neigh_bgp(tmp_path):
    s = Session(str(build_dump(tmp_path, faults={"fpmsyncd_stalled",
                                                 "fdb_not_programmed"})))

    def layers(key):
        return [(h["layer"], h["present"]) for h in s.trace(key)["hops"]]

    assert layers("RIB|default|10.0.0.0/24") == [
        ("FRR_RIB", True), ("APPL_DB", True), ("ASIC_DB", True)]
    assert layers("RIB|default|10.0.2.0/24") == [
        ("FRR_RIB", True), ("APPL_DB", False)]
    assert layers("FDB_TABLE|Vlan100:00:aa:bb:00:03:01") == [
        ("STATE_DB", True), ("ASIC_DB", False)]
    assert layers("NEIGH_TABLE:Ethernet4:10.1.1.2") == [
        ("APPL_DB", True), ("ASIC_DB", True)]
    assert layers("BGP_NEIGHBOR|default|10.1.1.2") == [
        ("CONFIG_DB", True), ("FRR_BGP", True)]


def test_cli_report_json(tmp_path, capsys):
    root = build_dump(tmp_path, faults={"vlan_member_stalled"})
    assert cli_main(["report", str(root), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["schema_version"] == "0"
    assert any(f["check"] == "vlan.membership" for f in out["findings"])


def test_mcp_tool_surface(tmp_path):
    root = build_dump(tmp_path, faults={"route_not_programmed"})
    info = T.load_dump(str(root))
    assert "ASIC_DB" in info["dbs"]
    keys = T.get_db("APPL_DB", "ROUTE_TABLE:*")
    assert keys["total"] == 4
    d = T.diff_pipeline()
    assert any(f["check"] == "route.programming" for f in d["findings"])
    ev_id = d["findings"][0]["evidence"][0]
    assert T.get_evidence(ev_id)["id"] == ev_id
    assert "id" in T.explain_check("route.programming")


def test_bench_plumbing_no_llm(tmp_path):
    sc = tmp_path / "corpus" / "s03_route_not_programmed"
    sc.mkdir(parents=True)
    build_tarball(sc, faults={"route_not_programmed"})
    (sc / "ground_truth.yaml").write_text(yaml.safe_dump(
        {"stage": "orchagent|syncd", "root_cause": "route not programmed"}))
    from sonic_rca.bench.harness import run_bench
    summary = run_bench(str(tmp_path / "corpus"), arm="both", model=None,
                        out_dir=str(tmp_path / "out"))
    assert "s03_route_not_programmed" in summary
    assert "Plumbing run" in summary
    assert (tmp_path / "out" / "SUMMARY.md").exists()
    tools_json = json.loads(
        (tmp_path / "out" / "s03_route_not_programmed.tools.json").read_text())
    assert tools_json["score"]["total"] >= 4  # deterministic top finding is right


# ---- real-capture quirks (newer generate_dump variants) -----------------

def test_flat_log_layout_tarball(tmp_path):
    tb = build_tarball(tmp_path, faults={"route_not_programmed",
                                         "vlan_member_stalled"}, flat_logs=True)
    rep = Session(str(tb)).report()
    assert sorted((f.check, f.key) for f in rep.findings) == [
        ("route.programming", "ROUTE_TABLE:10.0.1.0/24"),
        ("vlan.membership", "VLAN_MEMBER|Vlan100|Ethernet4"),
    ]
    route = _findings(rep, "route.programming")[0]
    assert "sairedis.rec" in route.correlated        # log/sairedis.rec.gz
    vlan = _findings(rep, "vlan.membership")[0]
    sources = {rep.evidence[e].source for e in vlan.correlated["syslog"]}
    assert sources == {"log/syslog.1.gz"}             # not syslog-info.log.gz
    assert [c["issue"] for c in rep.health["capture"]] == [
        "current syslog empty in archive; log correlation limited to rotations"]


def test_stale_rotations_outside_capture_window_not_cited(tmp_path):
    root = build_dump(tmp_path, faults={"vlan_member_stalled"})
    rep = Session(str(root)).report()
    cited = [rep.evidence[e].excerpt or "" for e in rep.evidence]
    assert not [x for x in cited if "STALE" in x]
    assert rep.health["capture"] == []


def test_route_key_normalization_and_scope():
    assert route_prefix("ROUTE_TABLE:10.1.0.1") == "10.1.0.1/32"
    assert route_prefix("ROUTE_TABLE:fc00::1") == "fc00::1/128"
    assert route_prefix("ROUTE_TABLE:fe80::/64") == "fe80::/64"
    assert route_prefix("ROUTE_TABLE:Vrf-red:10.9.0.0/24") == "10.9.0.0/24"
    assert frag_route_dest("ROUTE_TABLE:fe80::/64") == '"dest":"fe80::/64"'
    assert route_in_asic_scope("k", {"ifname": "Ethernet4,Ethernet8"})
    assert route_in_asic_scope("k", {"ifname": "Loopback0"})
    assert route_in_asic_scope("k", {})
    assert not route_in_asic_scope("k", {"ifname": "sr0"})
    assert not route_in_asic_scope("k", {"ifname": "eth0,docker0"})


def test_parse_log_ts_formats():
    y = 2026
    assert parse_log_ts("2026 Sep 28 08:25:51.317156 sonic INFO x", y) == \
        dt.datetime(2026, 9, 28, 8, 25, 51)
    assert parse_log_ts("Jun 26 22:11:28.350855+00:00 2025 sonic ERR x", y) == \
        dt.datetime(2025, 6, 26, 22, 11, 28)
    assert parse_log_ts("Sep 15 11:58:01.000 vlab-01 INFO x", y) == \
        dt.datetime(2026, 9, 15, 11, 58, 1)
    assert parse_log_ts("2026-09-28.08:37:11.496342|c|SAI_OBJECT", y) == \
        dt.datetime(2026, 9, 28, 8, 37, 11)
    assert parse_log_ts("2026-09-28T08:25:51Z E! x", y) == \
        dt.datetime(2026, 9, 28, 8, 25, 51)
    assert parse_log_ts("continuation line", y) is None

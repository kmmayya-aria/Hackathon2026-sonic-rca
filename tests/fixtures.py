"""Synthetic techsupport fixtures mirroring the 202605 archive layout.

Layout per generate_dump (sonic-utilities 202605): sonic_dump_<host>_<ts>/
with dump/<DB>.json in sonic-db-dump -y format, log/syslog, log/swss/*.rec,
dump/version, dump/services.summary. Faults are injected as DB-level
divergences so the walk engine has something real to find.

These fixtures validate the engine against the *format*; real sonic-vs
captures remain required for reportable benchmark results.

Quirks mirrored from real validation captures (see the results RUNLOG):
host routes without a mask in APPL_DB, a link-local route over a kernel-only
netdev (sr0) that orchagent never programs, stale pre-install syslog
rotations, and (flat_logs=True) the flattened log/ layout: every file
gzipped, *.rec directly under log/, empty current syslog, numbered rotations,
plus hard links and device nodes under etc/ in the tarball.
Also: frrcfgd CONFIG_DB schema (BGP_NEIGHBOR|default|<ip>), vtysh captures
dump/bgp.summary + dump/frr.ip_route.nhg in FRR 10.5 text format, a
never-reached "ghost" peer that stays Active, learned MACs only in STATE_DB
FDB_TABLE, and mgmt eth0 neighbors that are never ASIC-programmed.
"""
from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path

HOST, TS = "vlab-01", "20260915_120000"


def _dbjson(entries: dict[str, dict]) -> str:
    return json.dumps({k: {"type": "hash", "value": v, "ttl": -0.001}
                       for k, v in entries.items()}, indent=1)


def _gz(path: Path, lines: list[str]) -> None:
    path.write_bytes(gzip.compress(("\n".join(lines) + "\n").encode()
                                   if lines else b""))


def build_dump(dest: Path, faults: set[str] = frozenset(),
               flat_logs: bool = False) -> Path:
    """Create an extracted synthetic techsupport dir; return its root.

    faults: subset of {"vlan_member_stalled", "route_not_programmed",
                       "port_admin_mismatch", "swss_down", "bgp_peer_asn",
                       "fpmsyncd_stalled", "route_unconsumed", "route_asic_drift",
                       "fdb_not_programmed", "neigh_not_programmed",
                       "static_nh_unresolved", "intf_ip_overlap",
                       "acl_rule_rejected"}
    flat_logs: flattened generate_dump layout (see module docstring).
    """
    root = dest / f"sonic_dump_{HOST}_{TS}"
    (root / "dump").mkdir(parents=True)
    (root / "log" / "swss").mkdir(parents=True)

    cfg = {
        "PORT|Ethernet0": {"admin_status": "up", "mtu": "9100", "alias": "etp1"},
        "PORT|Ethernet4": {"admin_status": "up", "mtu": "9100", "alias": "etp2"},
        "VLAN|Vlan100": {"vlanid": "100"},
        "VLAN_MEMBER|Vlan100|Ethernet4": {"tagging_mode": "untagged"},
        "BGP_GLOBALS|default": {"local_asn": "65100", "router_id": "10.1.0.1"},
        "BGP_NEIGHBOR|default|10.1.1.2": {"admin_status": "up", "asn": "65200",
                                          "name": "spine0"},
        "BGP_NEIGHBOR|default|10.1.2.2": {"admin_status": "up", "asn": "65300",
                                          "name": "ghost-peer"},
        "STATIC_ROUTE|default|10.0.1.0/24": {"nexthop": "10.1.1.2"},
        "INTERFACE|Ethernet4": {"NULL": "NULL"},
        "INTERFACE|Ethernet4|10.1.1.1/31": {"NULL": "NULL"},
        "ACL_TABLE|DATA_T": {"type": "L3", "stage": "ingress", "ports@": "Ethernet0"},
        "ACL_RULE|DATA_T|R1": {"PRIORITY": "10", "PACKET_ACTION": "DROP",
                               "SRC_IP": "10.9.9.9/32"},
        # control-plane ACLs are caclmgrd's (iptables): no STATE_DB status
        "ACL_TABLE|SSH_ONLY": {"type": "CTRLPLANE", "services@": "SSH"},
        "ACL_RULE|SSH_ONLY|RULE_1": {"PRIORITY": "9999", "PACKET_ACTION": "ACCEPT",
                                     "SRC_IP": "10.0.0.0/8"},
    }
    # real: gearsyncd handshake entry is always pending on vs (no consumer)
    gearbox = {"_GEARBOX_TABLE:GearboxConfigDone": {"success": "1"},
               "GEARBOX_TABLE_KEY_SET": ["GearboxConfigDone"]}
    state = {"FDB_TABLE|Vlan100:00:aa:bb:00:03:01": {"port": "Ethernet4",
                                                     "type": "dynamic"},
             "ACL_RULE_TABLE|DATA_T|R1": {"status": "Active"}}
    appl = {
        "PORT_TABLE:Ethernet0": {"admin_status": "up", "mtu": "9100"},
        "PORT_TABLE:Ethernet4": {"admin_status": "up", "mtu": "9100"},
        "VLAN_MEMBER_TABLE:Vlan100:Ethernet4": {"tagging_mode": "untagged"},
        "ROUTE_TABLE:10.0.0.0/24": {"nexthop": "10.1.1.2", "ifname": "Ethernet4"},
        "ROUTE_TABLE:10.0.1.0/24": {"nexthop": "10.1.1.2", "ifname": "Ethernet4"},
        # real: host route key carries no mask; ASIC dest is 10.1.0.1/32
        "ROUTE_TABLE:10.1.0.1": {"nexthop": "0.0.0.0", "ifname": "Loopback0"},
        # real: kernel-only netdev; routeorch never programs it
        "ROUTE_TABLE:fe80::/64": {"nexthop": "::", "ifname": "sr0"},
        "NEIGH_TABLE:Ethernet4:10.1.1.2": {"family": "IPv4",
                                           "neigh": "bc:24:11:9f:4e:d9"},
        "NEIGH_TABLE:eth0:10.114.96.10": {"family": "IPv4",
                                          "neigh": "bc:24:11:d3:a4:c0"},
        "INTF_TABLE:Ethernet4": {"NULL": "NULL", "mac_addr": "00:00:00:00:00:00"},
        "INTF_TABLE:Ethernet4:10.1.1.1/31": {"family": "IPv4", "scope": "global"},
        # real: loopback /32 only gets an ip2me route (no RIF subnet route)
        "INTF_TABLE:Loopback0:10.1.0.1/32": {"family": "IPv4", "scope": "global"},
    }
    asic = {
        "ASIC_STATE:SAI_OBJECT_TYPE_SWITCH:oid:0x21000000000000":
            {"SAI_SWITCH_ATTR_INIT_SWITCH": "true"},
        "ASIC_STATE:SAI_OBJECT_TYPE_VLAN:oid:0x26000000000615":
            {"SAI_VLAN_ATTR_VLAN_ID": "100"},
        "ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF:oid:0xd00000000056d":
            {"SAI_HOSTIF_ATTR_NAME": "Ethernet0",
             "SAI_HOSTIF_ATTR_OBJ_ID": "oid:0x1000000000012"},
        "ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF:oid:0xd00000000056e":
            {"SAI_HOSTIF_ATTR_NAME": "Ethernet4",
             "SAI_HOSTIF_ATTR_OBJ_ID": "oid:0x1000000000013"},
        "ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:0x1000000000012":
            {"SAI_PORT_ATTR_ADMIN_STATE": "true", "SAI_PORT_ATTR_MTU": "9122"},
        "ASIC_STATE:SAI_OBJECT_TYPE_PORT:oid:0x1000000000013":
            {"SAI_PORT_ATTR_ADMIN_STATE": "true", "SAI_PORT_ATTR_MTU": "9122"},
        'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:{"dest":"10.0.0.0/24",'
        '"switch_id":"oid:0x21000000000000","vr":"oid:0x3000000000022"}':
            {"SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID": "oid:0x40000000000a1"},
        'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:{"dest":"10.0.1.0/24",'
        '"switch_id":"oid:0x21000000000000","vr":"oid:0x3000000000022"}':
            {"SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID": "oid:0x40000000000a1"},
        'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:{"dest":"10.1.0.1/32",'
        '"switch_id":"oid:0x21000000000000","vr":"oid:0x3000000000022"}':
            {"SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION": "SAI_PACKET_ACTION_FORWARD"},
        'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:{"dest":"10.1.1.0/31",'
        '"switch_id":"oid:0x21000000000000","vr":"oid:0x3000000000022"}':
            {"SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID": "oid:0x60000000001bf"},
        "ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:oid:0x60000000001bf":
            {"SAI_ROUTER_INTERFACE_ATTR_PORT_ID": "oid:0x1000000000013"},
        'ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:{"ip":"10.1.1.2",'
        '"rif":"oid:0x60000000001bf","switch_id":"oid:0x21000000000000"}':
            {"SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS": "BC:24:11:9F:4E:D9"},
        'ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:{"bvid":"oid:0x26000000000615",'
        '"mac":"00:AA:BB:00:03:01","switch_id":"oid:0x21000000000000"}':
            {"SAI_FDB_ENTRY_ATTR_TYPE": "SAI_FDB_ENTRY_TYPE_DYNAMIC"},
    }
    bgp_rows = [
        "10.1.1.2        4      65200        31        31       50    0    0 "
        "00:21:18            2        2 spine0",
        "10.1.2.2        4      65300         0         0        0    0    0 "
        "   never       Active        0 ghost-peer",
    ]
    rib = [
        "C>* 10.1.0.1/32 (103) is directly connected, Loopback0, weight 1, 00:24:23",
        "B>* 10.0.0.0/24 [20/0] (125) via 10.1.1.2, Ethernet4, weight 1, 00:19:08",
        "S>* 10.0.1.0/24 [1/0] (125) via 10.1.1.2, Ethernet4, weight 1, 00:21:19",
    ]
    # dump/frr.ip.nht.vrf.all (`show ip nht vrf all`, FRR 10.5)
    nht = ["", "VRF default:", " Resolve via default: on",
           "10.1.1.2(Connected)", " resolved via connected, prefix 10.1.1.0/31",
           " is directly connected, Ethernet4 (vrf default), weight 1",
           " Client list: static(fd 68) bgp(fd 73)"]
    # real images ship months of pre-install history; must not be correlated
    stale_syslog = [
        "Jun 26 22:11:28.350855+00:00 2025 vlab-01 ERR swss#vlanmgrd: :- "
        "STALE doVlanMemberTask: failed to process Vlan100 Ethernet4",
        "Jun 26 22:11:29.000000+00:00 2025 vlab-01 ERR swss#orchagent: :- "
        "STALE addRoute: SAI_STATUS_FAILURE",
    ]
    syslog = [
        "Sep 15 11:58:01.000 vlab-01 INFO swss#orchagent: :- doTask: processing",
        "Sep 15 11:58:02.000 vlab-01 INFO swss#vlanmgrd: :- doVlanMemberTask: "
        "Vlan100 member Ethernet4 processed",
    ]
    bgpd_log = ["2026 Sep 15 11:58:00.000000 vlab-01 INFO bgp#bgpd[93]: "
                "[VTVCM-Y2NW3] Configuration Read in Took: 00:00:00"]
    rec = [
        "2026-09-15.11:58:02.100|c|SAI_OBJECT_TYPE_ROUTE_ENTRY:"
        '{"dest":"10.0.0.0/24","switch_id":"oid:0x21000000000000"}'
        "|SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID=oid:0x40000000000a1",
        # real: syncd learn notification (escaped JSON), then a neighbor
        # create that carries the same MAC as an attribute
        '2026-09-15.11:58:03.000|n|fdb_event|[{"fdb_entry":"{\\"bvid\\":'
        '\\"oid:0x26000000000615\\",\\"mac\\":\\"00:AA:BB:00:03:01\\",'
        '\\"switch_id\\":\\"oid:0x21000000000000\\"}","fdb_event":'
        '"SAI_FDB_EVENT_LEARNED","list":[]}]|',
        '2026-09-15.11:58:03.100|c|SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:{"ip":'
        '"192.168.100.31","rif":"oid:0x60000000001c6","switch_id":'
        '"oid:0x21000000000000"}|SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS='
        '00:AA:BB:00:03:01',
    ]
    services = ["Service   Status", "swss      running", "syncd     running",
                "bgp       running"]
    # real: `docker ps -a` table; status is only visible here on the validation image
    docker_ps = {"database": "Up 3 hours", "swss": "Up 25 minutes",
                 "syncd": "Up 25 minutes", "bgp": "Up 25 minutes"}

    if "vlan_member_stalled" in faults:
        del appl["VLAN_MEMBER_TABLE:Vlan100:Ethernet4"]
        syslog.append("Sep 15 11:59:00.000 vlab-01 ERR swss#vlanmgrd: "
                      ":- doVlanMemberTask: failed to process Vlan100 Ethernet4")
    if "route_not_programmed" in faults:
        asic = {k: v for k, v in asic.items() if '"dest":"10.0.1.0/24"' not in k}
        syslog.append("Sep 15 11:59:10.000 vlab-01 ERR swss#orchagent: "
                      ":- addRoute: SAI_STATUS_FAILURE creating 10.0.1.0/24")
        rec.append("2026-09-15.11:59:10.050|c|SAI_OBJECT_TYPE_ROUTE_ENTRY:"
                   '{"dest":"10.0.1.0/24","switch_id":"oid:0x21000000000000"}'
                   "|SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID=oid:0x40000000000a1")
    if "port_admin_mismatch" in faults:
        appl["PORT_TABLE:Ethernet0"]["admin_status"] = "down"
        syslog.append("Sep 15 11:59:20.000 vlab-01 NOTICE swss#portmgrd: "
                      ":- doTask: set Ethernet0 admin_status to down")
    if "swss_down" in faults:
        services[1] = "swss      Exited (1) 2 minutes ago"
        # real (s05): stopping swss also stops its peer syncd and dependent bgp
        for c, st in (("swss", "0"), ("syncd", "0"), ("bgp", "137")):
            docker_ps[c] = f"Exited ({st}) About a minute ago"
        bgp_rows = []
        rib = []  # real: vtysh captures are empty with bgp stopped
    if "bgp_peer_asn" in faults:
        cfg["BGP_NEIGHBOR|default|10.1.1.2"]["asn"] = "64999"
        bgp_rows[0] = ("10.1.1.2        4      64999        35        36        0"
                       "    0    0 00:01:02       Active        0 spine0")
        # real: rsyslog routes bgp#bgpd to log/bgpd.log (not syslog); the
        # decoy peer 10.1.1.21 shares the 10.1.1.2 prefix
        bgpd_log.append("2026 Sep 15 11:59:29.000000 vlab-01 ERR bgp#bgpd[93]: "
                        "[J9K4Q-T8STY][EC 33554466] 10.1.1.21 [FSM] Failure "
                        "handling event BGP_Start in state Idle")
        bgpd_log.append("2026 Sep 15 11:59:30.000000 vlab-01 ERR bgp#bgpd[93]: "
                        "[MVZKX-EG443][EC 33554452] bgp_process_packet: BGP OPEN "
                        "receipt failed for peer: 10.1.1.2")
    if "fpmsyncd_stalled" in faults:
        rib.append("B>* 10.0.2.0/24 [20/0] (125) via 10.1.1.2, Ethernet4, "
                   "weight 1, 00:00:40")
    if "route_asic_drift" in faults:
        # real (s06): ASIC_DB entry deleted out-of-band; the rec still ends
        # with orchagent's create and no SAI error was logged
        asic = {k: v for k, v in asic.items() if '"dest":"10.0.0.0/24"' not in k}
    if "route_unconsumed" in faults:
        # real (s03): orchagent stopped; fpmsyncd's ProducerStateTable write
        # stays in _ROUTE_TABLE + ROUTE_TABLE_KEY_SET, ROUTE_TABLE never set
        rib.append("S>* 10.0.3.0/24 [1/0] (125) via 10.1.1.2, Ethernet4, "
                   "weight 1, 00:00:40")
        appl["_ROUTE_TABLE:10.0.3.0/24"] = {"nexthop": "10.1.1.2",
                                            "ifname": "Ethernet4"}
        appl["ROUTE_TABLE_KEY_SET"] = ["10.0.3.0/24"]
    if "static_nh_unresolved" in faults:
        # real (s04): frrcfgd renders the route, staticd registers the nexthop
        # with zebra NHT, it stays unresolved and the route never enters the RIB
        cfg["STATIC_ROUTE|default|10.0.9.0/24"] = {"nexthop": "10.250.250.250"}
        nht += ["10.250.250.250", " unresolved", " Client list: static(fd 68)"]
    if "intf_ip_overlap" in faults:
        # real (s08): intfmgrd publishes the address, intfsorch rejects it
        # because Ethernet4 already owns the subnet (the ASIC route stays on
        # Ethernet4's RIF)
        cfg["INTERFACE|Ethernet0"] = {"NULL": "NULL"}
        cfg["INTERFACE|Ethernet0|10.1.1.0/31"] = {"NULL": "NULL"}
        appl["INTF_TABLE:Ethernet0"] = {"NULL": "NULL", "mac_addr": "00:00:00:00:00:00"}
        appl["INTF_TABLE:Ethernet0:10.1.1.0/31"] = {"family": "IPv4",
                                                    "scope": "global"}
        syslog.append("Sep 15 11:59:40.000 vlab-01 NOTICE swss#orchagent: :- "
                      "setIntf: Router interface Ethernet0 IP 10.1.1.0/31 "
                      "overlaps with 10.1.1.1/31.")
    if "acl_rule_rejected" in faults:
        # real (s10): aclorch rejects an unsupported match; STATE_DB Inactive
        cfg["ACL_RULE|DATA_T|R2"] = {"PRIORITY": "20", "PACKET_ACTION": "FORWARD",
                                     "DUMMY_MATCH": "1"}
        state["ACL_RULE_TABLE|DATA_T|R2"] = {"status": "Inactive"}
        syslog.append("Sep 15 11:59:50.000 vlab-01 ERR swss#orchagent: :- "
                      "doAclRuleTask: Unknown or invalid rule attribute "
                      "'DUMMY_MATCH : 1'")
    if "fdb_not_programmed" in faults:
        asic = {k: v for k, v in asic.items() if "FDB_ENTRY" not in k}
    if "neigh_not_programmed" in faults:
        asic = {k: v for k, v in asic.items() if "NEIGHBOR_ENTRY" not in k}

    d = root / "dump"
    (d / "CONFIG_DB.json").write_text(_dbjson(cfg))
    (d / "APPL_DB.json").write_text(_dbjson({**appl, **gearbox}))
    (d / "ASIC_DB.json").write_text(_dbjson(asic))
    (d / "STATE_DB.json").write_text(_dbjson(state))
    for empty in ("COUNTERS_DB", "FLEX_COUNTER_DB", "APPL_STATE_DB"):
        (d / f"{empty}.json").write_text("{}")
    (d / "bgp.summary").write_text("\n".join([
        "", "IPv4 Unicast Summary:",
        "BGP router identifier 10.1.0.1, local AS number 65100 VRF default vrf-id 0",
        "Peers 2, using 47 KiB of memory", "",
        "Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  "
        "Up/Down State/PfxRcd   PfxSnt Desc", *bgp_rows, "",
        "Total number of neighbors 2"]) + "\n")
    (d / "frr.ip_route.nhg").write_text("\n".join([
        "Codes: K - kernel route, C - connected, L - local, S - static,",
        "       > - selected route, * - FIB route, q - queued, r - rejected, b - backup",
        "", "IPv4 unicast VRF default:", *rib]) + "\n")
    (d / "frr.ip.nht.vrf.all").write_text(
        "\n".join(nht + ["", "VRF mgmt:", " Resolve via default: on"]) + "\n")
    (d / "version").write_text(
        "SONiC Software Version: SONiC.202605.0-dirty\nPlatform: x86_64-kvm\n")
    (d / "services.summary").write_text("\n".join(services) + "\n")
    (d / "docker.ps").write_text("\n".join(
        ["CONTAINER ID   IMAGE                 COMMAND                  CREATED"
         "       STATUS                            PORTS     NAMES"]
        + [f"{i:012x}   docker-{c}:latest   \"/usr/local/bin/supe…\"   3 hours ago"
           f"   {st:<32}            {c}"
           for i, (c, st) in enumerate(docker_ps.items(), 1)]) + "\n")
    log = root / "log"
    if flat_logs:
        (log / "swss").rmdir()
        _gz(log / "syslog.gz", [])                    # clobbered current file
        _gz(log / "syslog.1.gz", syslog)
        _gz(log / "syslog.2.gz", stale_syslog)
        _gz(log / "syslog-info.log.gz", ["Sep 15 11:58:00.000 vlab-01 INFO "
                                         "swss#vlanmgrd: unrelated info file"])
        _gz(log / "sairedis.rec.gz", rec)
        _gz(log / "swss.rec.gz", [])
        _gz(log / "bgpd.log.gz", bgpd_log)
    else:
        (log / "syslog").write_text("\n".join(syslog) + "\n")
        (log / "bgpd.log").write_text("\n".join(bgpd_log) + "\n")
        _gz(log / "syslog.1.gz", stale_syslog)
        (log / "swss" / "sairedis.rec").write_text("\n".join(rec) + "\n")
        (log / "swss" / "swss.rec").write_text("")
    return root


def build_tarball(dest: Path, faults: set[str] = frozenset(),
                  flat_logs: bool = False) -> Path:
    root = build_dump(dest / "stage", faults, flat_logs)
    tb = dest / "techsupport.tar.gz"
    with tarfile.open(tb, "w:gz") as tf:
        tf.add(root, arcname=root.name)
        if flat_logs:
            # real archives: hard links + device nodes under etc/
            f = tarfile.TarInfo(f"{root.name}/etc/rc5.d/S01chrony")
            data = b"#!/bin/sh\n"
            f.size = len(data)
            tf.addfile(f, io.BytesIO(data))
            h = tarfile.TarInfo(f"{root.name}/etc/rc2.d/S01chrony")
            h.type, h.linkname = tarfile.LNKTYPE, f.name
            tf.addfile(h)
            c = tarfile.TarInfo(f"{root.name}/etc/udev/null")
            c.type, c.devmajor, c.devminor = tarfile.CHRTYPE, 1, 3
            tf.addfile(c)
    return tb


if __name__ == "__main__":
    import sys
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("demo")
    out.mkdir(parents=True, exist_ok=True)
    tb = build_tarball(out, faults={"route_not_programmed",
                                    "vlan_member_stalled", "bgp_peer_asn"})
    print(tb)

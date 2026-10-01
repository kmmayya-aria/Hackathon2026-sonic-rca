"""Parsers for vtysh text captures in dump/, exposed as read-only pseudo-DBs.

Formats are taken from real FRR 10.5 techsupport captures (SONiC main-derivative image):
  dump/bgp.summary        `show ip bgp summary`         -> FRR_BGP
  dump/frr.ip_route.nhg   `show ip route nexthop-group` -> FRR_RIB
  dump/frr.ip6_route.nhg  (IPv6 variant)                -> FRR_RIB
  dump/frr.ip.nht.vrf.all `show ip nht vrf all`         -> FRR_NHT
  dump/frr.ipv6.nht.vrf.all (IPv6 variant)              -> FRR_NHT
Note dump/ip.route on these images is the *kernel* FIB (`ip route show
table all`), not FRR's RIB; the selected-route markers (B>*, S>*) live in
frr.ip_route.nhg.

Each pseudo-DB row carries `_source` (archive-relative file) and `_lineno`
so findings cite the exact capture line.
"""
from __future__ import annotations

import re
from typing import Callable

Row = dict[str, str]

# 10.0.0.1  4  65200  31  31  50  0  0 00:21:18  50  50 spine0
_BGP_PEER = re.compile(
    r"^(?P<peer>[0-9a-fA-F.:]+)\s+4\s+(?P<asn>\d+)\s+(?P<rcvd>\d+)\s+"
    r"(?P<sent>\d+)\s+\d+\s+\d+\s+\d+\s+(?P<updown>\S+)\s+"
    r"(?P<state>\d+|\(Policy\)|[A-Za-z]+(?: \([^)]*\))?)"
    r"(?:\s+(?P<pfxsnt>\d+|\(Policy\)))?(?:\s+(?P<desc>.*))?$")
_BGP_VRF = re.compile(r"local AS number \d+ VRF (\S+)")
_BGP_ONLY_PEER = re.compile(r"^[0-9a-fA-F.:]+$")


def parse_bgp_summary(text: str) -> dict[str, Row]:
    """`show ip bgp summary` -> {"<vrf>|<peer>": row}.

    A numeric State/PfxRcd (or "(Policy)") means Established.
    """
    out: dict[str, Row] = {}
    vrf, pending = "default", None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        m = _BGP_VRF.search(line)
        if m:
            vrf = m.group(1)
            continue
        if _BGP_ONLY_PEER.match(line):          # long hostname: data wraps
            pending = (n, line)
            continue
        if pending and line.startswith(" "):
            n, line = pending[0], pending[1] + " " + line.strip()
        pending = None
        m = _BGP_PEER.match(line)
        if not m:
            continue
        st = m.group("state")
        established = st.isdigit() or st == "(Policy)"
        out[f"{vrf}|{m.group('peer')}"] = {
            "asn": m.group("asn"), "msg_rcvd": m.group("rcvd"),
            "msg_sent": m.group("sent"), "up_down": m.group("updown"),
            "state": "Established" if established else st,
            "pfx_rcd": st if established else "0",
            "desc": (m.group("desc") or "").strip(),
            "_lineno": str(n), "_line": raw.strip()}
    return out


# S>* 172.20.1.0/24 [1/0] (125) via 10.0.0.1, Ethernet1, weight 1, 00:21:19
# C * fe80::/64 (197) is directly connected, veth4, weight 1, 00:00:57
_RIB_HDR = re.compile(r"^IPv(?P<afi>[46]) unicast VRF (?P<vrf>\S+?):?$")
_RIB_ROUTE = re.compile(
    r"^(?P<proto>[A-Za-z])(?P<flags>[>* qrbto=]{0,3}?)\s+"
    r"(?P<prefix>[0-9a-fA-F.:]+/\d+)\s*(?P<rest>.*)$")
_RIB_CONT = re.compile(r"^\s+[>* qrbto=]*\s*(?:via|is directly)")
_NH_VIA = re.compile(r"via (?P<nh>[0-9a-fA-F.:]+)(?:, (?P<ifname>[\w./-]+))?")
_NH_CONN = re.compile(r"is directly connected, (?P<ifname>[\w./-]+)")


def _nexthops(text: str) -> tuple[list[str], list[str]]:
    m = _NH_VIA.search(text)
    if m:
        return [m.group("nh")], [m.group("ifname")] if m.group("ifname") else []
    m = _NH_CONN.search(text)
    return ([], [m.group("ifname")]) if m else ([], [])


def parse_frr_routes(text: str, afi_default: str = "4") -> dict[str, Row]:
    """`show ip route [nexthop-group]` -> {"<vrf>|<prefix>": row}.

    Keeps the selected ('>') entry per prefix (else the first seen); ECMP
    continuation lines append nexthops to the preceding route.
    """
    out: dict[str, Row] = {}
    vrf, cur, cur_nh, cur_if = "default", None, [], []

    def flush():
        if cur is not None:
            key = f"{vrf}|{cur['prefix']}"
            cur["nexthop"] = ",".join(sorted(set(cur_nh)))
            cur["ifname"] = ",".join(sorted(set(cur_if)))
            if key not in out or (cur["selected"] == "true"
                                  and out[key]["selected"] != "true"):
                out[key] = cur

    for n, raw in enumerate(text.splitlines(), 1):
        m = _RIB_HDR.match(raw.strip())
        if m:
            flush()
            cur, vrf = None, m.group("vrf")
            continue
        if cur is not None and _RIB_CONT.match(raw):
            nh, ifs = _nexthops(raw)
            cur_nh += nh
            cur_if += ifs
            continue
        m = _RIB_ROUTE.match(raw)
        if not m:
            continue
        flush()
        flags = m.group("flags")
        cur_nh, cur_if = _nexthops(m.group("rest"))
        cur = {"prefix": m.group("prefix"), "vrf": vrf,
               "protocol": m.group("proto"),
               "selected": "true" if ">" in flags else "false",
               "fib": "true" if "*" in flags else "false",
               "blackhole": "true" if "blackhole" in m.group("rest") else "false",
               "_lineno": str(n), "_line": raw.strip()}
    flush()
    return out


_NHT_VRF = re.compile(r"^VRF (?P<vrf>\S+):$")
# 10.0.0.1(Connected) | 10.250.250.250
_NHT_ADDR = re.compile(r"^(?P<addr>[0-9a-fA-F.:]+)(?:\((?P<how>[^)]*)\))?$")


def parse_frr_nht(text: str) -> dict[str, Row]:
    """`show ip nht vrf all` -> {"<vrf>|<addr>": row}.

    An address line (column 0) is followed by indented detail lines:
    ` resolved via connected, prefix ...` or ` unresolved`, then
    ` Client list: static(fd 68) bgp(fd 73)`.
    """
    out: dict[str, Row] = {}
    vrf, cur = "default", None
    for n, raw in enumerate(text.splitlines(), 1):
        m = _NHT_VRF.match(raw)
        if m:
            vrf, cur = m.group("vrf"), None
            continue
        m = _NHT_ADDR.match(raw)
        if m:
            cur = {"address": m.group("addr"), "vrf": vrf, "resolved": "false",
                   "via": "", "clients": "", "_lineno": str(n), "_line": raw}
            out[f"{vrf}|{m.group('addr')}"] = cur
            continue
        if cur is None or not raw.startswith(" "):
            continue
        line = raw.strip()
        if line.startswith("resolved via"):
            cur["resolved"] = "true"
            cur["via"] = line[len("resolved via "):]
        elif line == "unresolved":
            cur["resolved"] = "false"
            cur["_line"] = f"{cur['_line']} {line}"
        elif line.startswith("Client list:"):
            cur["clients"] = ",".join(re.findall(r"(\w+)\(fd", line))
    return out


# pseudo-DB name -> (capture files under dump/, parser, key prefix)
CAPTURE_DBS: dict[str, tuple[tuple[str, ...], Callable[[str], dict[str, Row]], str]] = {
    "FRR_BGP": (("bgp.summary",), parse_bgp_summary, "BGP_PEER|"),
    "FRR_RIB": (("frr.ip_route.nhg", "frr.ip6_route.nhg"), parse_frr_routes, "RIB|"),
    "FRR_NHT": (("frr.ip.nht.vrf.all", "frr.ipv6.nht.vrf.all"), parse_frr_nht, "NHT|"),
}

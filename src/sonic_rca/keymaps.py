"""Per-feature key maps across the SONiC state pipeline.

Mapping knowledge follows the sonic-utilities `dump state` plugin framework
(dump/plugins/{port,vlan,route}.py on branch 202605): CONFIG_DB uses '|'
separators, APPL_DB uses ':' table keys, ASIC_DB keys are
'ASIC_STATE:SAI_OBJECT_TYPE_<T>:<oid-or-json>'.
Each map: (index, intent_key) -> (reality_key or None, note).
Registered by name; playbooks reference maps by that name.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Callable, Optional

from .archive import ArchiveError

MapResult = tuple[Optional[str], str]
MapFn = Callable[["EvidenceIndex", str], MapResult]  # noqa: F821 (doc only)

_MAPS: dict[str, MapFn] = {}


def keymap(name: str):
    def deco(fn):
        _MAPS[name] = fn
        return fn
    return deco


def get_map(name: str) -> MapFn:
    if name not in _MAPS:
        raise KeyError(f"unknown key map: {name} (known: {sorted(_MAPS)})")
    return _MAPS[name]


# ---- intent filters: which intent keys the reality layer must carry ---------

FilterFn = Callable[[str, dict], bool]
_FILTERS: dict[str, FilterFn] = {}


def intent_filter(name: str, with_index: bool = False):
    # with_index: fn(key, val, index) for filters that consult other tables
    def deco(fn):
        fn.with_index = with_index
        _FILTERS[name] = fn
        return fn
    return deco


def get_filter(name: str) -> FilterFn:
    if name not in _FILTERS:
        raise KeyError(f"unknown intent filter: {name} (known: {sorted(_FILTERS)})")
    return _FILTERS[name]


# ---- refiners: DB-evidence conditions for refine_missing rules --------------
# (index, intent_key) -> evidence id when the condition holds, else None

RefineFn = Callable[["EvidenceIndex", str], Optional[str]]  # noqa: F821
_REFINERS: dict[str, RefineFn] = {}


def refiner(name: str):
    def deco(fn):
        _REFINERS[name] = fn
        return fn
    return deco


def get_refiner(name: str) -> RefineFn:
    if name not in _REFINERS:
        raise KeyError(f"unknown refiner: {name} (known: {sorted(_REFINERS)})")
    return _REFINERS[name]


@refiner("static_nexthop_unresolved")
def static_nexthop_unresolved(index, cfg_key: str) -> Optional[str]:
    """A STATIC_ROUTE nexthop that staticd registered with zebra NHT and that
    is unresolved (dump/frr.ip.nht.vrf.all): staticd withholds the route."""
    val = index.db_key("CONFIG_DB", cfg_key) or {}
    parts = cfg_key.split("|")
    vrf = val.get("nexthop-vrf") or (parts[1] if len(parts) > 2 else "default")
    for nh in filter(None, val.get("nexthop", "").split(",")):
        k = f"NHT|{vrf}|{nh}"
        try:
            row = index.db_key("FRR_NHT", k)
        except ArchiveError:
            return None
        if row and row.get("resolved") == "false" and "static" in row.get("clients", ""):
            return index.cite_db("FRR_NHT", k)
    return None


@refiner("intf_subnet_overlap")
def intf_subnet_overlap(index, key: str) -> Optional[str]:
    """Another interface already owns an overlapping subnet in APPL_DB
    INTF_TABLE: intfsorch rejects the address (setIntf "overlaps with")."""
    ifname, prefix = _intf_parts(key)
    net = ipaddress.ip_interface(prefix).network
    for k in sorted(index.db_get("APPL_DB", "INTF_TABLE:*")):
        other_if, other_pfx = _intf_parts(k)
        if not other_pfx or other_if == ifname:
            continue
        try:
            other = ipaddress.ip_interface(other_pfx).network
        except ValueError:
            continue
        if other.version == net.version and other.overlaps(net):
            return index.cite_db("APPL_DB", k)
    return None


# ---- benign rules: expected-state mismatches that are not pipeline faults ----

BenignFn = Callable[[str, dict], bool]
_BENIGN: dict[str, BenignFn] = {}


def benign_rule(name: str):
    def deco(fn):
        _BENIGN[name] = fn
        return fn
    return deco


def get_benign(name: str) -> BenignFn:
    if name not in _BENIGN:
        raise KeyError(f"unknown benign rule: {name} (known: {sorted(_BENIGN)})")
    return _BENIGN[name]


@benign_rule("bgp_peer_never_reached")
def bgp_peer_never_reached(key: str, rval: dict) -> bool:
    """Never Established and not one message received: the peer address is
    unreachable/unanswered (no OPEN was ever exchanged, so nothing on this box
    rejected it). Reported as a note, not a pipeline divergence."""
    return rval.get("up_down") == "never" and rval.get("msg_rcvd") == "0"


# ---- correlation fragments: object identity used to search logs/recordings --

FragFn = Callable[[str], str]
_FRAGS: dict[str, FragFn] = {}


def fragment(name: str):
    def deco(fn):
        _FRAGS[name] = fn
        return fn
    return deco


def get_fragment(name: str) -> FragFn:
    if name not in _FRAGS:
        raise KeyError(f"unknown fragment: {name} (known: {sorted(_FRAGS)})")
    return _FRAGS[name]


@fragment("last")
def frag_last(key: str) -> str:
    # VLAN_MEMBER|Vlan100|Ethernet4 -> Ethernet4
    return key.replace("|", ":").split(":")[-1]


@fragment("intf_prefix")
def frag_intf_prefix(key: str) -> str:
    # INTF_TABLE:Ethernet9:10.0.0.0/31 -> 10.0.0.0/31
    return _intf_parts(key)[1]


@fragment("acl_table")
def frag_acl_table(key: str) -> str:
    # ACL_RULE|RCA_T|R1 -> RCA_T
    return key.split("|")[1]


@fragment("route_cidr")
def frag_route_cidr(key: str) -> str:
    # ROUTE_TABLE:10.1.0.1 -> 10.1.0.1/32 ; RIB|default|198.51.1.0/24 -> 198.51.1.0/24
    # STATIC_ROUTE|default|10.9.1.0/24 -> 10.9.1.0/24
    if key.startswith(("RIB|", "STATIC_ROUTE|")):
        return key.rsplit("|", 1)[1]
    return route_prefix(key)


@fragment("appl_body")
def frag_appl_body(key: str) -> str:
    # _ROUTE_TABLE:fc00::/64 -> fc00::/64 (IPv6-safe, unlike "last")
    return key.split(":", 1)[1]


@fragment("route_dest")
def frag_route_dest(key: str) -> str:
    # ROUTE_TABLE:fe80::/64 -> "dest":"fe80::/64" (as in sairedis.rec json)
    return f'"dest":"{frag_route_cidr(key)}"'


@fragment("bgp_peer")
def frag_bgp_peer(key: str) -> str:
    # BGP_NEIGHBOR|default|10.0.0.1 (or legacy BGP_NEIGHBOR|10.0.0.1) -> 10.0.0.1
    return key.rsplit("|", 1)[1]


@fragment("fdb_mac")
def frag_fdb_mac(key: str) -> str:
    # FDB_TABLE|Vlan100:00:aa:bb:00:03:01 -> 00:AA:BB:00:03:01 (ASIC/rec case)
    return _fdb_parts(key)[1].upper()


@fragment("fdb_mac_rec")
def frag_fdb_mac_rec(key: str) -> str:
    # FDB entry inside a sairedis.rec fdb_event notification (escaped JSON):
    # \"mac\":\"00:AA:BB:00:03:01\" -- unlike the bare MAC, never a neighbor
    return f'\\"mac\\":\\"{frag_fdb_mac(key)}\\"'


@fragment("neigh_ip")
def frag_neigh_ip(key: str) -> str:
    # NEIGH_TABLE:Vlan100:192.168.100.31 -> 192.168.100.31 (IPv6-safe)
    return _neigh_parts(key)[1]


@fragment("neigh_ip_json")
def frag_neigh_ip_json(key: str) -> str:
    return f'"ip":"{frag_neigh_ip(key)}"'


# ---- route helpers ------------------------------------------------------------

# Netdevs orchagent programs routes over; anything else (eth0, sr0, docker0,
# lo, ...) is a kernel-only interface that routeorch never resolves.
_ROUTER_IF_RE = re.compile(r"^(Ethernet|PortChannel|Vlan|Loopback|Eth)\S*$")


def route_prefix(appl_key: str) -> str:
    """ROUTE_TABLE:[<vrf>:]<prefix> -> canonical CIDR (host routes get /32|/128).

    APPL_DB drops the mask on host routes (ROUTE_TABLE:10.1.0.1) while
    ASIC_DB always carries it (dest=10.1.0.1/32).
    """
    rest = appl_key.split(":", 1)[1]
    if rest.startswith("Vrf"):
        rest = rest.split(":", 1)[1]
    if "/" not in rest:
        rest += "/128" if ":" in rest else "/32"
    return rest


@intent_filter("route_in_asic_scope")
def route_in_asic_scope(key: str, val: dict) -> bool:
    ifnames = [i for i in str(val.get("ifname", "")).split(",") if i]
    return not ifnames or any(_ROUTER_IF_RE.match(i) for i in ifnames)


@intent_filter("rib_selected_bgp_static")
def rib_selected_bgp_static(key: str, val: dict) -> bool:
    """Selected BGP/static routes of non-mgmt VRFs that fpmsyncd must carry."""
    return (val.get("protocol") in ("B", "S") and val.get("selected") == "true"
            and val.get("vrf") != "mgmt" and route_in_asic_scope(key, val))


# ProducerStateTables with no orchagent consumer on vs (gearsyncd handshake)
_NO_CONSUMER = {"GEARBOX_TABLE"}


@intent_filter("producer_pending")
def producer_pending(key: str, val: dict) -> bool:
    return (key.startswith("_") and ":" in key
            and key[1:].split(":", 1)[0] not in _NO_CONSUMER)


@intent_filter("intf_subnet_in_asic_scope")
def intf_subnet_in_asic_scope(key: str, val: dict) -> bool:
    """Addressed routed ports/VLAN/LAG interfaces: intfsorch programs a subnet
    route via the interface's RIF. Loopbacks and host prefixes only get ip2me."""
    ifname, prefix = _intf_parts(key)
    if not prefix or not ifname.startswith(("Ethernet", "Vlan", "PortChannel")):
        return False
    try:
        net = ipaddress.ip_interface(prefix).network
    except ValueError:
        return False
    return net.prefixlen < net.max_prefixlen and not net.is_link_local


@intent_filter("acl_rule_dataplane", with_index=True)
def acl_rule_dataplane(key: str, val: dict, index) -> bool:
    # CTRLPLANE tables are caclmgrd's (iptables), never aclorch's
    table = index.db_key("CONFIG_DB", f"ACL_TABLE|{key.split('|')[1]}") or {}
    return str(table.get("type", "")).upper() != "CTRLPLANE"


@intent_filter("bgp_admin_up")
def bgp_admin_up(key: str, val: dict) -> bool:
    return str(val.get("admin_status", "up")).lower() != "down"


@intent_filter("neigh_in_asic_scope")
def neigh_in_asic_scope(key: str, val: dict) -> bool:
    # NEIGH_TABLE:eth0:* (mgmt) and other kernel-only netdevs are never programmed
    return bool(_ROUTER_IF_RE.match(_neigh_parts(key)[0]))


# ---- FDB / neighbor key helpers ---------------------------------------------

_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})$")


def _fdb_parts(key: str) -> tuple[str, str]:
    """FDB_TABLE|Vlan100:<mac> (STATE_DB) / FDB_TABLE:Vlan100:<mac> (APPL_DB)."""
    body = key.split("|", 1)[1] if "|" in key else key.split(":", 1)[1]
    m = _MAC_RE.search(body)
    mac = m.group(1) if m else body
    return body[: len(body) - len(mac)].rstrip(":"), mac


def _intf_parts(key: str) -> tuple[str, str]:
    # INTF_TABLE:<ifname>[:<ip>/<len>] (the IPv6 prefix keeps its colons)
    parts = key.split(":", 2)
    return parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else ""


def _neigh_parts(key: str) -> tuple[str, str]:
    """NEIGH_TABLE:<ifname>:<ip>; the ip may itself contain ':' (IPv6)."""
    ifname, ip = key.split(":", 1)[1].split(":", 1)
    return ifname, ip


# ---- CONFIG_DB -> APPL_DB ---------------------------------------------------

@keymap("port_table")
def cfg_port_to_appl(index, cfg_key: str) -> MapResult:
    # PORT|Ethernet0 -> PORT_TABLE:Ethernet0
    name = cfg_key.split("|", 1)[1]
    appl_key = f"PORT_TABLE:{name}"
    return (appl_key if index.db_key("APPL_DB", appl_key) is not None else None,
            appl_key)


@keymap("vlan_member_table")
def cfg_vlan_member_to_appl(index, cfg_key: str) -> MapResult:
    # VLAN_MEMBER|Vlan100|Ethernet4 -> VLAN_MEMBER_TABLE:Vlan100:Ethernet4
    parts = cfg_key.split("|")
    appl_key = "VLAN_MEMBER_TABLE:" + ":".join(parts[1:])
    return (appl_key if index.db_key("APPL_DB", appl_key) is not None else None,
            appl_key)


@keymap("intf_table")
def cfg_intf_to_appl(index, cfg_key: str) -> MapResult:
    # INTERFACE|Ethernet4|10.0.0.1/31 -> INTF_TABLE:Ethernet4:10.0.0.1/31
    parts = cfg_key.split("|")
    appl_key = "INTF_TABLE:" + ":".join(parts[1:])
    return (appl_key if index.db_key("APPL_DB", appl_key) is not None else None,
            appl_key)


# ---- CONFIG_DB -> STATE_DB --------------------------------------------------

@keymap("state_acl_rule")
def cfg_acl_rule_to_state(index, cfg_key: str) -> MapResult:
    # ACL_RULE|RCA_T|R1 -> ACL_RULE_TABLE|RCA_T|R1 (aclorch: status Active/Inactive)
    state_key = "ACL_RULE_TABLE|" + cfg_key.split("|", 1)[1]
    return (state_key if index.db_key("STATE_DB", state_key) is not None else None,
            state_key)


# ---- APPL_DB -> ASIC_DB -----------------------------------------------------

_ROUTE_PREFIX = "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:"


@keymap("sai_route_entry")
def appl_route_to_asic(index, appl_key: str) -> MapResult:
    """ROUTE_TABLE:<prefix> -> ASIC route entry whose json 'dest' == prefix."""
    prefix = route_prefix(appl_key)
    note = f"{_ROUTE_PREFIX}{{dest={prefix}}}"
    for k in index.db_get("ASIC_DB", _ROUTE_PREFIX + "*"):
        blob = k[len(_ROUTE_PREFIX):]
        try:
            dest = json.loads(blob).get("dest")
        except (ValueError, AttributeError):
            m = re.search(r'"dest"\s*:\s*"([^"]+)"', blob)
            dest = m.group(1) if m else None
        if dest == prefix:
            return k, note
    return None, note


@keymap("sai_vlan")
def cfg_vlan_to_asic(index, cfg_key: str) -> MapResult:
    """VLAN|Vlan100 -> ASIC vlan object with SAI_VLAN_ATTR_VLAN_ID == 100."""
    vid = cfg_key.split("|", 1)[1].removeprefix("Vlan")
    note = f"ASIC_STATE:SAI_OBJECT_TYPE_VLAN:{{SAI_VLAN_ATTR_VLAN_ID={vid}}}"
    for k, v in index.db_get("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_VLAN:*").items():
        if str(v.get("SAI_VLAN_ATTR_VLAN_ID")) == vid:
            return k, note
    return None, note


@keymap("sai_port_admin")
def appl_port_to_asic(index, appl_key: str) -> MapResult:
    """PORT_TABLE:EthernetN -> SAI port object, via HOSTIF name -> port oid."""
    name = appl_key.split(":", 1)[1]
    note = f"SAI_OBJECT_TYPE_PORT via HOSTIF name={name}"
    port_oid = None
    for v in index.db_get("ASIC_DB",
                          "ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF:*").values():
        if v.get("SAI_HOSTIF_ATTR_NAME") == name:
            port_oid = v.get("SAI_HOSTIF_ATTR_OBJ_ID")
            break
    if not port_oid:
        return None, note
    k = f"ASIC_STATE:SAI_OBJECT_TYPE_PORT:{port_oid}"
    return (k if index.db_key("ASIC_DB", k) is not None else None, note)


def _vlan_oid(index, vid: str) -> Optional[str]:
    for k, v in index.db_get("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_VLAN:*").items():
        if str(v.get("SAI_VLAN_ATTR_VLAN_ID")) == vid:
            return k.split(":", 2)[2]
    return None


def _json_keys(index, prefix: str):
    for k in index.db_get("ASIC_DB", prefix + "*"):
        try:
            yield k, json.loads(k[len(prefix):])
        except ValueError:
            continue


_FDB_PREFIX = "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:"


@keymap("sai_fdb_entry")
def fdb_to_asic(index, key: str) -> MapResult:
    """FDB_TABLE|Vlan100:<mac> -> FDB_ENTRY {bvid=<VLAN oid of 100>, mac=UPPER}."""
    vlan, mac = _fdb_parts(key)
    mac = mac.upper()
    vid = vlan.removeprefix("Vlan")
    note = f"{_FDB_PREFIX}{{bvid=<oid of VLAN {vid}>,mac={mac}}}"
    bvid = _vlan_oid(index, vid)
    for k, blob in _json_keys(index, _FDB_PREFIX):
        if str(blob.get("mac", "")).upper() == mac and \
                (bvid is None or blob.get("bvid") == bvid):
            return k, note
    return None, note


_NEIGH_PREFIX = "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:"


def _rif_ifname(index, rif: str) -> Optional[str]:
    """Router-interface oid -> EthernetN (via HOSTIF) or VlanN (via VLAN_ID)."""
    v = index.db_key("ASIC_DB", f"ASIC_STATE:SAI_OBJECT_TYPE_ROUTER_INTERFACE:{rif}")
    if not v:
        return None
    port = v.get("SAI_ROUTER_INTERFACE_ATTR_PORT_ID")
    if port:
        for h in index.db_get("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF:*").values():
            if h.get("SAI_HOSTIF_ATTR_OBJ_ID") == port:
                return h.get("SAI_HOSTIF_ATTR_NAME")
    vlan = v.get("SAI_ROUTER_INTERFACE_ATTR_VLAN_ID")
    if vlan:
        vv = index.db_key("ASIC_DB", f"ASIC_STATE:SAI_OBJECT_TYPE_VLAN:{vlan}")
        if vv and vv.get("SAI_VLAN_ATTR_VLAN_ID"):
            return f"Vlan{vv['SAI_VLAN_ATTR_VLAN_ID']}"
    return None


@keymap("sai_neighbor_entry")
def neigh_to_asic(index, key: str) -> MapResult:
    """NEIGH_TABLE:<ifname>:<ip> -> NEIGHBOR_ENTRY {ip, rif resolving to ifname}."""
    ifname, ip = _neigh_parts(key)
    note = f"{_NEIGH_PREFIX}{{ip={ip},rif=<{ifname}>}}"
    for k, blob in _json_keys(index, _NEIGH_PREFIX):
        if blob.get("ip") != ip:
            continue
        rif_if = _rif_ifname(index, str(blob.get("rif")))
        if rif_if is None or rif_if == ifname:
            return k, note
    return None, note


@keymap("sai_intf_subnet_route")
def intf_to_subnet_route(index, key: str) -> MapResult:
    """INTF_TABLE:<ifname>:<ip>/<len> -> ROUTE_ENTRY {dest=<network>} whose
    nexthop is the RIF of <ifname> (intfsorch addSubnetRoute)."""
    ifname, prefix = _intf_parts(key)
    net = str(ipaddress.ip_interface(prefix).network)
    note = f"{_ROUTE_PREFIX}{{dest={net},nexthop=<rif of {ifname}>}}"
    for k, blob in _json_keys(index, _ROUTE_PREFIX):
        if blob.get("dest") != net:
            continue
        nh = (index.db_key("ASIC_DB", k) or {}).get("SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID")
        if _rif_ifname(index, str(nh)) == ifname:
            return k, note
    return None, note


# ---- FRR captures (pseudo-DBs, see captures.py) -----------------------------

@keymap("frr_bgp_peer")
def cfg_bgp_neighbor_to_frr(index, cfg_key: str) -> MapResult:
    # BGP_NEIGHBOR|default|10.0.0.1 (or legacy BGP_NEIGHBOR|10.0.0.1)
    parts = cfg_key.split("|")
    vrf = parts[1] if len(parts) > 2 else "default"
    k = f"BGP_PEER|{vrf}|{parts[-1]}"
    return (k if index.db_key("FRR_BGP", k) is not None else None,
            f"{k} in dump/bgp.summary")


@keymap("frr_rib_from_static")
def static_route_to_rib(index, cfg_key: str) -> MapResult:
    # STATIC_ROUTE|default|10.9.1.0/24 (or legacy STATIC_ROUTE|10.9.1.0/24)
    parts = cfg_key.split("|")
    vrf = parts[1] if len(parts) > 2 else "default"
    k = f"RIB|{vrf}|{parts[-1]}"
    return (k if index.db_key("FRR_RIB", k) is not None else None,
            f"{k} in dump/frr.ip_route.nhg")


@keymap("appl_route_from_rib")
def rib_to_appl_route(index, rib_key: str) -> MapResult:
    """RIB|<vrf>|<prefix> -> ROUTE_TABLE:[<vrf>:]<prefix> (host routes w/o mask)."""
    _, vrf, prefix = rib_key.split("|", 2)
    base = "ROUTE_TABLE:" + ("" if vrf == "default" else f"{vrf}:")
    cands = [base + prefix]
    if prefix.endswith(("/32", "/128")):
        cands.append(base + prefix.rsplit("/", 1)[0])
    # `_ROUTE_TABLE:` = written by fpmsyncd, not yet consumed by orchagent
    # (ProducerStateTable); fpmsyncd did deliver it -> see appl.unconsumed.
    cands += ["_" + k for k in cands]
    for k in cands:
        if index.db_key("APPL_DB", k) is not None:
            return k, cands[0]
    return None, cands[0]


@keymap("appl_consumed")
def appl_pending_to_consumed(index, key: str) -> MapResult:
    """_<TABLE>:<k> still queued in <TABLE>_KEY_SET -> never applied."""
    table, body = key[1:].split(":", 1)
    queued = index.db_key("APPL_DB", f"{table}_KEY_SET") or {}
    state = "still queued in" if body in str(queued) else "pending, not in"
    return None, f"{table}:{body} not applied by consumer ({state} {table}_KEY_SET)"


# ---- field normalizers (compare across layer vocabularies) ------------------

_TRUTHY = {"up": "up", "true": "up", "enabled": "up",
           "down": "down", "false": "down", "disabled": "down"}


def norm_field(name: str, value) -> str:
    v = str(value).lower()
    if name in ("admin_status", "SAI_PORT_ATTR_ADMIN_STATE", "oper_status"):
        return _TRUTHY.get(v, v)
    if name in ("nexthop", "ifname"):             # ECMP order is not meaningful
        return ",".join(sorted(x for x in v.split(",") if x))
    return v


FIELD_ALIASES = {
    # playbook field -> per-DB field names
    "admin_status": {"CONFIG_DB": "admin_status", "APPL_DB": "admin_status",
                     "ASIC_DB": "SAI_PORT_ATTR_ADMIN_STATE"},
    "tagging_mode": {"CONFIG_DB": "tagging_mode", "APPL_DB": "tagging_mode"},
    "nexthop": {"APPL_DB": "nexthop"},
    "ifname": {"APPL_DB": "ifname"},
    "mtu": {"CONFIG_DB": "mtu", "APPL_DB": "mtu", "ASIC_DB": "SAI_PORT_ATTR_MTU"},
}


def field_for(db: str, field: str) -> str:
    return FIELD_ALIASES.get(field, {}).get(db, field)

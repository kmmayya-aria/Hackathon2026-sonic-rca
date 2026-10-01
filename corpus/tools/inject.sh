#!/usr/bin/env bash
# Fault-injection + capture driver, run ON the DUT (never by sonic-rca).
# Usage: sudo ./inject.sh <scenario-id> <out-dir>
# Injects the fault, waits for it to become visible, captures
# `show techsupport`, and writes the sealed ground_truth.yaml next to it.
# Restore between scenarios: sudo config reload -y <baseline config_db.json>.
#
# Validated on a SONiC main-derivative image (FRR 10.5, frrcfgd mode, vslib),
# DUT = leaf0 of a 1-spine/2-leaf topology. Supervisor program names match
# community 202605. The image defaults to alias interface naming, hence the
# SONIC_CLI_IFACE_MODE export; routes/BGP are driven through CONFIG_DB
# (frrcfgd), so they persist in the dump like the rest of the intent.
set -euo pipefail
SC=${1:?scenario id}; OUT=${2:?output dir}; mkdir -p "$OUT/$SC"
export SONIC_CLI_IFACE_MODE=default
FREE_PORT=${FREE_PORT:-Ethernet33}     # admin-up, no IP, no VLAN, no neighbor
NH=${NH:-10.0.0.1}                     # resolvable nexthop (BGP peer)
PEER=${PEER:-10.0.0.1}                 # the real (Established) BGP peer
CFG="sonic-db-cli CONFIG_DB"; ASIC="sonic-db-cli ASIC_DB"

gt() {  # stage, root cause, injected object
    printf 'stage: %s\nroot_cause: %s\nobject: %s\n' "$1" "$2" "$3" \
        > "$OUT/$SC/ground_truth.yaml"
}
wait_for() {  # <seconds> <cmd...>: poll until cmd succeeds
    local t=$1; shift
    for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
    echo "WARN: fault not visible after ${t}s: $*" >&2; return 1
}

case "$SC" in
  s01_port_admin_mismatch)
    docker exec swss supervisorctl stop portmgrd
    config interface shutdown "$FREE_PORT"        # CONFIG intent changes; APPL stale
    gt "portmgrd" "portmgrd stopped; CONFIG_DB admin_status=down never reaches APPL_DB PORT_TABLE" "PORT|$FREE_PORT";;
  s02_vlan_member_stalled)
    docker exec swss supervisorctl stop vlanmgrd
    config vlan member add -u 100 "$FREE_PORT"
    gt "vlanmgrd" "vlanmgrd stopped; VLAN_MEMBER in CONFIG_DB never reaches APPL_DB" "VLAN_MEMBER|Vlan100|$FREE_PORT";;
  s03_route_not_programmed)
    docker exec swss supervisorctl stop orchagent
    $CFG hset 'STATIC_ROUTE|default|10.9.0.0/24' nexthop "$NH"
    wait_for 30 sonic-db-cli APPL_DB exists 'ROUTE_TABLE:10.9.0.0/24' || true
    gt "orchagent|syncd" "orchagent stopped; static route reaches APPL_DB ROUTE_TABLE but is never programmed to ASIC_DB" "ROUTE_TABLE:10.9.0.0/24";;
  s04_unresolved_nexthop)
    $CFG hset 'STATIC_ROUTE|default|10.9.1.0/24' nexthop 10.250.250.250
    # FRR (staticd NHT) withholds an unresolvable static route, so it never
    # reaches APPL_DB/neighorch (real capture s04)
    gt "staticd" "static route nexthop unresolvable (no neighbor); staticd withholds the route from the RIB" "STATIC_ROUTE|default|10.9.1.0/24";;
  s05_swss_down)
    systemctl stop swss
    gt "swss" "swss service stopped" "swss.service";;
  s06_asic_db_drift)
    KEY=$($ASIC keys 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*"172.20.2.0/24"*' | head -1)
    [ -n "$KEY" ] || { echo "route 172.20.2.0/24 not in ASIC_DB" >&2; exit 3; }
    $ASIC del "$KEY"
    gt "reality-drift" "ASIC_DB route entry deleted out-of-band (orchagent/syncd never asked)" "ROUTE_TABLE:172.20.2.0/24";;
  s07_bgp_peer_asn)
    $CFG hset "BGP_NEIGHBOR|default|$PEER" asn 64999
    wait_for 150 sh -c "vtysh -c 'show bgp neighbors $PEER' | grep -q 'Bad Peer AS'" || true
    gt "bgp/frr" "peer ASN misconfigured (64999, peer is 65200); OPEN rejected, session not Established" "BGP_NEIGHBOR|default|$PEER";;
  s08_intf_ip_overlap)
    config interface ip add Ethernet9 10.0.0.0/31 || true   # overlaps existing
    # intfmgrd publishes it to APPL_DB; orchagent (intfsorch) rejects the
    # overlap (real capture s08)
    gt "orchagent" "overlapping interface subnet rejected by orchagent (intfsorch)" "INTERFACE|Ethernet9|10.0.0.0/31";;
  s09_mtu_not_propagated)
    docker exec swss supervisorctl stop portmgrd
    config interface mtu "$FREE_PORT" 1500
    gt "portmgrd|portsorch" "MTU intent not propagated past CONFIG_DB" "PORT|$FREE_PORT";;
  s10_acl_not_programmed)
    config acl add table RCA_T L3 -p "$FREE_PORT" || true
    # rule with a match unsupported on vs — accepted at CONFIG, dropped by aclorch
    $CFG hset 'ACL_RULE|RCA_T|R1' PRIORITY 100 PACKET_ACTION FORWARD DUMMY_MATCH 1
    gt "aclorch" "ACL rule accepted at CONFIG_DB, never programmed to ASIC_DB" "ACL_RULE|RCA_T|R1";;
  s11_fpmsyncd_stalled)
    # Needs NEW prefixes after fpmsyncd stops: a DUT static route here; the
    # peer may additionally advertise new prefixes (operator step on the peer).
    docker exec bgp supervisorctl stop fpmsyncd || true   # may be pre-stopped
    $CFG hset 'STATIC_ROUTE|default|10.9.2.0/24' nexthop "$NH"
    wait_for 30 sh -c "vtysh -c 'show ip route 10.9.2.0/24' | grep -q 'S>'" || true
    gt "zebra/fpmsyncd" "fpmsyncd stopped; new FRR RIB routes never reach APPL_DB ROUTE_TABLE" "ROUTE_TABLE:10.9.2.0/24";;
  s12_fdb_not_programmed)
    MAC=${MAC:-00:AA:BB:00:03:01}
    KEY=$($ASIC keys "ASIC_STATE:SAI_OBJECT_TYPE_FDB_ENTRY:*\"$MAC\"*" | head -1)
    [ -n "$KEY" ] || { echo "FDB $MAC not in ASIC_DB (aged out?)" >&2; exit 3; }
    $ASIC del "$KEY"
    gt "reality-drift" "ASIC_DB FDB entry deleted out-of-band; STATE_DB still has the learned MAC" "FDB_TABLE|Vlan100:${MAC,,}";;
  *) echo "unknown scenario $SC" >&2; exit 2;;
esac

sleep "${SETTLE:-25}"                             # convergence window
rm -rf /var/dump/sonic_dump_* 2>/dev/null || true
show techsupport --silent -g 15 >/dev/null 2>&1 || generate_dump -v
# generate_dump flattens /var/log by basename; on the validation image an empty
# /var/log/rotate/disk/syslog clobbers /var/log/syslog, so snapshot it too.
gzip -c /var/log/syslog > "$OUT/$SC/syslog.live.gz" 2>/dev/null || true
TB=$(ls -t /var/dump/sonic_dump_*.tar.gz | head -1)
cp "$TB" "$OUT/$SC/techsupport.tar.gz"
echo "captured $OUT/$SC/techsupport.tar.gz"

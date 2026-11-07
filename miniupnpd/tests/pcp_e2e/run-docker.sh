#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
DIR=$ROOT/miniupnpd/tests/pcp_e2e
DOCKER=${DOCKER:-docker}
SUFFIX=$$
KEEP=${PCP_E2E_KEEP:-0}
ARTIFACTS=${PCP_E2E_ARTIFACT_DIR:-$ROOT/.tmp/pcp-e2e}
STATUS_FILE=${E2E_STATUS_FILE:-$DIR/status.md}
E2E_PLATFORM=linux
RUN_ID=$(date -u +%Y-%m-%dT%H-%M-%SZ)
case "$ARTIFACTS" in /*) ;; *) ARTIFACTS=$ROOT/$ARTIFACTS ;; esac
STATUS=0
EXECUTED=0
# The router runs with enable_upnp=yes, so the UPnP section runs too (PCP_E2E_UPNP=0 leaves it out).
E2E_UPNP=${PCP_E2E_UPNP:-1}
[ "$E2E_UPNP" = 1 ] || E2E_UPNP=

. "$ROOT/miniupnpd/tests/common/e2e_lib.sh"
e2e_timestamp_output "$@"
e2e_parse_args "$@"
e2e_self_test

# PCP_E2E_SLOT=N picks a slot of e2e_address_plan; by default the first free one
reserve_slot e2e_address_plan "${PCP_E2E_SLOT:-}"
echo "Fixture slot $SLOT: LAN $LAN4.0/24 ${LAN6}/64, WAN $WAN4.0/24 ${WAN6}/64"
LAN=pcp-e2e-lan-$SLOT
WAN=pcp-e2e-wan-$SLOT
ROUTER=pcp-e2e-router-$SLOT
ALLOW=pcp-e2e-allow-$SLOT
RUNNER=pcp-e2e-runner-$SLOT

RUN_DIR=$ARTIFACTS/$RUN_ID-slot$SLOT
mkdir -p "$RUN_DIR"
export COMPOSE_PROFILES=agents
[ -z "$E2E_UPNP" ] || export PCP_TEST_ENABLE_UPNP=yes

cleanup() {
  result=$?
  trap - EXIT INT TERM
  set_nat66 0 >/dev/null 2>&1 || true
  if [ "$KEEP" != 1 ]; then
    "$DOCKER" rm -f "$RUNNER" >/dev/null 2>&1 || true
    e2e_compose down --timeout 1 >/dev/null 2>&1 || true
  else
    echo "Retaining fixture: remove it with: SLOT=$SLOT ... docker compose -p pcp-e2e-$SLOT down" >&2
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

e2e_tools_image
e2e_build_daemon
e2e_compose up --detach --quiet-pull >/dev/null
"$DOCKER" exec "$ROUTER" ip -6 address replace fd42:1::1/64 dev eth0 nodad

e2e_wait_agent "$ALLOW"
sleep 2
e2e_router_policy "$ROUTER"
RESULTS_FILE=$RUN_DIR/results.tsv
: > "$RESULTS_FILE"
"$DOCKER" logs --timestamps "$ROUTER" > "$RUN_DIR/daemon-start.log" 2>&1 || true
echo "Daemon startup log: $RUN_DIR/daemon-start.log"

snapshot_daemon_state() {
  state_file=$1
  {
    echo "Snapshot time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "$DOCKER" exec "$ROUTER" sh -c '
      echo "=== miniupnpd process ==="
      cat /proc/1/status
      tr "\\000" " " </proc/1/cmdline
      echo
      echo "=== miniupnpd configuration ==="
      cat /etc/miniupnpd.conf
      echo "=== interface addresses ==="
      ip -details address
      echo "=== IPv4 routes ==="
      ip -4 route show table all
      echo "=== IPv6 routes ==="
      ip -6 route show table all
      echo "=== nftables ruleset ==="
      nft -a list ruleset
      echo "=== daemon state files ==="
      for state_file in /var/lib/miniupnpd/*; do
        [ -f "$state_file" ] || continue
        echo "--- $state_file ---"
        cat "$state_file"
      done
      echo "=== lease files ==="
      for lease_file in /var/lib/miniupnpd/*.leases /var/lib/miniupnpd/*.leases6 /var/log/upnp.leases; do
        [ -f "$lease_file" ] || continue
        echo "--- $lease_file ---"
        cat "$lease_file"
      done
    '
  } >"$state_file" 2>&1 || true
}

lose_rules() {
  "$DOCKER" exec "$ROUTER" sh -c '
    chains="miniupnpd prerouting_miniupnpd postrouting_miniupnpd"
    count() {
      for chain in $chains; do nft -a list chain inet filter "$chain"; done 2>/dev/null |
        grep " # handle " | grep -vc "{"
    }
    before=$(count)
    for chain in $chains; do nft flush chain inet filter "$chain"; done
    echo "$before $(count)"
  '
}

set_nat66() {
  enabled=$1
  nat66_handle=$(
    "$DOCKER" exec "$ROUTER" nft -a list chain inet filter postrouting 2>/dev/null |
      awk -v marker="pcp-e2e-nat66-$SUFFIX" 'index($0, marker) {
        for (i = 1; i < NF; i++) if ($i == "handle") print $(i + 1)
      }'
  )
  if [ "$enabled" = 1 ]; then
    [ -n "$nat66_handle" ] && return 0
    "$DOCKER" exec "$ROUTER" nft add rule inet filter postrouting \
      meta nfproto ipv6 oifname wan0 masquerade comment "pcp-e2e-nat66-$SUFFIX"
  elif [ -n "$nat66_handle" ]; then
    "$DOCKER" exec "$ROUTER" nft delete rule inet filter postrouting handle "$nat66_handle"
    if "$DOCKER" exec "$ROUTER" nft -a list chain inet filter postrouting 2>/dev/null |
      grep -Fq "pcp-e2e-nat66-$SUFFIX"; then
      echo "failed to remove section NAT66 rule" >&2
      return 1
    fi
  fi
}

start_packet_capture() {
  pcap_file=$1
  capture_pidfile=/tmp/pcp-e2e-capture-$SUFFIX.pid
  "$DOCKER" exec "$ROUTER" sh -c '
    pcap_file=$1
    pidfile=$2
    rm -f "$pcap_file" "$pcap_file.log"
    tcpdump -U -n -i any -s 0 -w "$pcap_file" >"$pcap_file.log" 2>&1 &
    echo $! >"$pidfile"
  ' sh "$pcap_file" "$capture_pidfile"
  capture_ready=0
  for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    if "$DOCKER" exec "$ROUTER" sh -c \
      'pid=$(cat "$1" 2>/dev/null) && [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && [ -s "$2" ]' \
      sh "$capture_pidfile" "$pcap_file" >/dev/null 2>&1; then
      capture_ready=1
      break
    fi
    sleep 0.1
  done
  [ "$capture_ready" = 1 ] || {
    echo "tcpdump failed to start; see $pcap_file.log" >&2
    return 1
  }
}

stop_packet_capture() {
  pcap_file=$1
  capture_pidfile=/tmp/pcp-e2e-capture-$SUFFIX.pid
  "$DOCKER" exec "$ROUTER" sh -c '
    pidfile=$1
    pcap_file=$2
    pid=$(cat "$pidfile" 2>/dev/null) || exit 0
    kill -INT "$pid" 2>/dev/null || true
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
      grep -q "packets captured" "$pcap_file.log" 2>/dev/null && break
      sleep 0.1
    done
    rm -f "$pidfile"
  ' sh "$capture_pidfile" "$pcap_file" >/dev/null 2>&1 || true
}

run_family() {
  family=$1
  if [ "$family" = ipv4 ]; then
    lanip=$LAN4.2
    router=$LAN4.1
    external=$WAN4.1
    unowned_ip=$WAN4.77
    allow_ip=$WAN4.2; deny_ip=$WAN4.130; third_ip=$WAN4.200
  else
    lanip=${LAN6}2
    router=${LAN6}1
    external=${WAN6}1
    unowned_ip=${WAN6}77
    allow_ip=${WAN6}2; deny_ip=${WAN6}130; third_ip=${WAN6}200
  fi
  # The control channel uses LAN IPv4; each agent still binds test traffic
  # to its independently assigned WAN address.
  allow_url=http://$LAN4.12:18080
  deny_url=http://$LAN4.13:18080
  third_url=http://$LAN4.14:18080

  family_dir=$RUN_DIR/$family
  mkdir -p "$family_dir"
  case_rows=$(e2e_case_rows "$family")
  active_section=
  active_section_nat66=0
  while IFS="$(printf '\t')" read -r section_name case_name section_nat66; do
    [ -n "$case_name" ] || continue
    e2e_case_selected "$case_name" || continue
    if [ "$section_name" != "$active_section" ]; then
      if [ "$active_section_nat66" = 1 ]; then
        set_nat66 0
      fi
      active_section=$section_name
      active_section_nat66=0
      if [ "$section_nat66" = true ]; then
        set_nat66 1
        active_section_nat66=1
      fi
    fi
    case_client=$lanip
    case_router=$router
    if [ "$family" = ipv6 ] && [ "$section_nat66" = true ]; then
    case_client=fd42:1::2
    case_router=fd42:1::1
      runner_ula=add
    else
      runner_ula=skip
    fi
    case_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    EXECUTED=$((EXECUTED + 1))
    case_dir=$family_dir/$section_name/$case_name
    mkdir -p "$case_dir"
    snapshot_daemon_state "$case_dir/daemon-before.txt"
    start_packet_capture "/pcp-e2e-artifacts/$family/$section_name/$case_name/packet-capture.pcap"
    e2e_start_runner
    e2e_wait_runner
    stop_packet_capture "/pcp-e2e-artifacts/$family/$section_name/$case_name/packet-capture.pcap"
    snapshot_daemon_state "$case_dir/daemon-after.txt"
    case_artifacts="$family/$section_name/$case_name/packet-capture.pcap; $family/$section_name/$case_name/packet-capture.pcap.log; $family/$section_name/$case_name/daemon-before.txt; $family/$section_name/$case_name/daemon-expect-*.txt; $family/$section_name/$case_name/daemon-after.txt; $family/$section_name/$case_name/runner.log; $family/$section_name/$case_name/daemon.log"
    e2e_record_result "$case_artifacts"
    "$DOCKER" logs --timestamps --since "$case_start" "$ROUTER" \
      > "$case_dir/daemon.log" 2>&1 || true
  done <<EOF
$case_rows
EOF
  if [ "$active_section_nat66" = 1 ]; then
    set_nat66 0
  fi
}

run_family ipv4
run_family ipv6
"$DOCKER" logs --timestamps "$ROUTER" > "$RUN_DIR/daemon-final.log" 2>&1 || true
e2e_write_status "${RUN_DIR#"$ROOT"/} (daemon startup/final logs and per-case captures/snapshots)" \
  "router=Linux nftables"
echo "Daemon logs: $RUN_DIR (startup, per-case snapshots, final)"
e2e_result "$STATUS"
exit "$STATUS"

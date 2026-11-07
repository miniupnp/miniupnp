#!/bin/sh
# Linux (Docker) driver of the daemon_options suite: one fresh router daemon per configuration of
# daemon-options-cases.yaml, then the runner from the LAN and from the WAN side, per address family.
#
#   miniupnpd/tests/daemon_options/run-docker.sh [--case NAME ...]
#
# The topology is the e2e one (common/compose.yaml, no traffic agents): a LAN and a WAN bridge, the
# router on both (common/docker image and entrypoint, real WAN), the runner as a LAN client or as a
# host on the WAN link. A configuration's lines replace the fixture's default line of the same option
# (PCP_TEST_EXTRA_CONF with PCP_TEST_CONF_REPLACE=1, see common/docker/entrypoint.sh).
# PCP_TEST_SLOT=N picks a slot; by default the first free one.
#
# Writes status.md beside this script (the linux column); the raw results go to
# .tmp/tests/daemon_options/status-data.json and the daemon logs to .tmp/daemon-options/<run>/.
# DAEMON_OPTIONS_KEEP=1 keeps the containers and networks; PCP_TEST_SELF_TEST=0 skips the self-tests.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
DIR=$ROOT/miniupnpd/tests/daemon_options
DOCKER=${DOCKER:-docker}
KEEP=${DAEMON_OPTIONS_KEEP:-0}
DATA_DIR=$ROOT/.tmp/tests/daemon_options
RUN_DIR=$ROOT/.tmp/daemon-options/$(date -u +%Y-%m-%dT%H-%M-%SZ)
STATUS=0

. "$ROOT/miniupnpd/tests/common/e2e_lib.sh"
e2e_timestamp_output "$@"
e2e_parse_args "$@"
e2e_self_test
reserve_slot e2e_address_plan "${PCP_TEST_SLOT:-}"
echo "Fixture slot $SLOT: LAN $LAN4.0/24 ${LAN6}/64, WAN $WAN4.0/24 ${WAN6}/64"
LAN=pcp-e2e-lan-$SLOT
WAN=pcp-e2e-wan-$SLOT
ROUTER=pcp-e2e-router-$SLOT
STUN=daemon-options-stun-$SLOT
NEIGHBOUR=daemon-options-neighbour-$SLOT
export PCP_TEST_CONF_REPLACE=1
ROUTER_LAN4=$LAN4.1 ROUTER_LAN6=${LAN6}1 ROUTER_WAN4=$WAN4.1 ROUTER_WAN6=${WAN6}1
CALL_DIR=$DATA_DIR/router-calls-$SLOT
CALL_LOOP=

cleanup() {
  result=$?
  trap - EXIT INT TERM
  [ -z "$CALL_LOOP" ] || kill "$CALL_LOOP" 2>/dev/null || true
  rm -rf "$CALL_DIR"
  if [ "$KEEP" = 1 ]; then
    echo "Keeping the fixture: $ROUTER $LAN $WAN" >&2
  else
    "$DOCKER" rm -f "$STUN" "$NEIGHBOUR" >/dev/null 2>&1 || true
    e2e_compose down --timeout 1 >/dev/null 2>&1 || true
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$DATA_DIR" "$RUN_DIR"
e2e_tools_image "libssl-dev openssl"
e2e_build_daemon "--igd2 --vendorcfg --https"
e2e_compose up --no-start --quiet-pull router >/dev/null

# the WAN STUN server, and a second LAN host that routes through the router and serves HTTP
"$DOCKER" run -d --name "$STUN" --network "$WAN" --ip "$WAN4.5" --ip6 "${WAN6}5" --volume "$DIR:/suite:ro" \
  --entrypoint python3 "$IMAGE" /suite/stun_server.py >/dev/null
"$DOCKER" run -d --name "$NEIGHBOUR" --network "$LAN" --ip "$LAN4.3" --ip6 "${LAN6}3" --cap-add NET_ADMIN \
  --entrypoint sh "$IMAGE" -c "ip route replace default via $ROUTER_LAN4; \
    mkdir -p /srv && echo neighbour-served > /srv/index.html && cd /srv && exec python3 -m http.server 45300" >/dev/null

daemon_listening() {
  "$DOCKER" logs "$ROUTER" 2>&1 | grep -Ec 'Listening for NAT-PMP|HTTP listening on port' || true
}

# restart_router: the same container, so the lease file stays; ready at its next listening line
restart_router() {
  before=$(daemon_listening)
  "$DOCKER" restart -t 2 "$ROUTER" >/dev/null
  for _attempt in $(seq 1 100); do
    [ "$(daemon_listening)" -le "$before" ] || { sleep 1; echo restarted; return 0; }
    sleep 0.2
  done
  echo "restart timed out"
}

# a TCP connection from a host on the WAN to the router's WAN address
wan_probe() {
  "$DOCKER" run --rm --network "$WAN" --ip "$WAN4.6" --ip6 "${WAN6}6" --entrypoint python3 "$IMAGE" -c "
import urllib.request
try:
    print(urllib.request.urlopen('http://$ROUTER_WAN4:$1/', timeout=5).read().decode())
except OSError as error:
    print('no connection', error)"
}

# router_call COMMAND: the commands of lib_test.router_call
router_call() {
  case $1 in
    ruleset) "$DOCKER" exec "$ROUTER" nft list ruleset ;;
    log) "$DOCKER" logs "$ROUTER" ;;
    cat:*) "$DOCKER" exec "$ROUTER" cat "${1#cat:}" ;;
    restart) restart_router ;;
    # a reload of the firewall: the chains stay, their rules are gone, and the daemon is not told
    firewall-flush)
      "$DOCKER" exec "$ROUTER" sh -c "nft list ruleset | awk '/^table/ { t = \$2 \" \" \$3 } /^[[:space:]]chain (miniupnpd|.*_miniupnpd|pcp-filter)/ { print t, \$2 }' |
        while read -r f t c; do nft flush chain \$f \$t \$c; done" && echo flushed ;;
    wan-probe:*) wan_probe "${1#wan-probe:}" ;;
    # the WAN of the plan is public: this one is reserved, and SIGUSR1 has the daemon look at it again
    wan-reserved)
      "$DOCKER" exec "$ROUTER" sh -c "ip address add 198.51.100.1/24 dev wan0 && ip address del $WAN4.1/24 dev wan0 && kill -USR1 1" &&
        sleep 1 && echo changed ;;
    *) echo "unknown router command: $1" ;;
  esac
}

mkdir -p "$CALL_DIR"
chmod 700 "$CALL_DIR"
(
  while :; do
    e2e_serve_router_calls "$CALL_DIR" || sleep 0.1
  done
) &
CALL_LOOP=$!

# start_router RUN-NUMBER CONFIG-LINE...: a fresh router daemon with these configuration lines,
# ready when it listens (at least one protocol is on, or miniupnpd exits).
start_router() {
  router_log=$RUN_DIR/daemon-$1.log
  shift
  export PCP_TEST_EXTRA_CONF
  PCP_TEST_EXTRA_CONF=$(printf '%s\n' "$@" | tr + ' ' | sed -e "s/@WAN4@/$WAN4/g" -e "s/@LAN4@/$LAN4/g" -e "s/@LAN6@/$LAN6/g")
  e2e_compose up --detach --force-recreate --no-deps router >/dev/null 2>&1 ||
    { echo "FAIL: the router container did not start" >&2; exit 1; }
  for _attempt in $(seq 1 50); do
    if "$DOCKER" logs "$ROUTER" 2>&1 | grep -Eq 'Listening for NAT-PMP|HTTP listening on port'; then
      sleep 1     # the other protocol's sockets open right after
      "$DOCKER" exec "$ROUTER" cat /etc/miniupnpd.conf > "$router_log.conf" 2>&1 || true
      return 0
    fi
    [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$ROUTER" 2>/dev/null)" = true ] || break
    sleep 0.2
  done
  "$DOCKER" logs "$ROUTER" > "$router_log" 2>&1 || true
  echo "FAIL: the daemon with [$*] did not start listening; see $router_log" >&2
  return 1
}

# run_cases SIDE FAMILY CONFIG-LINE...: the runner from the LAN client or a host on the WAN link
run_cases() {
  side=$1 family=$2
  down=$3
  shift 3
  if [ "$side" = lan ]; then
    network=$LAN source4=$LAN4.2 source6=${LAN6}2 router4=$ROUTER_LAN4 router6=$ROUTER_LAN6
  else
    network=$WAN source4=$WAN4.2 source6=${WAN6}2 router4=$ROUTER_WAN4 router6=$ROUTER_WAN6
  fi
  host=$router4
  [ "$family" = ipv4 ] || host=$router6
  for line in "$@"; do set -- "$@" --config "$line"; shift; done
  for selected in $SELECTED_CASES; do set -- "$@" --case "$selected"; done
  [ "$down" = 0 ] || set -- "$@" --daemon-down
  # the host's paths, so that the report names the data file relative to the repository
  "$DOCKER" run --rm --network "$network" --ip "$source4" --ip6 "$source6" \
    --user "$(id -u):$(id -g)" --env PYTHONDONTWRITEBYTECODE=1 \
    --volume "$ROOT/miniupnpd/tests:$ROOT/miniupnpd/tests:ro" \
    --volume "$ROOT/miniupnpd/options.c:$ROOT/miniupnpd/options.c:ro" \
    --volume "$DIR:$DIR:rw" --volume "$DATA_DIR:$DATA_DIR:rw" \
    --entrypoint python3 "$IMAGE" "$DIR/run_daemon_options_cases.py" \
    --router-call-dir "$CALL_DIR" --host "$host" --family "$family" --side "$side" --platform linux \
    --status-file "$DIR/status.md" --status-data-file "$DATA_DIR/status-data.json" \
    --run-info "daemon=${DAEMON_OPTIONS_DAEMON:-$(git -C "$ROOT" branch --show-current 2>/dev/null || echo unknown)}" \
    --run-info "router=Linux nftables (Docker)" "$@"
}

# the runs: SIDE FAMILY CONFIG-LINE..., one daemon per configuration (consecutive lines)
case_args=
for selected in $SELECTED_CASES; do case_args="$case_args --case $selected"; done
# shellcheck disable=SC2086
runs=$(python3 "$DIR/run_daemon_options_cases.py" --list-runs $case_args)
[ -n "$runs" ] || { echo "No cases matched the selection." >&2; exit 1; }
active=-
number=0
while read -r side family config; do
  if [ "$config" != "$active" ]; then
    [ "$number" = 0 ] || "$DOCKER" logs "$ROUTER" > "$RUN_DIR/daemon-$number.log" 2>&1 || true
    number=$((number + 1))
    active=$config
    echo "=== daemon $number: ${config:-fixture defaults}"
    router_up=1
    # shellcheck disable=SC2086
    start_router "$number" $config || router_up=0
  fi
  echo "--- from $side, $family"
  # shellcheck disable=SC2086
  run_cases "$side" "$family" "$((1 - router_up))" $config || STATUS=1
done <<EOF
$runs
EOF
"$DOCKER" logs "$ROUTER" > "$RUN_DIR/daemon-$number.log" 2>&1 || true
echo "Status report: $DIR/status.md; daemon logs: $RUN_DIR"
e2e_result "$STATUS"
exit "$STATUS"

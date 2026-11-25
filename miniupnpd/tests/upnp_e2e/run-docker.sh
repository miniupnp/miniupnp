#!/bin/sh
# The UPnP end-to-end suite on Linux (Docker): the pcp_e2e topology (a LAN with the runner, a router
# running miniupnpd in UPnP mode with a real WAN, three WAN peers with traffic agents), once per build
# (igd2: --igd2, igd1: the default build). Each case runs in its own runner container; the results go
# into status.md (column linux-igd2), the raw data and the logs into .tmp/tests/upnp_e2e/.
#
#   run-docker.sh [--case NAME]...        UPNP_E2E_BUILDS="igd2" (default) selects the builds; "igd1 igd2" adds IGDv1
#
# The fixture is common/compose.yaml. UPNP_E2E_SLOT=N picks a slot of e2e_address_plan; by default the
# first free one, so it runs beside the other suites.
# A case with requires: [restart] asks for a restart of the router container after its first request.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
DIR=$ROOT/miniupnpd/tests/upnp_e2e
DOCKER=${DOCKER:-docker}
KEEP=${UPNP_E2E_KEEP:-0}
BUILDS=${UPNP_E2E_BUILDS:-igd2}
DATA_DIR=$ROOT/.tmp/tests/upnp_e2e
STATUS_FILE=${UPNP_E2E_STATUS_FILE:-$DIR/status.md}
E2E_STATUS_DATA_FILE=${UPNP_E2E_STATUS_DATA_FILE:-$DATA_DIR/status-data.json}
RUN_ID=$(date -u +%Y-%m-%dT%H-%M-%SZ)
STATUS=0
EXECUTED=0

. "$ROOT/miniupnpd/tests/common/e2e_lib.sh"
e2e_timestamp_output "$@"
e2e_parse_args "$@"
e2e_self_test

E2E_RUNNER=run_upnp_e2e_cases.py
reserve_slot e2e_address_plan "${UPNP_E2E_SLOT:-}"
echo "Fixture slot $SLOT: LAN $LAN4.0/24 ${LAN6}/64, WAN $WAN4.0/24 ${WAN6}/64"
LAN=pcp-e2e-lan-$SLOT
ROUTER=pcp-e2e-router-$SLOT
ALLOW=pcp-e2e-allow-$SLOT
RUNNER=pcp-e2e-runner-$SLOT
e2e_tools_image
RUN_ROOT=$DATA_DIR/runs/$RUN_ID
RUN_DIR=$RUN_ROOT
export COMPOSE_PROFILES=agents PCP_TEST_ENABLE_UPNP=yes

cleanup_fixture() {
  "$DOCKER" rm -f "$RUNNER" >/dev/null 2>&1 || true
  e2e_compose down --timeout 1 >/dev/null 2>&1 || true
}
cleanup() {
  result=$?
  trap - EXIT INT TERM
  if [ "$KEEP" != 1 ]; then cleanup_fixture; else echo "Keeping the fixture ($ROUTER ...)" >&2; fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# snapshot_daemon_state FILE (the runner asks for it after each request): the ruleset and the lease file.
snapshot_daemon_state() {
  "$DOCKER" exec "$ROUTER" sh -c 'nft list ruleset; echo "=== lease file ==="; cat /var/lib/miniupnpd/miniupnpd.leases 2>/dev/null' \
    >"$1" 2>&1 || true
}

# restart_daemon (router_call restart, which a requires: [restart] case sends after its first request):
# the same container, so the lease file stays; its entrypoint rebuilds the ruleset.
restart_daemon() {
  "$DOCKER" restart "$ROUTER" >/dev/null
  e2e_wait_upnp "$ROUTER" "$LAN4.1"
  e2e_router_policy "$ROUTER"
}

run_build() {
  E2E_RUNNER_ARGS="--build $build"
  E2E_PLATFORM=linux-$build
  RUN_DIR=$RUN_ROOT/$build
  RESULTS_FILE=$RUN_DIR/results.tsv
  mkdir -p "$RUN_DIR"
  : > "$RESULTS_FILE"
  flags=
  [ "$build" = igd2 ] && flags=--igd2
  e2e_build_daemon "$flags"
  e2e_compose up --detach --quiet-pull >/dev/null
  e2e_wait_agent "$ALLOW"
  e2e_wait_upnp "$ROUTER" "$LAN4.1"
  e2e_router_policy "$ROUTER"
  echo "=== $build ==="
  for family in ipv4 ipv6; do
    if [ "$family" = ipv4 ]; then
      lanip=$LAN4.2 router=$LAN4.1 external=$WAN4.1
      allow_ip=$WAN4.2 deny_ip=$WAN4.130 third_ip=$WAN4.200
    else
      lanip=${LAN6}2 router=${LAN6}1 external=${WAN6}1
      allow_ip=${WAN6}2 deny_ip=${WAN6}130 third_ip=${WAN6}200
    fi
    allow_url=http://$LAN4.12:18080 deny_url=http://$LAN4.13:18080 third_url=http://$LAN4.14:18080 unowned_ip=$external
    rows=$(e2e_case_rows "$family")
    while IFS="$(printf '\t')" read -r section_name case_name _flag; do
      [ -n "$case_name" ] || continue
      e2e_case_selected "$case_name" || continue
      EXECUTED=$((EXECUTED + 1))
      case_client=$lanip case_router=$router runner_ula=skip
      case_dir=$RUN_DIR/$family/$section_name/$case_name
      mkdir -p "$case_dir"
      case_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
      e2e_start_runner
      e2e_wait_runner
      "$DOCKER" logs --timestamps --since "$case_start" "$ROUTER" > "$case_dir/daemon.log" 2>&1 || true
      e2e_record_result "$family/$section_name/$case_name/runner.log; daemon.log; daemon-expect-*.txt"
    done <<EOF
$rows
EOF
  done
  "$DOCKER" logs --timestamps "$ROUTER" > "$RUN_DIR/daemon-final.log" 2>&1 || true
  e2e_write_report "${RUN_DIR#"$ROOT"/}" "router=Linux nftables"
  cat "$RESULTS_FILE" >> "$RUN_ROOT/results.tsv"
  cleanup_fixture
}

mkdir -p "$RUN_ROOT"
: > "$RUN_ROOT/results.tsv"
for build in $BUILDS; do
  run_build
done
# over the builds: a case of one build is not missing from the other
e2e_check_selection "$RUN_ROOT/results.tsv"
echo "Status report: $STATUS_FILE (raw data: $E2E_STATUS_DATA_FILE; logs: $RUN_ROOT)"
e2e_result "$STATUS"
exit "$STATUS"

#!/bin/sh
# The UPnP wire suite on Linux (Docker): builds miniupnpd (igd1: the default build, igd2: --igd2, and each with --strict), starts
# it in UPnP mode (PCP_TEST_ENABLE_UPNP=yes) on a LAN network, and runs run_upnp_wire_cases.py in a LAN client
# container for IPv4 and IPv6. The results go into status.md (columns linux-igd1, linux-igd2); the raw
# data, the logs and the daemon's state files of each run into .tmp/tests/upnp_wire/ of the repository.
#
#   run-docker.sh [igd1|igd2|all] [--case NAME]...
#
# A case that needs a daemon restart asks this script for it (router_call restart). UPNP_WIRE_SLOT=N picks a
# slot of e2e_address_plan for the LAN; by default the first free one, so runs go side by side.
# UPNP_WIRE_KEEP=1 keeps the containers; PCP_TEST_SELF_TEST=0 skips the self-tests.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
DIR=$ROOT/miniupnpd/tests/upnp_wire
DOCKER=${DOCKER:-docker}
KEEP=${UPNP_WIRE_KEEP:-0}
DATA_DIR=$ROOT/.tmp/tests/upnp_wire
STATUS_FILE=${UPNP_WIRE_STATUS_FILE:-$DIR/status.md}
E2E_STATUS_DATA_FILE=${UPNP_WIRE_STATUS_DATA_FILE:-$DATA_DIR/status-data.json}
RUN_ID=$(date -u +%Y-%m-%dT%H-%M-%SZ)
RUN_ROOT=$DATA_DIR/runs/$RUN_ID
STATUS=0
EXECUTED=0

. "$ROOT/miniupnpd/tests/common/e2e_lib.sh"
e2e_timestamp_output "$@"

BUILDS=
args=$#
while [ "$args" -gt 0 ]; do
  argument=$1; shift; args=$((args - 1))
  case "$argument" in
    igd1|igd2|igd1-strict|igd2-strict) BUILDS="$BUILDS $argument" ;;
    all) BUILDS="igd1 igd2 igd1-strict igd2-strict" ;;
    *) set -- "$@" "$argument" ;;
  esac
done
e2e_parse_args "$@"
[ -n "$BUILDS" ] || BUILDS="igd1 igd2 igd1-strict igd2-strict"
command -v "$DOCKER" >/dev/null 2>&1 || { echo "Docker is required." >&2; exit 2; }
e2e_self_test
E2E_RUNNER=run_upnp_wire_cases.py
mkdir -p "$RUN_ROOT"
: > "$RUN_ROOT/results.tsv"

reserve_slot e2e_address_plan "${UPNP_WIRE_SLOT:-}"
echo "Fixture slot $SLOT: LAN $LAN4.0/24 ${LAN6}/64"
LAN=upnp-wire-lan-$SLOT
ROUTER=upnp-wire-router-$SLOT
RUNNER=upnp-wire-runner-$SLOT
UUID=$(sed -n 's/^uuid: //p' "$DIR/upnp-wire-cases.yaml")

cleanup() {
  result=$?
  trap - EXIT INT TERM
  if [ "$KEEP" != 1 ]; then
    "$DOCKER" rm -f "$RUNNER" "$ROUTER" >/dev/null 2>&1 || true
    "$DOCKER" network rm "$LAN" >/dev/null 2>&1 || true
  else
    echo "Keeping $ROUTER $RUNNER $LAN" >&2
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$DOCKER" network create --driver bridge --ipv6 \
  --subnet "$LAN4.0/24" --gateway "$LAN4.254" \
  --subnet "${LAN6}/64" --gateway "${LAN6}ffff" "$LAN" >/dev/null

# restart_daemon (router_call restart): the same container, so the lease file stays
restart_daemon() {
  "$DOCKER" restart "$ROUTER" >/dev/null
  e2e_wait_upnp "$ROUTER" "$LAN4.1"
}

e2e_tools_image
for build in $BUILDS; do
  flags='' strict=''
  case "$build" in igd2*) flags=--igd2 ;; esac
  case "$build" in *-strict) flags="$flags --strict"; strict=--strict ;; esac
  E2E_RUNNER_ARGS="--build ${build%-strict} $strict"
  E2E_PLATFORM=linux-$build
  RUN_DIR=$RUN_ROOT/$build
  RESULTS_FILE=$RUN_DIR/results.tsv
  mkdir -p "$RUN_DIR/state"
  chmod 777 "$RUN_DIR/state"
  : > "$RESULTS_FILE"
  e2e_build_daemon "$flags"
  "$DOCKER" run -d --name "$ROUTER" --network "$LAN" --ip "$LAN4.1" --ip6 "${LAN6}1" \
    --cap-add NET_ADMIN --cap-add NET_RAW --env PCP_TEST_ENABLE_UPNP=yes --env "PCP_TEST_UPNP_UUID=$UUID" \
    --volume "$RUN_DIR/state:/var/lib/miniupnpd" --volume "$DAEMON_DIR:/opt/miniupnpd:ro" "$IMAGE" >/dev/null
  e2e_wait_upnp "$ROUTER" "$LAN4.1"
  echo "=== $build ==="
  for family in ipv4 ipv6; do
    e2e_run_family "$family" --lease-file /out/state/miniupnpd.leases
  done
  "$DOCKER" logs --timestamps "$ROUTER" > "$RUN_DIR/daemon.log" 2>&1 || true
  "$DOCKER" rm -f "$ROUTER" >/dev/null
  e2e_write_report "${RUN_DIR#"$ROOT"/}" "router=Linux nftables"
  cat "$RESULTS_FILE" >> "$RUN_ROOT/results.tsv"
done
# over the builds: a case of one build is not missing from the other
e2e_check_selection "$RUN_ROOT/results.tsv"
echo "Status report: $STATUS_FILE (raw data: $E2E_STATUS_DATA_FILE; logs: $RUN_ROOT)"
e2e_result "$STATUS"
exit "$STATUS"

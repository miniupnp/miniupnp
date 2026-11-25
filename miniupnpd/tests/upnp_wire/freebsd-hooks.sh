# shellcheck shell=sh disable=SC2034 # sourced by pcp_e2e/run-freebsd.sh, which uses these variables
# The suite hooks of upnp_wire/run-freebsd.sh and run-openbsd.sh: pcp_e2e/run-freebsd.sh sources this
# file after its own functions, so these replace them. Uses the variables of that script. The whole
# corpus of one family runs in one LAN container, both families at once (e2e_run_families); the cases of
# the lease file SKIP (the file is in the VM).
DIR=$ROOT/miniupnpd/tests/upnp_wire
E2E_RUNNER=run_upnp_wire_cases.py
E2E_UPNP=    # the driver sets it for the pcp_e2e runner

# Two phases, as on Docker: every case on igd2, then the strict-path cases on igd2-strict
# (UPNP_WIRE_PHASES, from run-freebsd.sh --base or --strict, keeps one). The fixture starts on the
# build of the first phase (run-freebsd.sh sets its configure options). A later phase with the other
# build configures and builds again (--igd2, with --strict or without) and starts that daemon from a clean
# state. The configure stamp makes this a full build (about 5 s), and the next run's first one too.
E2E_PHASES=$UPNP_WIRE_PHASES
PLATFORM=freebsd; [ "$ROUTER" = openbsd-pf ] && PLATFORM=openbsd
STARTED_PHASE=${E2E_PHASES%% *}
enter_phase() {
  E2E_PLATFORM=$PLATFORM-$1
  E2E_RUNNER_ARGS="--build igd2"
  [ "$1" = igd2 ] || E2E_RUNNER_ARGS="$E2E_RUNNER_ARGS --strict"
  [ "$1" != "$STARTED_PHASE" ] || return 0
  E2E_CONFIGURE_OPTIONS=--igd2; [ "$1" = igd2 ] || E2E_CONFIGURE_OPTIONS="--igd2 --strict"
  RUN_DIR=$RUN_DIR/$1
  mkdir -p "$RUN_DIR"
  echo "=== $1: building and starting the daemon ==="
  build_router
  start_router
  STARTED_PHASE=$1
}

restart_daemon() { vm sh $ROUTER_SCRIPT restart; }

run_families() {
  e2e_run_families
  $SSH "$PRIV cat /tmp/pcp-e2e/miniupnpd.log" >"$RUN_DIR/daemon.log" 2>&1 || true
}

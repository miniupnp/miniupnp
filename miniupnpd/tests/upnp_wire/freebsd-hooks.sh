# shellcheck shell=sh disable=SC2034 # sourced by pcp_e2e/run-freebsd.sh, which uses these variables
# The suite hooks of upnp_wire/run-freebsd.sh: pcp_e2e/run-freebsd.sh sources this file after its own
# functions, so these replace them. Uses the variables of that script. The whole corpus of one family
# runs in one LAN container (e2e_run_family); the cases of the lease file SKIP (the file is in the VM).
DIR=$ROOT/miniupnpd/tests/upnp_wire
E2E_RUNNER=run_upnp_wire_cases.py
E2E_RUNNER_ARGS="--build igd2"
E2E_PLATFORM=freebsd-igd2
E2E_UPNP=    # the driver sets it for the pcp_e2e runner

restart_daemon() { vm sh $ROUTER_SCRIPT restart; }

run_family() {
  e2e_run_family "$1"
  $SSH "$PRIV cat /tmp/pcp-e2e/miniupnpd.log" >"$RUN_DIR/daemon-$1.log" 2>&1 || true
}

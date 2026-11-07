# shellcheck shell=sh disable=SC2034 # sourced by pcp_e2e/run-freebsd.sh, which uses these variables
# The suite hooks of upnp_e2e/run-freebsd.sh: pcp_e2e/run-freebsd.sh sources this file after its own
# functions, so these replace them. Uses the variables of that script. A restart case asks for the
# restart itself (router_call restart, after its first request).
DIR=$ROOT/miniupnpd/tests/upnp_e2e
E2E_RUNNER=run_upnp_e2e_cases.py
E2E_RUNNER_ARGS="--build igd2"
E2E_PLATFORM=freebsd-igd2
E2E_UPNP=    # the driver sets it for the pcp_e2e runner

restart_daemon() { vm sh $ROUTER_SCRIPT restart; }

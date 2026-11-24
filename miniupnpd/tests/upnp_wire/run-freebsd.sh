#!/bin/sh
# upnp_wire with a FreeBSD pf router in QEMU: the fixture of pcp_e2e/run-freebsd.sh (its slots, --reuse,
# up, down, ssh), and a runner in a LAN container. One call runs both builds, as run-docker.sh does: every
# case on igd2, then the strict-path cases on igd2-strict (built in the VM again, with --strict); --base
# runs only igd2, --strict only igd2-strict. The results go into the freebsd-igd2 and freebsd-igd2-strict
# columns of status.md. Options and environment: see pcp_e2e/run-freebsd.sh.
#
#   run-freebsd.sh [--base|--strict] [--slot N] [--case NAME]...
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
phases=
args=$#
while [ "$args" -gt 0 ]; do
  argument=$1; shift; args=$((args - 1))
  case "$argument" in
    --base) phases="$phases igd2" ;;
    --strict) phases="$phases igd2-strict" ;;
    *) set -- "$@" "$argument" ;;
  esac
done
export UPNP_WIRE_PHASES="${phases:- igd2 igd2-strict}"
UPNP_WIRE_PHASES=${UPNP_WIRE_PHASES# }
# the build of the first phase; a non-empty option list also keeps pf-router.sh from adding --pcp-peer
case "$UPNP_WIRE_PHASES" in
  igd2-strict*) export E2E_CONFIGURE_OPTIONS="--igd2 --strict" ;;
  *) export E2E_CONFIGURE_OPTIONS=--igd2 ;;
esac
export PCP_E2E_SUITE_HOOKS="$HERE/freebsd-hooks.sh"
export PCP_E2E_RESTART=0
export PCP_E2E_ARTIFACT_DIR="${PCP_E2E_ARTIFACT_DIR:-$HERE/../../../.tmp/tests/upnp_wire/freebsd}"
export E2E_STATUS_FILE="${UPNP_WIRE_STATUS_FILE:-$HERE/status.md}"
export E2E_STATUS_DATA_FILE="${UPNP_WIRE_STATUS_DATA_FILE:-$HERE/../../../.tmp/tests/upnp_wire/status-data.json}"
export E2E_EXTRA_CONF="uuid=$(sed -n 's/^uuid: //p' "$HERE/upnp-wire-cases.yaml"),notify_interval=10"
exec sh "$HERE/../pcp_e2e/run-freebsd.sh" "$@"

#!/bin/sh
# upnp_wire with a FreeBSD pf router in QEMU: the fixture of pcp_e2e/run-freebsd.sh (its slots, --reuse,
# up, down, ssh), a daemon built with --igd2, and a runner in a LAN container. The results go into the
# freebsd-igd2 column of status.md. Options and environment: see pcp_e2e/run-freebsd.sh.
#
#   run-freebsd.sh --slot 2 [--case NAME]...
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
export PCP_E2E_SUITE_HOOKS="$HERE/freebsd-hooks.sh"
export PCP_E2E_RESTART=0
export PCP_E2E_ARTIFACT_DIR="${PCP_E2E_ARTIFACT_DIR:-$HERE/../../../.tmp/tests/upnp_wire/freebsd}"
export E2E_STATUS_FILE="${UPNP_WIRE_STATUS_FILE:-$HERE/status.md}"
export E2E_STATUS_DATA_FILE="${UPNP_WIRE_STATUS_DATA_FILE:-$HERE/../../../.tmp/tests/upnp_wire/status-data.json}"
export E2E_CONFIGURE_OPTIONS=--igd2
export E2E_EXTRA_CONF="uuid=$(sed -n 's/^uuid: //p' "$HERE/upnp-wire-cases.yaml"),notify_interval=30"
exec sh "$HERE/../pcp_e2e/run-freebsd.sh" "$@"

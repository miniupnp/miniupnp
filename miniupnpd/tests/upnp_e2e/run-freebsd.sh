#!/bin/sh
# upnp_e2e with a FreeBSD pf router in QEMU: the fixture of pcp_e2e/run-freebsd.sh (its slots, --reuse,
# up, down, ssh), a daemon built with --igd2, and the hooks below in place of the PCP runner. The results
# go into the freebsd-igd2 column of status.md. Options and environment: see pcp_e2e/run-freebsd.sh.
#
#   run-freebsd.sh --slot 2 [--case NAME]...
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
export PCP_E2E_SUITE_HOOKS="$HERE/freebsd-hooks.sh"
export PCP_E2E_RESTART=0    # the lease check of pcp_e2e; the restart cases of this corpus replace it
export PCP_E2E_ARTIFACT_DIR="${PCP_E2E_ARTIFACT_DIR:-$HERE/../../../.tmp/tests/upnp_e2e/freebsd}"
export E2E_STATUS_FILE="${UPNP_E2E_STATUS_FILE:-$HERE/status.md}"
export E2E_STATUS_DATA_FILE="${UPNP_E2E_STATUS_DATA_FILE:-$HERE/../../../.tmp/tests/upnp_e2e/status-data.json}"
export E2E_CONFIGURE_OPTIONS=--igd2
exec sh "$HERE/../pcp_e2e/run-freebsd.sh" "$@"

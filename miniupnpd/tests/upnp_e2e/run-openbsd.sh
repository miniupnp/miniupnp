#!/bin/sh
# upnp_e2e with an OpenBSD pf router in QEMU: run-freebsd.sh with the router of pcp_e2e/run-openbsd.sh
# (the same fixture, slots and options). The results go into the openbsd-igd2 column of status.md.
#
#   run-openbsd.sh --slot 2 [--case NAME]...
#
# PCP_TEST_OPENBSD_VERSION picks the release (default 8.0).
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PCP_E2E_ROUTER=openbsd-pf
PCP_E2E_ARTIFACT_DIR="${PCP_E2E_ARTIFACT_DIR:-$HERE/../../../.tmp/tests/upnp_e2e/openbsd}"
export PCP_E2E_ROUTER PCP_E2E_ARTIFACT_DIR
exec sh "$HERE/run-freebsd.sh" "$@"

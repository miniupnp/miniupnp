#!/bin/sh
# upnp_wire with an OpenBSD pf router in QEMU: run-freebsd.sh with the router of pcp_e2e/run-openbsd.sh
# (the same fixture, slots and options). The results go into the openbsd-igd2 and openbsd-igd2-strict
# columns of status.md.
#
#   run-openbsd.sh [--base|--strict] [--slot N] [--case NAME]...
#
# PCP_TEST_OPENBSD_VERSION picks the release (default 8.0).
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
PCP_E2E_ROUTER=openbsd-pf
PCP_E2E_ARTIFACT_DIR="${PCP_E2E_ARTIFACT_DIR:-$HERE/../../../.tmp/tests/upnp_wire/openbsd}"
export PCP_E2E_ROUTER PCP_E2E_ARTIFACT_DIR
exec sh "$HERE/run-freebsd.sh" "$@"

#!/bin/sh
# FreeBSD driver of the daemon_options suite. The whole run is inside a throwaway VM: this script
# boots it, copies the tree in, runs freebsd/run-suite.sh and copies the results out, with
# ../common/freebsd_vm.sh. The `platform: linux` cases stay out (nftables, the Linux uptime, the
# minissdpd stand-in, lease_file6).
#
#   miniupnpd/tests/daemon_options/run-freebsd.sh [--freebsd-version RELEASE] [--case NAME ...]
#
# Fills the freebsd column of status.md, from the daemon of this tree, built with pf as pcp_e2e
# builds it (freebsd/run-suite.sh). DAEMON_OPTIONS_DAEMON names it in the report. Environment as for
# ../common/freebsd_vm.sh.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
DIR=$ROOT/miniupnpd/tests/daemon_options
. "$ROOT/miniupnpd/tests/common/e2e_lib.sh"
e2e_parse_args "$@"
cases=$SELECTED_CASES
daemon=${DAEMON_OPTIONS_DAEMON:-$(git -C "$ROOT" branch --show-current 2>/dev/null || echo unknown)}

export PCP_TEST_OUT_DIR=${PCP_TEST_OUT_DIR:-$ROOT/.tmp/ci/out/freebsd/daemon_options}
export PCP_TEST_RESULTS_DIR=$DIR
export PCP_TEST_DATA_DIR=$ROOT/.tmp/tests/daemon_options
export PCP_TEST_VM_COMMAND="env DAEMON_OPTIONS_DAEMON='$daemon' DAEMON_OPTIONS_CASES='$cases' sh miniupnpd/tests/daemon_options/freebsd/run-suite.sh /tmp/pcp-results"
exec sh "$ROOT/miniupnpd/tests/common/freebsd_vm.sh"

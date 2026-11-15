#!/bin/sh
# FreeBSD counterpart of run-docker.sh for the cases that restart
# the daemon (the YAML cases marked "requires: daemon-restart").
#
# In a throwaway FreeBSD VM (../common/freebsd_vm.sh), freebsd/ci.sh builds the daemon on an
# epair(4) router topology (freebsd/setup.sh) and runs the YAML runner with fixtures/freebsd.sh
# as its fixture.  The runner fills the FreeBSD column of the combined status.md.
#
#   miniupnpd/tests/pcp_wire/run-freebsd.sh [--freebsd-version RELEASE]
#
# Environment: as for ../common/freebsd_vm.sh, and
#   PCP_TEST_OUT_DIR           where run.log, summary.txt, console.log, status.md
#                              and the captures are saved (default:
#                              <repo>/.tmp/ci/out/freebsd/announce)
#   PCP_TEST_RESULTS_DIR       where status.md is written (default: beside
#                              this script)
#   PCP_TEST_DATA_DIR          where status-data.json is kept (default:
#                              <repository>/.tmp/tests/pcp_wire)
#   PCP_TEST_LEASE_ONLY, PCP_TEST_LEASE_CASES   see freebsd/ci.sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/../common/e2e_lib.sh"
e2e_parse_args "$@"
[ -z "$SELECTED_CASES" ] || { echo "--case is not supported here" >&2; exit 2; }

export PCP_TEST_OUT_DIR=${PCP_TEST_OUT_DIR:-"$REPO_ROOT/.tmp/ci/out/freebsd/announce"}
export PCP_TEST_RESULTS_DIR=${PCP_TEST_RESULTS_DIR:-"$SCRIPT_DIR"}
export PCP_TEST_DATA_DIR=${PCP_TEST_DATA_DIR:-"$REPO_ROOT/.tmp/tests/pcp_wire"}
export PCP_TEST_VM_COMMAND="env PCP_TEST_LEASE_ONLY=${PCP_TEST_LEASE_ONLY:-0} PCP_TEST_LEASE_CASES=${PCP_TEST_LEASE_CASES:-1} sh miniupnpd/tests/pcp_wire/freebsd/ci.sh /root/miniupnp /tmp/pcp-results"
exec sh "$SCRIPT_DIR/../common/freebsd_vm.sh"

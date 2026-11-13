#!/bin/sh
# OpenBSD driver of the daemon_options suite: run-freebsd.sh with an OpenBSD VM. The same
# freebsd/run-suite.sh runs in it, with routing domains for hosts (OpenBSD has no vnet jail).
# Fills the openbsd column of status.md.
#
#   miniupnpd/tests/daemon_options/run-openbsd.sh [--case NAME ...]
#
# PCP_TEST_OPENBSD_VERSION picks the release (default 8.0). Environment as for
# ../common/freebsd_vm.sh.
PCP_TEST_VM_OS=openbsd
PCP_TEST_OUT_DIR=${PCP_TEST_OUT_DIR:-$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)/.tmp/ci/out/openbsd/daemon_options}
export PCP_TEST_VM_OS PCP_TEST_OUT_DIR
exec sh "$(dirname -- "$0")/run-freebsd.sh" "$@"

#!/bin/sh
# Run a command of a test suite in a throwaway FreeBSD VM (QEMU), for the FreeBSD drivers of the
# suites (pcp_wire/run-freebsd.sh, daemon_options/run-freebsd.sh): boot the VM, copy the checkout
# into /root/miniupnp, run the command there as root and bring its results back. The VM steps
# are those of vm_lib.sh, which pcp_e2e/run-freebsd.sh uses as well.
#
# Requires: qemu-system-x86_64, qemu-img, xz, curl, ssh, python3 with PyYAML,
# xorriso (or genisoimage/mkisofs).  KVM is used when /dev/kvm is usable.
#
# Set by the driver:
#   PCP_TEST_VM_COMMAND        what runs in the VM, from /root/miniupnp; it writes its
#                              status.md and status-data.json to /tmp/pcp-results
#   PCP_TEST_OUT_DIR           where run.log, summary.txt, console.log and /tmp/pcp-results
#                              (as results/) are saved
#   PCP_TEST_RESULTS_DIR       where status.md is written
#   PCP_TEST_DATA_DIR          where status-data.json is kept
# Environment:
#   PCP_TEST_FREEBSD_VERSION   FreeBSD release (--freebsd-version of the drivers; default: the
#                              newest release that has a cloud-init image, looked up at run time)
#   PCP_TEST_FREEBSD_CACHE     image cache dir (default: ~/.cache/miniupnpd-pcp-test)
#   PCP_TEST_FREEBSD_MEMORY    VM memory in MB (default: 2048)
#   PCP_TEST_FREEBSD_SSH_PORT  host port forwarded to the VM (default: a free one from 2401)
#   PCP_TEST_KEEP_VM=1         leave the VM running and keep its work dir
#
# The first run boots the downloaded image once, runs freebsd/prepare.sh (gmake, pkgconf, rsync,
# and the libpfctl.h header on FreeBSD 15) and caches the result as
# prepared-<version>-<hash>.qcow2 in the cache dir; later runs boot a throwaway
# overlay on it.  Delete that file to rebuild it.
set -eu

: "${PCP_TEST_VM_COMMAND:?the command to run in the VM}"
: "${PCP_TEST_OUT_DIR:?where the run is saved}"
: "${PCP_TEST_RESULTS_DIR:?where status.md is written}"
: "${PCP_TEST_DATA_DIR:?where status-data.json is kept}"
COMMON=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$COMMON/../../.." && pwd)
VERSION=${PCP_TEST_FREEBSD_VERSION:-}
# shellcheck disable=SC1091
. "$COMMON/e2e_lib.sh"
# shellcheck disable=SC1091
. "$COMMON/vm_lib.sh"
# an SSH port of its own for each VM, unless the caller names one
SSH_PORT=${PCP_TEST_FREEBSD_SSH_PORT:-}
[ -n "$SSH_PORT" ] || reserve_slot pcp_qemu_plan ""
# a VM kept by an earlier run (this one, or pcp_e2e/run-freebsd.sh up) may hold the port
if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :$SSH_PORT" 2>/dev/null | grep -q LISTEN; then
	echo "Host port $SSH_PORT is in use (a VM kept by another run?). Stop it, or set PCP_TEST_FREEBSD_SSH_PORT." >&2
	exit 2
fi
KEEP_VM=${PCP_TEST_KEEP_VM:-0}
OUT_DIR=$PCP_TEST_OUT_DIR

vmlib_tools qemu-system-x86_64 qemu-img xz curl ssh ssh-keygen tar
if ! python3 -c 'import yaml' >/dev/null 2>&1; then
	echo "python3 with PyYAML is required to run the YAML cases." >&2
	exit 2
fi

WORK=$(mktemp -d)
QEMU_PID=
KEY=
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$KEEP_VM" = 1 ]; then
		echo "Keeping VM (pid ${QEMU_PID:-none}); work dir $WORK; ssh -p $SSH_PORT -i $KEY $VM_USER@127.0.0.1" >&2
	else
		[ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null || true
		rm -rf "$WORK"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

vmlib_freebsd_image
vmlib_seed miniupnpd-pcp-test
vmlib_prepared "$COMMON/freebsd/prepare.sh" "prepared-$VERSION"
# Throwaway overlay so the cached image is never modified.
qemu-img create -q -f qcow2 -F qcow2 -b "$PREPARED" "$WORK/disk.qcow2" 10G
vmlib_boot "$WORK/disk.qcow2"

# The files to copy: tracked and uncommitted ones, plus miniupnpd/tests even if a
# git exclude rule hides it (this checkout may not track it).
copy_list() {
	(cd "$REPO_ROOT" && { git ls-files -co --exclude-standard -z | grep -zv '^miniupnpd/tests/' | grep -zv '^miniupnpd/tests2/'
	    find miniupnpd/tests -type f -not -path '*/__pycache__/*' -print0; })
}
vmlib_copy "$REPO_ROOT" copy_list -rlpc

# Everything else runs inside the VM: PCP_TEST_VM_COMMAND, from the copy of the tree. The
# existing status data is copied in first, so the FreeBSD column merges into the suite's
# status.md.
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
RESULTS_DIR=$PCP_TEST_RESULTS_DIR
DATA_DIR=$PCP_TEST_DATA_DIR
STATUS_FILE=$RESULTS_DIR/status.md
DATA_FILE=$DATA_DIR/status-data.json
$SSH "$PRIV rm -rf /tmp/pcp-results && $PRIV mkdir -p /tmp/pcp-results && $PRIV chmod 777 /tmp/pcp-results"
if [ -f "$DATA_FILE" ]; then
	$SSH "cat >/tmp/pcp-results/status-data.json" <"$DATA_FILE"
fi
{
	rc=0
	$SSH "cd /root/miniupnp && $PRIV $PCP_TEST_VM_COMMAND" 2>&1 || rc=$?
	echo $rc >"$OUT_DIR/exit-status"
} | tee "$OUT_DIR/run.log"
status=$(cat "$OUT_DIR/exit-status")
rm -f "$OUT_DIR/exit-status"

# Bring the results back: the merged status report and data, logs, captures.
mkdir -p "$OUT_DIR/results"
$SSH "$PRIV tar -cf - -C /tmp/pcp-results ." 2>/dev/null | tar -xf - -C "$OUT_DIR/results" || true
if [ -f "$OUT_DIR/results/status.md" ]; then
	mkdir -p "$RESULTS_DIR" "$DATA_DIR"
	cp "$OUT_DIR/results/status.md" "$STATUS_FILE"
	cp "$OUT_DIR/results/status-data.json" "$DATA_FILE"
fi
# Collect the VM-side logs and the status report next to the captures.
$SSH "$PRIV tar -cf - -C /tmp pcp-fixture" 2>/dev/null | tar -xf - -C "$OUT_DIR" || true
cp "$WORK/console.log" "$OUT_DIR/console.log" 2>/dev/null || true
echo "FreeBSD $VERSION, exit status $status" >"$OUT_DIR/summary.txt"
echo "Results saved to $OUT_DIR" >&2
exit "$status"

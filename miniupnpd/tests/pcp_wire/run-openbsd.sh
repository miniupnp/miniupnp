#!/bin/sh
# The YAML cases against miniupnpd with pf on OpenBSD. It fills the openbsd column of status.md.
#
# OpenBSD has no jail(8) to hold a client inside the VM as freebsd/run-suite.sh does, so this uses
# the kept fixture of ../pcp_e2e/run-openbsd.sh (the VM, its LAN and WAN on Docker bridges) and runs
# the runner on the host, which is a LAN host of the fixture ($LAN4.254 and ${LAN6}ffff). The daemon
# runs as the pcp_wire fixtures run it (no UPnP), from a clean state, and the runner reads its lease
# files over SSH. The cases that restart the daemon or renumber the WAN need a fixture command this
# script does not provide, and are left out.
#
#   run-openbsd.sh [--slot N] [--keep-vm] [--case NAME ...]
#
#   --slot N    the fixture slot (default 8), as for ../pcp_e2e/run-openbsd.sh
#   --keep-vm   leave the fixture up (default: remove it at the end)
#
# Environment: PCP_TEST_OPENBSD_VERSION (default 8.0), PCP_TEST_RESULTS_DIR (status.md, default
# beside this script), PCP_TEST_DATA_DIR (status-data.json, default <repo>/.tmp/tests/pcp_wire),
# PCP_TEST_OUT_DIR (logs, default <repo>/.tmp/ci/out/openbsd/wire).
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd)
E2E=$REPO_ROOT/miniupnpd/tests/pcp_e2e/run-openbsd.sh
SLOT=8
KEEP_VM=0
CASES=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--slot) SLOT=${2:?--slot needs a number}; shift 2 ;;
	--keep-vm) KEEP_VM=1; shift ;;
	--case) CASES="$CASES --case ${2:?--case needs a name}"; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
RESULTS_DIR=${PCP_TEST_RESULTS_DIR:-"$SCRIPT_DIR"}
DATA_DIR=${PCP_TEST_DATA_DIR:-"$REPO_ROOT/.tmp/tests/pcp_wire"}
OUT_DIR=${PCP_TEST_OUT_DIR:-"$REPO_ROOT/.tmp/ci/out/openbsd/wire"}
mkdir -p "$RESULTS_DIR" "$DATA_DIR" "$OUT_DIR"

# shellcheck disable=SC1091
. "$REPO_ROOT/miniupnpd/tests/common/e2e_lib.sh"
e2e_address_plan "$SLOT"
CACHE=${PCP_TEST_FREEBSD_CACHE:-"$HOME/.cache/miniupnpd-pcp-test"}
STATE=$CACHE/e2e-vm/${PCP_E2E_VM_NAME:-openbsd-pf-slot$SLOT}

# The fixture: the VM, the tree synced and built. The e2e runner holds the slot lock only while it
# runs; this script then uses the fixture alone.
sh "$E2E" up --reuse --slot "$SLOT" --no-restart
finish() {
	status=$?
	trap - EXIT HUP INT TERM
	[ "$KEEP_VM" = 1 ] || sh "$E2E" down --slot "$SLOT" >/dev/null 2>&1 || true
	exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# shellcheck disable=SC1091
. "$STATE/state.env"
VM_SSH="ssh -p $SSH_PORT -i $CACHE/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 openbsd@127.0.0.1"
$VM_SSH "cd /root/miniupnp && doas sh miniupnpd/tests/pcp_e2e/freebsd/pf-router.sh start enable_upnp=no" \
	>"$OUT_DIR/daemon-start.log" 2>&1 || { cat "$OUT_DIR/daemon-start.log" >&2; exit 1; }

runner() {
	# shellcheck disable=SC2086
	python3 -I "$SCRIPT_DIR/run_pcp_wire_cases.py" --port 5351 --platform openbsd \
		--unsupported pcp-peer \
		--state-command "$VM_SSH doas cat /var/tmp/miniupnpd.leases /var/tmp/miniupnpd.leases6" \
		--status-file "$RESULTS_DIR/status.md" --status-data-file "$DATA_DIR/status-data.json" \
		$CASES "$@"
}
status=0
{
	runner --host "$LAN4.1" --family ipv4 --protocol both --mutating || status=1
	runner --host "${LAN6}1" --family ipv6 --protocol pcp --mutating --allow-empty-selection || status=1
	echo "exit status $status"
} 2>&1 | tee "$OUT_DIR/run.log"
$VM_SSH "doas cat /tmp/pcp-e2e/miniupnpd.log" >"$OUT_DIR/miniupnpd.log" 2>&1 || true
grep -q '^exit status 0$' "$OUT_DIR/run.log"

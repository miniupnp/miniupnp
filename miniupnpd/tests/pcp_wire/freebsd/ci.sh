#!/bin/sh
# Runs inside the FreeBSD VM as root (the GitHub workflow's vmactions step).
#
#   ci.sh DAEMON_TREE RESULTS_DIR
#
# Builds the daemon from DAEMON_TREE on the epair router topology, runs the whole
# YAML suite against it (run-suite.sh) and then the YAML cases that restart it,
# using this checkout's runner and corpus.  The
# FreeBSD column of RESULTS_DIR/status.md and the captures are written there.
set -eu

[ "$#" -eq 2 ] || { echo "usage: $0 DAEMON_TREE RESULTS_DIR" >&2; exit 2; }
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TREE=$(CDPATH='' cd -- "$1" && pwd)
mkdir -p "$2"
RESULTS=$(CDPATH='' cd -- "$2" && pwd)

. "$HERE/../common/e2e_lib.sh"
cd "$TREE"
sh "$HERE/freebsd/setup.sh"
status=0
if [ "${PCP_TEST_LEASE_ONLY:-0}" = 1 ]; then
	# only the lease cases (PCP_TEST_LEASE_ONLY=1)
	sh "$HERE/freebsd/lease-suite.sh" "$RESULTS" || status=1
	exit "$status"
fi
# The whole suite against a running daemon, from a client jail on LAN1 ...
echo "=== The suite ==="
sh "$HERE/freebsd/run-suite.sh" "$RESULTS" || status=1
# ... then the cases that cold-start the daemon themselves.
export PCP_TEST_DAEMON_TREE=$TREE FREEBSD_ARTIFACTS=$RESULTS/captures
echo "=== The cases which start the daemon ==="
for family in ipv4 ipv6; do
	python3 "$HERE/run_pcp_wire_cases.py" --fixture "$HERE/fixtures/freebsd.sh" --fixture-only \
		--protocol pcp --family "$family" --platform freebsd --allow-empty-selection \
		--status-file "$RESULTS/status.md" --status-data-file "$RESULTS/status-data.json" || status=1
done
# ... and last the cases which restart the daemon over its PCP lease file.
# PCP_TEST_LEASE_CASES=0 skips them.
if [ "${PCP_TEST_LEASE_CASES:-1}" = 1 ]; then
	echo "=== The cases which restart the daemon over its lease file ==="
	sh "$HERE/freebsd/lease-suite.sh" "$RESULTS" || status=1
fi
# RESULTS is new for each daemon, so its status report holds this run alone.
echo "=== All parts ==="
e2e_result "$status" "$RESULTS/status.md" freebsd
exit "$status"

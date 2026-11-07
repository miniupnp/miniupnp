#!/bin/sh
# Runs inside the FreeBSD VM as root, from the daemon tree, after setup.sh.
#
#   run-suite.sh RESULTS_DIR
#
# Runs the whole YAML suite against a long-running miniupnpd.  The client must
# be a different host: the daemon works out which LAN a request came from by
# routing to the sender, and for the router's own address that route is lo0, so
# a runner on the router itself is ignored over IPv6 ("not from a LAN").
# epair0b therefore moves into a vnet jail that shares the root filesystem (and
# so the runner and Python), which plays the Docker harness's client container.
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 RESULTS_DIR" >&2; exit 2; }
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
RESULTS=$(CDPATH='' cd -- "$1" && pwd)
WORK=/tmp/pcp-fixture
JAIL=pcpclient
. "$HERE/../common/freebsd_lib.sh"

daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null || true
	jail -r "$JAIL" >/dev/null 2>&1 || true
	ifconfig epair0b up >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# the lease files, read by the runner (--state-file) as in the Docker harness
LEASE_BASE=$WORK/suite.leases
LEASE6=${LEASE_BASE}6
rm -f "$LEASE_BASE" "$LEASE6"
{ cat "$WORK/miniupnpd.conf"; echo "lease_file=$LEASE_BASE"; echo "lease_file6=$LEASE6"; } >"$WORK/suite.conf"
miniupnpd/miniupnpd -d -f "$WORK/suite.conf" >"$RESULTS/suite-miniupnpd.log" 2>&1 &
daemon=$!

freebsd_make_jail "$JAIL" epair0b 192.168.1.2 fd42:1::2
sleep 3 # let IPv6 DAD finish

runner() { jexec "$JAIL" python3 "$HERE/run_pcp_wire_cases.py" --port 5351 "$@"; }

ready=0
attempt=0
while [ "$attempt" -lt 20 ]; do
	if runner --host 192.168.1.1 --protocol natpmp --case public-address \
	    --status-file "$WORK/readiness.md" >/dev/null 2>&1; then
		ready=1
		break
	fi
	kill -0 "$daemon" 2>/dev/null || break
	attempt=$((attempt + 1))
	sleep 1
done
if [ "$ready" -ne 1 ]; then
	echo "miniupnpd did not answer on 192.168.1.1:5351" >&2
	cat "$RESULTS/suite-miniupnpd.log" >&2
	exit 1
fi

status=0
runner --host 192.168.1.1 --family ipv4 --mutating --platform freebsd --state-file "$LEASE_BASE" --state-file "$LEASE6" \
	--status-file "$RESULTS/status.md" --status-data-file "$RESULTS/status-data.json" || status=1
runner --host fd42:1::1 --family ipv6 --protocol pcp --allow-empty-selection --platform freebsd \
	--state-file "$LEASE_BASE" --state-file "$LEASE6" \
	--status-file "$RESULTS/status.md" --status-data-file "$RESULTS/status-data.json" || status=1
exit "$status"

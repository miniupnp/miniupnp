#!/bin/sh
# Runs inside the FreeBSD VM as root, from the daemon tree, after setup.sh.
#
#   lease-suite.sh RESULTS_DIR
#
# The YAML cases which need the PCP lease file (requires: lease-restart, see
# run-docker.sh for the Linux counterpart), with the daemon setup.sh
# built (--leasefile --pcp-peer): the cases make their mappings, the daemon is stopped, the
# rules of its pf anchor are flushed (as after a reboot) and it is started again;
# the verify phase checks that the lease file and the rules came back.  Then the
# profiles with a short minimum lifetime.  The client is a vnet jail on LAN1, as
# in run-suite.sh.
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 RESULTS_DIR" >&2; exit 2; }
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
RESULTS=$(CDPATH='' cd -- "$1" && pwd)
WORK=/tmp/pcp-fixture
JAIL=pcpclient
LEASE_BASE=$WORK/miniupnpd.leases
LEASE6=${LEASE_BASE}6
SNAP=$WORK/lease-snapshots
LOG=$RESULTS/lease-miniupnpd.log

daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null || true
	jail -r "$JAIL" >/dev/null 2>&1 || true
	ifconfig epair0b up >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# no mapping of the baseline suite is left in the anchor
# the rules are in child anchors of miniupnpd, and its own rules send packets there
flush_anchor() {
	for child in $(pfctl -a miniupnpd -sA 2>/dev/null); do
		pfctl -a "$child" -F all >/dev/null 2>&1 || true
	done
	pfctl -a miniupnpd -F all >/dev/null 2>&1 || true
}
flush_anchor

jail -c name="$JAIL" path=/ host.hostname="$JAIL" persist vnet vnet.interface=epair0b
jexec "$JAIL" ifconfig lo0 127.0.0.1/8 up
jexec "$JAIL" ifconfig epair0b up
jexec "$JAIL" ifconfig epair0b inet 192.168.1.2/24
jexec "$JAIL" ifconfig epair0b inet6 fd42:1::2/64
sleep 3 # let IPv6 DAD finish

# runner FAMILY ARGS... : the YAML runner in the jail
runner() {
	runner_family=$1
	shift
	if [ "$runner_family" = ipv6 ]; then
		jexec "$JAIL" python3 "$HERE/run_pcp_wire_cases.py" --port 5351 --host fd42:1::1 --family ipv6 \
			--protocol pcp --allow-empty-selection --platform freebsd --state-file "$LEASE_BASE" --state-file "$LEASE6" \
			--status-file "$RESULTS/status.md" --status-data-file "$RESULTS/status-data.json" "$@"
	else
		jexec "$JAIL" python3 "$HERE/run_pcp_wire_cases.py" --port 5351 --host 192.168.1.1 --family ipv4 \
			--mutating --platform freebsd --state-file "$LEASE_BASE" --state-file "$LEASE6" \
			--status-file "$RESULTS/status.md" --status-data-file "$RESULTS/status-data.json" "$@"
	fi
}

# start_daemon EXTRA_CONF : cold start, waits until it answers
start_daemon() {
	grep -v '^max_lifetime' "$WORK/miniupnpd.conf" >"$WORK/lease.conf"
	{ echo "max_lifetime=7200"; echo "lease_file=$LEASE_BASE"; echo "lease_file6=$LEASE6"; printf '%s\n' "$1"; } >>"$WORK/lease.conf"
	miniupnpd/miniupnpd -d -f "$WORK/lease.conf" >>"$LOG" 2>&1 &
	daemon=$!
	attempt=0
	while [ "$attempt" -lt 20 ]; do
		if runner ipv4 --protocol natpmp --case public-address --status-file "$WORK/readiness.md" \
		    >/dev/null 2>&1; then
			return 0
		fi
		kill -0 "$daemon" 2>/dev/null || break
		attempt=$((attempt + 1))
		sleep 1
	done
	echo "FAIL: miniupnpd did not answer on 192.168.1.1:5351" >&2
	tail -20 "$LOG" >&2
	return 1
}
# stop_daemon : the rules of the anchor are lost, as after a reboot; the lease file stays
stop_daemon() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null || true
	wait "$daemon" 2>/dev/null || true
	daemon=
	flush_anchor
}
# the rules of the anchor for the internal ports of a lease case. The "ts-N" of a
# pinhole label is its expiry on the daemon's clock; it is restored from the
# unix time in the lease file and may move by a second (the runner allows the
# same with expiry_tolerance), so it is left out of the comparison.
lease_rules() {
	{ pfctl -a miniupnpd -sn 2>&1; pfctl -a miniupnpd -sr 2>&1; } | grep -E "$1" \
		| sed 's/ ts-[0-9]*:/ ts-N:/' | sort || true
}

status=0

run_lease_restart() {
	family=$1
	lease_case=lease-restart-$family
	lease_args="--snapshot-dir $SNAP --case $lease_case --profile baseline"
	# shellcheck disable=SC2086
	ports=$(runner "$family" --list-lease-ports $lease_args | tr ' ' '|')
	[ -n "$ports" ] || return 0
	# shellcheck disable=SC2086
	runner "$family" --phase create $lease_args || return 1
	rules_before=$(lease_rules "$ports")
	stop_daemon
	start_daemon "" || return 1
	rules_after=$(lease_rules "$ports")
	if [ "$rules_before" != "$rules_after" ]; then
		echo "FAIL $lease_case: pf rules of the mappings changed over the restart:" >&2
		echo "before: $rules_before" >&2
		echo "after:  $rules_after" >&2
		return 1
	fi
	# shellcheck disable=SC2086
	runner "$family" --phase verify $lease_args
}

# run_profile PROFILE EXTRA_CONF CASE... : a daemon with other settings
run_profile() {
	profile=$1
	extra=$2
	shift 2
	stop_daemon
	rm -f "$LEASE_BASE" "$LEASE6"
	start_daemon "$extra" || return 1
	case_args=
	for profile_case in "$@"; do case_args="$case_args --case $profile_case"; done
	# shellcheck disable=SC2086
	runner ipv4 --profile "$profile" $case_args || return 1
	for profile_case in "$@"; do
		case "$profile_case" in
		lease-expiry)
			for phase in create verify; do
				runner ipv4 --profile "$profile" --case "$profile_case" --phase "$phase" || return 1
			done ;;
		esac
	done
}

rm -rf "$SNAP" "$LEASE_BASE" "$LEASE6"
mkdir -p "$SNAP"
start_daemon "" || exit 1
for family in ipv4 ipv6; do
	run_lease_restart "$family" || status=1
done
run_profile short-lifetime 'pcp_min_lifetime_override=2' lease-short-lifetime-granted map-renewal-extends-expiry lease-expiry || status=1
run_profile min-lifetime-only 'min_lifetime=2' lease-min-lifetime-without-option || status=1
exit "$status"

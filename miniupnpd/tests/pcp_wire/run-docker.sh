#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd)
DOCKER_BIN=${DOCKER:-docker}
# what e2e_lib.sh reads
ROOT=$REPO_ROOT
DOCKER=$DOCKER_BIN
# the addresses of this run: the first free slot, or PCP_TEST_SLOT=N (1-128)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/../common/e2e_lib.sh"
reserve_slot e2e_address_plan "${PCP_TEST_SLOT:-}"
# fixtures/docker.sh runs under this reservation and uses the same addresses
export PCP_TEST_SLOT="$SLOT"
CONTAINER=${PCP_TEST_CONTAINER:-miniupnpd-pcp-test-$$}
NETWORK=${PCP_TEST_NETWORK:-miniupnpd-pcp-net-$$}
WAN_NETWORK=$NETWORK-wan
PEER_CONTAINER=$CONTAINER-peer
WAN_PEER=${PCP_TEST_WAN_PEER:-0}
KEEP_CONTAINER=${PCP_TEST_KEEP_CONTAINER:-0}
SECOND_CLIENT=${PCP_TEST_SECOND_CLIENT:-1}
CAPTURE=${PCP_TEST_CAPTURE:-1}
CAPTURE_DIR=${PCP_TEST_CAPTURE_DIR:-"$REPO_ROOT/.tmp/packet-captures"}
RESULTS_DIR=${PCP_TEST_RESULTS_DIR:-"$SCRIPT_DIR"}
DATA_DIR=${PCP_TEST_DATA_DIR:-"$REPO_ROOT/.tmp/tests/pcp_wire"}
CAPTURE_TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S.%N)

if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
	echo "Docker is required to run the PCP/NAT-PMP test environment." >&2
	exit 2
fi
e2e_tools_image
e2e_build_daemon
# for fixtures/docker.sh
export PCP_TEST_IMAGE="$IMAGE" PCP_TEST_DAEMON_DIR="$DAEMON_DIR"
# what a router and what a container running harness code mount
DAEMON_MOUNT=$DAEMON_DIR:/opt/miniupnpd:ro
TESTS_MOUNT=$SCRIPT_DIR/..:/pcp-tests:ro
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$KEEP_CONTAINER" = 1 ]; then
		echo "Keeping Docker container $CONTAINER" >&2
	else
		if [ "$status" -ne 0 ]; then
			"$DOCKER_BIN" logs "$CONTAINER" >&2 2>/dev/null || true
			"$DOCKER_BIN" logs "$PEER_CONTAINER" >&2 2>/dev/null || true
		fi
		"$DOCKER_BIN" rm -f "$CONTAINER" >/dev/null 2>&1 || true
		"$DOCKER_BIN" rm -f "$PEER_CONTAINER" >/dev/null 2>&1 || true
		"$DOCKER_BIN" network rm "$WAN_NETWORK" >/dev/null 2>&1 || true
		"$DOCKER_BIN" network rm "$NETWORK" >/dev/null 2>&1 || true
		if [ -n "${STATE_DIR:-}" ]; then
			# the daemon wrote its files as root
			"$DOCKER_BIN" run --rm --volume "$STATE_DIR:/state" --entrypoint sh "$IMAGE" \
				-c 'rm -rf /state/* /state/.[!.]*' >/dev/null 2>&1 || true
			rm -rf "$STATE_DIR"
		fi
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "$CAPTURE" in
0|1) ;;
*) echo "PCP_TEST_CAPTURE must be 0 or 1." >&2; exit 2 ;;
esac
case "$WAN_PEER" in
0|1) ;;
*) echo "PCP_TEST_WAN_PEER must be 0 or 1." >&2; exit 2 ;;
esac
case "$SECOND_CLIENT" in
0|1) ;;
*) echo "PCP_TEST_SECOND_CLIENT must be 0 or 1." >&2; exit 2 ;;
esac
mkdir -p "$RESULTS_DIR" "$DATA_DIR"
# /var/lib/miniupnpd of the daemon, where lease_file and lease_file6 are written, shared
# read-only with the test client to check what the daemon records
STATE_DIR=$(mktemp -d)
chmod 755 "$STATE_DIR"
if [ "$CAPTURE" = 1 ]; then
	mkdir -p "$CAPTURE_DIR"
fi

if [ "$WAN_PEER" = 1 ]; then
	# IPv6 is routed through the fixture firewall, not translated by Docker.
	"$DOCKER_BIN" network create --driver bridge --ipv6 \
		--opt com.docker.network.bridge.gateway_mode_ipv6=routed \
		--subnet "$LAN4.0/24" --gateway "$LAN4.254" --subnet "$LAN6_PREFIX::/64" "$NETWORK" >/dev/null
else
	"$DOCKER_BIN" network create --driver bridge --ipv6 \
		--subnet "$LAN4.0/24" --gateway "$LAN4.254" --subnet "$LAN6_PREFIX::/64" "$NETWORK" >/dev/null
fi
LAN_SUBNET4=$LAN4.0/24

if [ "$WAN_PEER" = 1 ]; then
	"$DOCKER_BIN" network create --driver bridge --ipv6 \
		--opt com.docker.network.bridge.gateway_mode_ipv6=routed \
		--subnet $WAN4.0/24 --gateway $WAN4.254 \
		--subnet $WAN6_PREFIX::/64 --gateway $WAN6_PREFIX::ff "$WAN_NETWORK" >/dev/null
	"$DOCKER_BIN" create --name "$CONTAINER" --network "$NETWORK" \
		--network-alias pcp-router --env "PCP_TEST_WAN4=$WAN4" --env "PCP_TEST_WAN6_PREFIX=$WAN6_PREFIX" --cap-add NET_ADMIN --env PCP_TEST_REAL_WAN=1 \
		--volume "$STATE_DIR:/var/lib/miniupnpd" --volume "$DAEMON_MOUNT" \
		--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 "$IMAGE" >/dev/null
	"$DOCKER_BIN" network connect --ip $WAN4.1 --ip6 $WAN6_PREFIX::1 "$WAN_NETWORK" "$CONTAINER"
	"$DOCKER_BIN" start "$CONTAINER" >/dev/null
	"$DOCKER_BIN" create --name "$PEER_CONTAINER" --network "$NETWORK" \
		--cap-add NET_ADMIN --volume "$TESTS_MOUNT" --entrypoint python3 "$IMAGE" \
		/pcp-tests/common/traffic_agent.py --host 0.0.0.0 \
		--source4 $WAN4.2 --source6 $WAN6_PREFIX::2 \
		--route6 "$LAN6_PREFIX::/64" --gateway6 $WAN6_PREFIX::1 >/dev/null
	"$DOCKER_BIN" network connect --ip $WAN4.2 --ip6 $WAN6_PREFIX::2 "$WAN_NETWORK" "$PEER_CONTAINER"
	"$DOCKER_BIN" start "$PEER_CONTAINER" >/dev/null
	peer_ready=0
	for attempt in 1 2 3 4 5 6 7 8 9 10; do
		if "$DOCKER_BIN" exec "$PEER_CONTAINER" python3 -c \
			'import urllib.request; urllib.request.urlopen("http://127.0.0.1:18080", timeout=1)' >/dev/null 2>&1; then
			peer_ready=1
			break
		fi
		sleep 1
	done
	if [ "$peer_ready" != 1 ]; then
		echo "WAN traffic actor did not become ready." >&2
		exit 1
	fi
	ROUTER4=$("$DOCKER_BIN" inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" "$CONTAINER")
	ROUTER6=$("$DOCKER_BIN" inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").GlobalIPv6Address}}" "$CONTAINER")
	PEER4=$("$DOCKER_BIN" inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" "$PEER_CONTAINER")
else
	"$DOCKER_BIN" run --detach \
	--name "$CONTAINER" \
	--network "$NETWORK" \
	--network-alias pcp-router --env "PCP_TEST_WAN4=$WAN4" --env "PCP_TEST_WAN6_PREFIX=$WAN6_PREFIX" \
	--cap-add NET_ADMIN \
	--volume "$STATE_DIR:/var/lib/miniupnpd" --volume "$DAEMON_MOUNT" \
	"$IMAGE"
fi

ready=0
attempt=0
while [ "$attempt" -lt 20 ]; do
	if "$DOCKER_BIN" run --rm --network "$NETWORK" --volume "$TESTS_MOUNT" \
		--entrypoint python3 "$IMAGE" \
		/pcp-tests/pcp_wire/run_pcp_wire_cases.py \
		--host pcp-router --port 5351 \
		--protocol natpmp --case public-address >/dev/null 2>&1; then
		ready=1
		break
	fi
	if ! "$DOCKER_BIN" inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -qx true; then
		break
	fi
	attempt=$((attempt + 1))
	sleep 1
done

if [ "$ready" -ne 1 ]; then
	echo "Docker PCP/NAT-PMP server did not become ready on UDP port 5351." >&2
	exit 1
fi

# Keep the same tests and JSON results when capture is disabled.  Only capture
# runs mount the capture directory and grant NET_RAW to the test client.
run_tests() {
	test_family=$1
	shift
	set -- --host pcp-router --port 5351 --family "$test_family" --platform linux \
		--state-file /pcp-wire-daemon-state/miniupnpd.leases --state-file /pcp-wire-daemon-state/miniupnpd.leases6 \
		--status-file /pcp-wire-results/status.md \
		--status-data-file /pcp-wire-data/status-data.json "$@"
	if [ "$test_family" = ipv6 ]; then
		set -- --protocol pcp --allow-empty-selection "$@"
	else
		set -- --mutating "$@"
	fi
	if [ "$WAN_PEER" = 1 ]; then
		set -- --peer-url "http://$PEER4:18080" "$@"
	fi
	if [ -n "${PCP_TEST_RESULTS_DIR:-}" ] || [ "$CAPTURE" = 0 ]; then
		set -- --results-file "/pcp-wire-results/results-$test_family.json" "$@"
	fi
	if [ "$CAPTURE" = 1 ]; then
		set -- --capture-dir /pcp-wire-captures --capture-interface eth0 "$@"
	fi
	# the second LAN client: one more address of the client container (.200); its cases are IPv4
	second=
	if [ "$SECOND_CLIENT" = 1 ] && [ "$test_family" = ipv4 ]; then
		second=$(python3 -c 'import ipaddress, sys; n = ipaddress.ip_network(sys.argv[1])
print(f"{n.network_address + 200}/{n.prefixlen}")' "$LAN_SUBNET4")
		set -- --second-client "${second%/*}" "$@"
	fi
	if [ "$WAN_PEER" = 1 ] || [ "$SECOND_CLIENT" = 1 ]; then
		set -- --cap-add NET_ADMIN --env "PCP_TEST_SECOND_CLIENT_CIDR=$second" \
			--entrypoint sh "$IMAGE" /pcp-tests/common/docker/client-entrypoint.sh "$@"
		if [ "$WAN_PEER" = 1 ]; then
			set -- --env "PCP_TEST_ROUTER4=$ROUTER4" --env "PCP_TEST_ROUTER6=$ROUTER6" \
				--env "PCP_TEST_WAN4=$WAN4" --env "PCP_TEST_WAN6_PREFIX=$WAN6_PREFIX" "$@"
		fi
	else
		set -- --entrypoint python3 "$IMAGE" /pcp-tests/pcp_wire/run_pcp_wire_cases.py "$@"
	fi
	set -- --volume "$TESTS_MOUNT" \
		--volume "$SCRIPT_DIR:/pcp-tests/pcp_wire:rw" \
		--volume "$RESULTS_DIR:/pcp-wire-results:rw" \
		--volume "$DATA_DIR:/pcp-wire-data:rw" \
		--volume "$STATE_DIR:/pcp-wire-daemon-state:ro" \
		--env PYTHONDONTWRITEBYTECODE=1 "$@"
	if [ "$CAPTURE" = 1 ]; then
		set -- --cap-add NET_RAW \
			--env "PCP_TEST_CAPTURE_TIMESTAMP=$CAPTURE_TIMESTAMP" \
			--volume "$CAPTURE_DIR:/pcp-wire-captures:rw" "$@"
	fi
	"$DOCKER_BIN" run --rm --network "$NETWORK" "$@"
}

test_status=0
# PCP_TEST_LEASE_ONLY=1: only the lease-restart cases and the profile passes below.
# PCP_TEST_BREAK=1: lose the lease file before the restart; the cases then have to FAIL.
if [ "${PCP_TEST_LEASE_ONLY:-0}" != 1 ]; then
	run_tests ipv4 "$@" || test_status=1
	run_tests ipv6 "$@" || test_status=1
fi

# The cases which require lease-restart (pcp-wire-cases.yaml) run in two phases, the
# daemon is restarted in between: "create" makes the mappings, "verify" checks that the
# lease files (lease_file, lease_file6) have the same lines again and the daemon has created the
# firewall rules again. PCP_TEST_LEASE_CASES=0 skips them, as do selected cases.
wait_for_daemon() {
	attempt=0
	while [ "$attempt" -lt 30 ]; do
		if "$DOCKER_BIN" run --rm --network "$NETWORK" --volume "$TESTS_MOUNT" --entrypoint python3 "$IMAGE" \
			/pcp-tests/pcp_wire/run_pcp_wire_cases.py --host pcp-router --port 5351 \
			--protocol natpmp --case public-address >/dev/null 2>&1; then
			return 0
		fi
		attempt=$((attempt + 1))
		sleep 1
	done
	echo "FAIL: the daemon did not answer again" >&2
	return 1
}
# firewall rules of the mappings of a lease case, by their internal ports
lease_rules() {
	"$DOCKER_BIN" exec "$CONTAINER" sh -c "nft list ruleset | grep -E '$1' | sort" || true
}
run_lease_restart() {
	lease_family=$1
	lease_case=lease-restart-$lease_family
	lease_args="--snapshot-dir /pcp-wire-data --case $lease_case --profile baseline"
	# shellcheck disable=SC2086
	ports=$(run_tests "$lease_family" --list-lease-ports $lease_args | tr ' ' '|')
	[ -n "$ports" ] || return 0
	# shellcheck disable=SC2086
	run_tests "$lease_family" --phase create $lease_args || return 1
	rules_before=$(lease_rules "$ports")
	if [ "${PCP_TEST_BREAK:-0}" = 1 ]; then
		# to check the test itself: lose the lease file, the verify phase has to fail
		"$DOCKER_BIN" exec "$CONTAINER" rm -f /var/lib/miniupnpd/miniupnpd.leases /var/lib/miniupnpd/miniupnpd.leases6
	fi
	"$DOCKER_BIN" restart "$CONTAINER" >/dev/null
	wait_for_daemon || return 1
	# the daemon creates the rules again from the lease file; compare them before the
	# verify phase deletes the mappings
	rules_after=$(lease_rules "$ports")
	if [ "$rules_before" != "$rules_after" ]; then
		echo "FAIL $lease_case: firewall rules of the mappings changed over the restart:" >&2
		echo "before: $rules_before" >&2
		echo "after:  $rules_after" >&2
		return 1
	fi
	# shellcheck disable=SC2086
	run_tests "$lease_family" --phase verify $lease_args
}
# A daemon with other settings, for the cases of a profile (pcp-wire-cases.yaml)
run_profile() {
	profile=$1
	extra_conf=$2
	shift 2
	"$DOCKER_BIN" rm -f "$CONTAINER" >/dev/null 2>&1 || true
	"$DOCKER_BIN" run --rm --volume "$STATE_DIR:/state" --entrypoint sh "$IMAGE" \
		-c 'rm -rf /state/* /state/.[!.]*' >/dev/null 2>&1 || true
	"$DOCKER_BIN" run --detach --name "$CONTAINER" --network "$NETWORK" --network-alias pcp-router --env "PCP_TEST_WAN4=$WAN4" --env "PCP_TEST_WAN6_PREFIX=$WAN6_PREFIX" \
		--cap-add NET_ADMIN --env "PCP_TEST_EXTRA_CONF=$extra_conf" \
		--volume "$STATE_DIR:/var/lib/miniupnpd" --volume "$DAEMON_MOUNT" "$IMAGE" >/dev/null
	wait_for_daemon || return 1
	case_args=
	for profile_case in "$@"; do case_args="$case_args --case $profile_case"; done
	# shellcheck disable=SC2086
	run_tests ipv4 --profile "$profile" $case_args
	# the cases which make mappings and wait for them to expire have no restart in between
	for profile_case in "$@"; do
		case "$profile_case" in
		lease-expiry)
			for phase in create verify; do
				run_tests ipv4 --profile "$profile" --case "$profile_case" --phase "$phase" || return 1
			done ;;
		esac
	done
}
if [ "${PCP_TEST_LEASE_CASES:-1}" = 1 ] && [ "$#" -eq 0 ]; then
	for lease_family in ipv4 ipv6; do
		run_lease_restart "$lease_family" || test_status=1
	done
	if [ "$WAN_PEER" = 0 ]; then
		run_profile short-lifetime 'pcp_min_lifetime_override=2' lease-short-lifetime-granted map-renewal-extends-expiry lease-expiry || test_status=1
		run_profile min-lifetime-only 'min_lifetime=2' lease-min-lifetime-without-option || test_status=1
	fi
fi

# The containers write their results as root; give the files back to the caller
# so the host-side runner below can update them.
for owned in status.md results-ipv4.json results-ipv6.json; do
	if [ -e "$RESULTS_DIR/$owned" ]; then
		"$DOCKER_BIN" run --rm --volume "$RESULTS_DIR:/pcp-wire-results:rw" \
			--entrypoint chown "$IMAGE" "$(id -u):$(id -g)" "/pcp-wire-results/$owned" || true
	fi
done
if [ -e "$DATA_DIR/status-data.json" ]; then
	"$DOCKER_BIN" run --rm --volume "$DATA_DIR:/pcp-wire-data:rw" \
		--entrypoint chown "$IMAGE" "$(id -u):$(id -g)" /pcp-wire-data/status-data.json || true
fi

# Cases that need to restart the daemon (the startup ANNOUNCE) run on the host:
# the fixture starts its own router containers with Docker.  Remove ours first so
# their networks cannot overlap with the fixture's.
if [ "${PCP_TEST_RESTART_CASES:-1}" = 1 ] && [ "$KEEP_CONTAINER" = 1 ]; then
	echo "Skipping the daemon-restart cases: PCP_TEST_KEEP_CONTAINER=1 keeps the networks they need." >&2
elif [ "${PCP_TEST_RESTART_CASES:-1}" = 1 ]; then
	if ! python3 -c 'import yaml' >/dev/null 2>&1; then
		echo "PyYAML is required on the host for the daemon-restart cases;" >&2
		echo "install python3-yaml or set PCP_TEST_RESTART_CASES=0 to skip them." >&2
		exit 2
	fi
	"$DOCKER_BIN" rm -f "$CONTAINER" "$PEER_CONTAINER" >/dev/null 2>&1 || true
	"$DOCKER_BIN" network rm "$WAN_NETWORK" >/dev/null 2>&1 || true
	"$DOCKER_BIN" network rm "$NETWORK" >/dev/null 2>&1 || true
	# Forward only the case and profile selection (their values are plain names).
	selection=
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--case|--profile)
			if [ "$#" -lt 2 ]; then break; fi
			selection="$selection $1 $2"
			shift
			;;
		esac
		shift
	done
	for restart_family in ipv4 ipv6; do
		# shellcheck disable=SC2086
		DOCKER=$DOCKER_BIN python3 "$SCRIPT_DIR/run_pcp_wire_cases.py" \
			--fixture "$SCRIPT_DIR/fixtures/docker.sh" --fixture-only --protocol pcp \
			--family "$restart_family" --platform linux --allow-empty-selection \
			--status-file "$RESULTS_DIR/status.md" \
			--status-data-file "$DATA_DIR/status-data.json" $selection || test_status=1
	done
fi
e2e_result "$test_status"
exit "$test_status"

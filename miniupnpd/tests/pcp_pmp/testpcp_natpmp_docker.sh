#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
DOCKER_BIN=${DOCKER:-docker}
IMAGE=${PCP_TEST_IMAGE:-miniupnpd-pcp-test:local}
CONTAINER=${PCP_TEST_CONTAINER:-miniupnpd-pcp-test-$$}
NETWORK=${PCP_TEST_NETWORK:-miniupnpd-pcp-net-$$}
WAN_NETWORK=$NETWORK-wan
PEER_CONTAINER=$CONTAINER-peer
WAN_PEER=${PCP_TEST_WAN_PEER:-0}
KEEP_CONTAINER=${PCP_TEST_KEEP_CONTAINER:-0}
CAPTURE=${PCP_TEST_CAPTURE:-1}
CAPTURE_DIR=${PCP_TEST_CAPTURE_DIR:-"$REPO_ROOT/.tmp/packet-captures"}
RESULTS_DIR=${PCP_TEST_RESULTS_DIR:-"$SCRIPT_DIR"}
CAPTURE_TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S.%N)

if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
	echo "Docker is required to run the PCP/NAT-PMP test environment." >&2
	exit 2
fi
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
mkdir -p "$RESULTS_DIR"
if [ "$CAPTURE" = 1 ]; then
	mkdir -p "$CAPTURE_DIR"
fi

"$DOCKER_BIN" build \
	--file "$SCRIPT_DIR/docker/Dockerfile" \
	--tag "$IMAGE" \
	"$REPO_ROOT"
if [ "$WAN_PEER" = 1 ]; then
	# IPv6 is routed through the fixture firewall, not translated by Docker.
	"$DOCKER_BIN" network create --driver bridge --ipv6 \
		--opt com.docker.network.bridge.gateway_mode_ipv6=routed \
		--subnet fd42:5351:5351::/64 "$NETWORK" >/dev/null
else
	"$DOCKER_BIN" network create --driver bridge --ipv6 \
		--subnet fd42:5351:5351::/64 "$NETWORK" >/dev/null
fi

if [ "$WAN_PEER" = 1 ]; then
	"$DOCKER_BIN" network create --driver bridge --ipv6 \
		--opt com.docker.network.bridge.gateway_mode_ipv6=routed \
		--subnet 198.51.100.0/24 --gateway 198.51.100.254 \
		--subnet fd42:5351:5352::/64 --gateway fd42:5351:5352::ff "$WAN_NETWORK" >/dev/null
	"$DOCKER_BIN" create --name "$CONTAINER" --network "$NETWORK" \
		--network-alias pcp-router --cap-add NET_ADMIN --env PCP_TEST_REAL_WAN=1 \
		--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 "$IMAGE" >/dev/null
	"$DOCKER_BIN" network connect --ip 198.51.100.1 --ip6 fd42:5351:5352::1 "$WAN_NETWORK" "$CONTAINER"
	"$DOCKER_BIN" start "$CONTAINER" >/dev/null
	"$DOCKER_BIN" create --name "$PEER_CONTAINER" --network "$NETWORK" \
		--cap-add NET_ADMIN --entrypoint python3 "$IMAGE" \
		/src/miniupnpd/tests/common/traffic_agent.py --host 0.0.0.0 \
		--source4 198.51.100.2 --source6 fd42:5351:5352::2 \
		--route6 fd42:5351:5351::/64 --gateway6 fd42:5351:5352::1 >/dev/null
	"$DOCKER_BIN" network connect --ip 198.51.100.2 --ip6 fd42:5351:5352::2 "$WAN_NETWORK" "$PEER_CONTAINER"
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
	--network-alias pcp-router \
	--cap-add NET_ADMIN \
	"$IMAGE"
fi

ready=0
attempt=0
while [ "$attempt" -lt 20 ]; do
	if "$DOCKER_BIN" run --rm --network "$NETWORK" \
		--entrypoint python3 "$IMAGE" \
		/src/miniupnpd/tests/pcp_pmp/testpcp_natpmp.py \
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
	set -- --host pcp-router --port 5351 --family "$test_family" \
		--status-file /pcp-pmp-results/status.md "$@"
	if [ "$test_family" = ipv6 ]; then
		set -- --protocol pcp --allow-empty-selection --append-status "$@"
	else
		set -- --mutating "$@"
	fi
	if [ "$WAN_PEER" = 1 ]; then
		set -- --peer-url "http://$PEER4:18080" "$@"
	fi
	if [ -n "${PCP_TEST_RESULTS_DIR:-}" ] || [ "$CAPTURE" = 0 ]; then
		set -- --results-file "/pcp-pmp-results/results-$test_family.json" "$@"
	fi
	if [ "$CAPTURE" = 1 ]; then
		set -- --capture-dir /pcp-pmp-captures --capture-interface eth0 "$@"
	fi
	if [ "$WAN_PEER" = 1 ]; then
		set -- --cap-add NET_ADMIN --env "PCP_TEST_ROUTER4=$ROUTER4" \
			--env "PCP_TEST_ROUTER6=$ROUTER6" --entrypoint sh "$IMAGE" \
			/pcp-pmp-tests/docker/client-entrypoint.sh "$@"
	else
		set -- --entrypoint python3 "$IMAGE" /pcp-pmp-tests/testpcp_natpmp.py "$@"
	fi
	set -- --volume "$SCRIPT_DIR:/pcp-pmp-tests:rw" \
		--volume "$RESULTS_DIR:/pcp-pmp-results:rw" \
		--env PYTHONDONTWRITEBYTECODE=1 "$@"
	if [ "$CAPTURE" = 1 ]; then
		set -- --cap-add NET_RAW \
			--env "PCP_TEST_CAPTURE_TIMESTAMP=$CAPTURE_TIMESTAMP" \
			--volume "$CAPTURE_DIR:/pcp-pmp-captures:rw" "$@"
	fi
	"$DOCKER_BIN" run --rm --network "$NETWORK" "$@"
}

test_status=0
run_tests ipv4 "$@" || test_status=1
run_tests ipv6 "$@" || test_status=1
exit "$test_status"

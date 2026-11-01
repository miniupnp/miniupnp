#!/bin/sh
# Check that miniupnpd sends its unsolicited PCP ANNOUNCE (224.0.0.1 and
# ff02::1, UDP port 5350) only on the LAN interface and never on the WAN.
#
# The announce is sent once at daemon start, before any test client can
# connect, so this cannot be a YAML case: the router container captures its
# own traffic from before miniupnpd starts and the result is checked here.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd)
DOCKER_BIN=${DOCKER:-docker}
IMAGE=${PCP_TEST_IMAGE:-miniupnpd-pcp-test:local}
CONTAINER=${PCP_TEST_CONTAINER:-miniupnpd-pcp-announce-$$}
NETWORK=${PCP_TEST_NETWORK:-miniupnpd-pcp-announce-net-$$}
WAN_NETWORK=$NETWORK-wan
KEEP_CONTAINER=${PCP_TEST_KEEP_CONTAINER:-0}
LOG=/tmp/announce.log

if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
	echo "Docker is required to run the PCP announce test." >&2
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
		fi
		"$DOCKER_BIN" rm -f "$CONTAINER" >/dev/null 2>&1 || true
		"$DOCKER_BIN" network rm "$WAN_NETWORK" >/dev/null 2>&1 || true
		"$DOCKER_BIN" network rm "$NETWORK" >/dev/null 2>&1 || true
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$DOCKER_BIN" build --file "$SCRIPT_DIR/docker/Dockerfile" --tag "$IMAGE" "$REPO_ROOT"
"$DOCKER_BIN" network create --driver bridge --ipv6 \
	--opt com.docker.network.bridge.gateway_mode_ipv6=routed \
	--subnet fd42:5351:5351::/64 "$NETWORK" >/dev/null
"$DOCKER_BIN" network create --driver bridge --ipv6 \
	--opt com.docker.network.bridge.gateway_mode_ipv6=routed \
	--subnet 198.51.100.0/24 --gateway 198.51.100.254 \
	--subnet fd42:5351:5352::/64 --gateway fd42:5351:5352::ff "$WAN_NETWORK" >/dev/null

# Capture every outgoing packet from UDP source port 5351 to destination port
# 5350 on all interfaces, starting before the entrypoint (and miniupnpd) runs.
# "-e" prints the interface name in "any" mode.
"$DOCKER_BIN" create --name "$CONTAINER" --network "$NETWORK" \
	--network-alias pcp-router --cap-add NET_ADMIN --cap-add NET_RAW \
	--env PCP_TEST_REAL_WAN=1 --env PCP_TEST_WAN_DEFAULT_ROUTE=1 \
	--env PCP_TEST_IPV6_LISTENING_IP=1 \
	--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
	--entrypoint sh "$IMAGE" -c \
	"tcpdump -i any -n -e -l -Q out 'udp and dst port 5350' >$LOG 2>&1 & \
	 sleep 1; exec /usr/local/bin/miniupnpd-test-entrypoint" >/dev/null
"$DOCKER_BIN" network connect --ip 198.51.100.1 --ip6 fd42:5351:5352::1 \
	"$WAN_NETWORK" "$CONTAINER"
"$DOCKER_BIN" start "$CONTAINER" >/dev/null

# Wait for the daemon to answer, then give the startup announce time to land.
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
	attempt=$((attempt + 1))
	sleep 1
done
if [ "$ready" -ne 1 ]; then
	echo "Docker PCP server did not become ready on UDP port 5351." >&2
	exit 1
fi
sleep 2

capture=$("$DOCKER_BIN" exec "$CONTAINER" cat "$LOG")
printf '%s\n' "$capture"

# tcpdump -e "any" lines look like: "... eth0 Out ifindex 5 ... 224.0.0.1.5350".
announces=$(printf '%s\n' "$capture" | grep -E '\.5351 > (224\.0\.0\.1|ff02::1)\.5350' || true)
status=0

check_sent() {
	if ! printf '%s\n' "$announces" | grep -q "$1.*$2"; then
		echo "FAIL: no ANNOUNCE to $2 on LAN interface $1" >&2
		status=1
	fi
}
# eth0 is the LAN interface after the entrypoint renames the WAN to wan0.
check_sent eth0 224.0.0.1
check_sent eth0 ff02::1

if printf '%s\n' "$announces" | grep -q 'wan0'; then
	echo "FAIL: ANNOUNCE sent on the external interface wan0:" >&2
	printf '%s\n' "$announces" | grep 'wan0' >&2
	status=1
fi

if [ "$status" -eq 0 ]; then
	echo "PASS: ANNOUNCE sent on the LAN interface only"
fi
exit "$status"

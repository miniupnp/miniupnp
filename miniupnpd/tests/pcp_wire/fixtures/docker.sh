#!/bin/sh
# Linux (Docker) fixture for the runner's daemon-restart and wan-renumber cases.
#
#   docker.sh supports CAPABILITY                 exit 0 for daemon-restart and wan-renumber
#   docker.sh daemon-restart DIRECTORY FAMILY
#   docker.sh wan-renumber-start DIRECTORY FAMILY
#   docker.sh wan-renumber-change DIRECTORY
#   docker.sh wan-renumber-stop DIRECTORY
#
# Each starts a fresh router container (WAN default route, as on a real gateway)
# whose entrypoint records outgoing PCP multicast on the LAN and WAN interfaces
# from before miniupnpd starts.
#
# daemon-restart waits for the startup announce and copies lan-0.pcap and
# wan-0.pcap into DIRECTORY.
#
# wan-renumber-start leaves the router running and prints its LAN address; the
# runner (on the host, which is on the LAN bridge) creates a mapping.
# wan-renumber-change moves the WAN address from .1 to .3 of the WAN /24.
# wan-renumber-stop copies the captures and the daemon log into DIRECTORY and
# removes the router.  The names of the router and its networks are kept in
# DIRECTORY/fixture.env between the commands.
#
# run-docker.sh builds what this needs and passes it: PCP_TEST_IMAGE, PCP_TEST_DAEMON_DIR.
set -eu

usage() {
	echo "usage: $0 supports CAPABILITY | daemon-restart DIRECTORY FAMILY |" >&2
	echo "       wan-renumber-start DIRECTORY FAMILY | wan-renumber-change DIRECTORY |" >&2
	echo "       wan-renumber-stop DIRECTORY" >&2
	exit 2
}

[ "$#" -ge 2 ] || usage
COMMAND=$1
DIRECTORY=$2
DOCKER_BIN=${DOCKER:-docker}
# the addresses of the run: run-docker.sh reserves PCP_TEST_SLOT
# shellcheck disable=SC1091
. "$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)/common/e2e_lib.sh"
e2e_address_plan "${PCP_TEST_SLOT:-1}"
IMAGE=${PCP_TEST_IMAGE:-}
TESTS=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)

case "$COMMAND" in
supports)
	case "$2" in
	daemon-restart|wan-renumber) exit 0 ;;
	*) exit 1 ;;
	esac
	;;
daemon-restart|wan-renumber-start) [ "$#" -eq 3 ] || usage ;;
wan-renumber-change|wan-renumber-stop) [ "$#" -eq 2 ] || usage ;;
*) usage ;;
esac

if [ "$COMMAND" = daemon-restart ] || [ "$COMMAND" = wan-renumber-start ]; then
	CONTAINER=${PCP_TEST_CONTAINER:-miniupnpd-pcp-restart-$$}
	NETWORK=miniupnpd-pcp-restart-net-$$
	WAN_NETWORK=$NETWORK-wan
else
	# shellcheck disable=SC1091
	. "$DIRECTORY/fixture.env"
fi

remove_router() {
	"$DOCKER_BIN" rm -f "$CONTAINER" >/dev/null 2>&1 || true
	"$DOCKER_BIN" network rm "$WAN_NETWORK" >/dev/null 2>&1 || true
	"$DOCKER_BIN" network rm "$NETWORK" >/dev/null 2>&1 || true
}

# On a failure: show the daemon's log and remove the router.  wan-renumber-start
# and -change keep it on success, for the next command.
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$status" -ne 0 ]; then
		"$DOCKER_BIN" logs "$CONTAINER" >&2 2>/dev/null || true
	fi
	if [ "$status" -ne 0 ] || [ "$KEEP_ROUTER" = 0 ]; then
		remove_router
	fi
	exit "$status"
}
KEEP_ROUTER=0
case "$COMMAND" in wan-renumber-start|wan-renumber-change) KEEP_ROUTER=1 ;; esac
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_router() {
	"$DOCKER_BIN" network create --driver bridge --ipv6 \
		--opt com.docker.network.bridge.gateway_mode_ipv6=routed \
		--subnet "$LAN4.0/24" --gateway "$LAN4.254" --subnet "$LAN6_PREFIX::/64" "$NETWORK" >/dev/null
	"$DOCKER_BIN" network create --driver bridge --ipv6 \
		--opt com.docker.network.bridge.gateway_mode_ipv6=routed \
		--subnet $WAN4.0/24 --gateway $WAN4.254 \
		--subnet $WAN6_PREFIX::/64 --gateway $WAN6_PREFIX::ff "$WAN_NETWORK" >/dev/null
	"$DOCKER_BIN" create --name "$CONTAINER" --network "$NETWORK" \
		--network-alias pcp-router --env "PCP_TEST_WAN4=$WAN4" --env "PCP_TEST_WAN6_PREFIX=$WAN6_PREFIX" --cap-add NET_ADMIN --cap-add NET_RAW \
		--env PCP_TEST_REAL_WAN=1 --env PCP_TEST_WAN_DEFAULT_ROUTE=1 \
		--env PCP_TEST_IPV6_LISTENING_IP=1 --env PCP_TEST_CAPTURE_DIR=/capture \
		--volume "${PCP_TEST_DAEMON_DIR:?}:/opt/miniupnpd:ro" \
		--sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
		"$IMAGE" >/dev/null
	"$DOCKER_BIN" network connect --ip $WAN4.1 --ip6 $WAN6_PREFIX::1 \
		"$WAN_NETWORK" "$CONTAINER"
	"$DOCKER_BIN" start "$CONTAINER" >/dev/null

	# Wait for the daemon to answer.
	ready=0
	attempt=0
	while [ "$attempt" -lt 20 ]; do
		if "$DOCKER_BIN" run --rm --network "$NETWORK" --volume "$TESTS:/pcp-tests:ro" \
			--entrypoint python3 "$IMAGE" \
			/pcp-tests/pcp_wire/run_pcp_wire_cases.py \
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
}

# Flush the captures (tcpdump writes the pcap trailer on SIGINT), then copy out.
copy_captures() {
	"$DOCKER_BIN" exec "$CONTAINER" pkill -INT tcpdump || true
	sleep 1
	mkdir -p "$DIRECTORY"
	"$DOCKER_BIN" cp "$CONTAINER:/capture/." "$DIRECTORY"
}

case "$COMMAND" in
daemon-restart)
	start_router
	sleep 6         # give the startup announce time to land
	copy_captures
	;;
wan-renumber-start)
	mkdir -p "$DIRECTORY"
	printf 'CONTAINER=%s\nNETWORK=%s\nWAN_NETWORK=%s\n' "$CONTAINER" "$NETWORK" "$WAN_NETWORK" \
		>"$DIRECTORY/fixture.env"
	start_router
	sleep 2         # let the startup announce pass before the mapping is created
	if [ "$3" = ipv6 ]; then
		format="{{(index .NetworkSettings.Networks \"$NETWORK\").GlobalIPv6Address}}"
	else
		format="{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}"
	fi
	"$DOCKER_BIN" inspect -f "$format" "$CONTAINER"
	;;
wan-renumber-change)
	# Delete first: a second address in the same subnet would be a secondary one,
	# which Linux removes with the primary (without promote_secondaries).
	"$DOCKER_BIN" exec "$CONTAINER" sh -c "
		ip address del $WAN4.1/24 dev wan0 &&
		ip address add $WAN4.3/24 dev wan0 &&
		ip route replace default via $WAN4.254 dev wan0"
	;;
wan-renumber-stop)
	copy_captures || true
	"$DOCKER_BIN" logs "$CONTAINER" >"$DIRECTORY/daemon.log" 2>&1 || true
	;;
esac

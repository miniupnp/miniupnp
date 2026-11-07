#!/bin/sh
set -eu
# Return WAN traffic through the disposable router rather than Docker's host.
if [ -n "${PCP_TEST_ROUTER4:-}" ]; then
	ip route replace "$PCP_TEST_WAN4.0/24" via "$PCP_TEST_ROUTER4" dev eth0
	ip -6 route replace "$PCP_TEST_WAN6_PREFIX::/64" via "$PCP_TEST_ROUTER6" dev eth0
fi
# A second LAN address for the cases with a second client (the runner's --second-client).
if [ -n "${PCP_TEST_SECOND_CLIENT_CIDR:-}" ]; then
	case "$PCP_TEST_SECOND_CLIENT_CIDR" in
	*:*) ip -6 address add "$PCP_TEST_SECOND_CLIENT_CIDR" dev eth0 nodad ;;
	*) ip address add "$PCP_TEST_SECOND_CLIENT_CIDR" dev eth0 ;;
	esac
fi
exec python3 /pcp-tests/pcp_wire/run_pcp_wire_cases.py "$@"

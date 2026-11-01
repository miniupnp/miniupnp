#!/bin/sh
set -eu
# Return WAN traffic through the disposable router rather than Docker's host.
ip route replace 198.51.100.0/24 via "$PCP_TEST_ROUTER4" dev eth0
ip -6 route replace fd42:5351:5352::/64 via "$PCP_TEST_ROUTER6" dev eth0
exec python3 /pcp-pmp-tests/testpcp_natpmp.py "$@"

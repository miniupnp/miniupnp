#!/bin/sh
# run-freebsd.sh with a Debian VM running miniupnpd with iptables as the router: the same
# fixture, cases and options. The LAN client and the WAN agents are Docker containers on the
# host, and there is no Docker in the VM. A VM has its own kernel, so the host does not need
# the modules of the legacy iptables tables, which miniupnpd uses through libiptc.
PCP_E2E_ROUTER=debian-iptables
export PCP_E2E_ROUTER
exec sh "$(dirname -- "$0")/run-freebsd.sh" "$@"

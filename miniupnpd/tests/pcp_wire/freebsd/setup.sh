#!/bin/sh
# Runs inside the FreeBSD VM as root, from the repository root.
#
# Builds miniupnpd with pf, the PCP lease file and PCP PEER (as the Docker
# image) and creates a router topology out of epair(4)
# pairs (WAN + two LANs, default route out of the WAN).  daemon-restart.sh
# then starts the daemon on it.  The "b" end of each pair stands in for the
# remote host, so capturing on it shows exactly what miniupnpd transmitted on
# the "a" end.
set -eu

WORK=/tmp/pcp-fixture
. "$(dirname -- "$0")/../../common/freebsd_lib.sh"
rm -rf "$WORK"
mkdir -p "$WORK"

# gmake, pkgconf and (on FreeBSD 15) a static libpfctl plus its header come
# from the prepared VM image.
PEER_OPTION=$(freebsd_peer_option)
(cd miniupnpd && ./configure --firewall=pf --ipv6 --leasefile $PEER_OPTION --disable-tests >/dev/null \
	&& freebsd_link_pfctl \
	&& CPPFLAGS="-DPCP_ANNOUNCE_COUNT=5" make -f Makefile.bsd >"$WORK/build.log" 2>&1) || {
	tail -40 "$WORK/build.log" >&2
	echo "FAIL: build" >&2
	exit 1
}

kldload -n if_epair || true
kldload -n pf || true
# A pair is named after its "a" end (epair0a / epair0b): destroying epair0a removes the
# pair an earlier run in this VM left (ci.sh runs once per daemon tree).
for n in 0 1 2; do
	ifconfig epair${n}a destroy >/dev/null 2>&1 || true
	ifconfig epair$n create >/dev/null
done
# epair0 = LAN1, epair1 = LAN2, epair2 = WAN
ifconfig epair0a up
ifconfig epair0a inet 192.168.1.1/24
ifconfig epair0a inet6 fd42:1::1/64
ifconfig epair0b up
ifconfig epair1a up
ifconfig epair1a inet 192.168.2.1/24
ifconfig epair1a inet6 fd42:2::1/64
ifconfig epair1b up
ifconfig epair2a up
ifconfig epair2a inet 198.51.100.1/24
ifconfig epair2a inet6 fd42:3::1/64
ifconfig epair2b up
ifconfig epair2b inet 198.51.100.2/24
ifconfig epair2b inet6 fd42:3::2/64
sleep 3 # let IPv6 DAD finish

freebsd_clear_default_routes

# Like a real router, send the default route out of the WAN so multicast
# without an explicit output interface would leave through it.
route -n add -net default 198.51.100.2 >/dev/null 2>&1 \
	|| route -n change -net default 198.51.100.2
route -n add -inet6 default fd42:3::2 >/dev/null 2>&1 \
	|| route -n change -inet6 default fd42:3::2

# nat-anchor: the NAT rules of the PCP PEER mappings are in the anchor
cat >"$WORK/pf.conf" <<'PF'
nat-anchor "miniupnpd"
rdr-anchor "miniupnpd"
anchor "miniupnpd"
pass all
PF
pfctl -F all >/dev/null 2>&1 || true
pfctl -e >/dev/null 2>&1 || true
pfctl -f "$WORK/pf.conf"

cat >"$WORK/miniupnpd.conf" <<'CONF'
ext_ifname=epair2a
ext_allow_private_ipv4=yes
listening_ip=epair0a
listening_ip=epair1a
enable_upnp=no
enable_pcp_pmp=yes
max_lifetime=600
secure_mode=yes
allow 1024-65535 0.0.0.0/0 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
CONF

echo "FreeBSD fixture ready"

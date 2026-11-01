#!/bin/sh
# Runs inside the FreeBSD VM as root, from the repository root.
#
# Builds miniupnpd with pf, creates a router topology out of epair(4) pairs
# (WAN + two LANs, default route out of the WAN) and checks that the startup
# PCP ANNOUNCE (224.0.0.1 / ff02::1, UDP port 5350) is seen on both LANs and
# never on the WAN.  The "b" end of each pair stands in for the remote host,
# so capturing on it shows exactly what miniupnpd transmitted on the "a" end.
set -eu

WORK=/tmp/announce-test
rm -rf "$WORK"
mkdir -p "$WORK"

pkg install -y gmake pkgconf >/dev/null 2>&1 || true
(cd miniupnpd && ./configure --firewall=pf --ipv6 --disable-tests >/dev/null \
	&& make -f Makefile.bsd >"$WORK/build.log" 2>&1) || {
	tail -40 "$WORK/build.log" >&2
	echo "FAIL: build" >&2
	exit 1
}

kldload -n if_epair || true
kldload -n pf || true
for n in 0 1 2; do
	ifconfig epair$n destroy >/dev/null 2>&1 || true
	ifconfig epair$n create >/dev/null
done
# epair0 = LAN1, epair1 = LAN2, epair2 = WAN
ifconfig epair0a inet 192.168.1.1/24 inet6 fd42:1::1/64 up
ifconfig epair0b up
ifconfig epair1a inet 192.168.2.1/24 inet6 fd42:2::1/64 up
ifconfig epair1b up
ifconfig epair2a inet 198.51.100.1/24 inet6 fd42:3::1/64 up
ifconfig epair2b inet 198.51.100.2/24 inet6 fd42:3::2/64 up
sleep 3 # let IPv6 DAD finish

# Like a real router, send the default route out of the WAN so multicast
# without an explicit output interface would leave through it.
route -n add -net default 198.51.100.2 >/dev/null 2>&1 \
	|| route -n change -net default 198.51.100.2
route -n add -inet6 default fd42:3::2 >/dev/null 2>&1 \
	|| route -n change -inet6 default fd42:3::2

cat >"$WORK/pf.conf" <<'PF'
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
CONF

for n in 0 1 2; do
	tcpdump -i epair${n}b -n -l -Q in "udp and dst port 5350" \
		>"$WORK/epair${n}b.log" 2>&1 &
	echo $! >>"$WORK/tcpdump.pids"
done
sleep 1

miniupnpd/miniupnpd -d -f "$WORK/miniupnpd.conf" >"$WORK/miniupnpd.log" 2>&1 &
echo $! >"$WORK/miniupnpd.pid"
sleep 5
kill "$(cat "$WORK/miniupnpd.pid")" 2>/dev/null || true
kill $(cat "$WORK/tcpdump.pids") 2>/dev/null || true
sleep 1

status=0
announces() { grep -E '\.5351 > (224\.0\.0\.1|ff02::1)\.5350' "$WORK/$1.log" || true; }
expect_on_lan() {
	if ! announces "$1" | grep -q "$2"; then
		echo "FAIL: no ANNOUNCE to $2 on LAN interface ${1%b}a" >&2
		status=1
	fi
}
for lan in epair0b epair1b; do
	expect_on_lan $lan 224.0.0.1
	expect_on_lan $lan ff02::1
done
if [ -n "$(announces epair2b)" ]; then
	echo "FAIL: ANNOUNCE sent on the external interface epair2a:" >&2
	announces epair2b >&2
	status=1
fi

if [ "$status" -ne 0 ]; then
	echo "--- miniupnpd.log" >&2
	cat "$WORK/miniupnpd.log" >&2
	for n in 0 1 2; do echo "--- epair${n}b" >&2; cat "$WORK/epair${n}b.log" >&2; done
else
	echo "PASS: ANNOUNCE sent on the LAN interfaces only"
fi
exit "$status"

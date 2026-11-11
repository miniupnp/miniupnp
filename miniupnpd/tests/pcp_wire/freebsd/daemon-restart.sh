#!/bin/sh
# Runs inside the FreeBSD VM as root, from the repository root, after setup.sh.
#
# Cold-starts miniupnpd while capturing what each epair "b" end receives, and
# leaves lan-0.pcap, lan-1.pcap (the LANs) and wan-0.pcap (the WAN) in
# /tmp/pcp-restart for the host runner to judge.
set -eu

WORK=/tmp/pcp-fixture
OUT=/tmp/pcp-restart
rm -rf "$OUT"
mkdir -p "$OUT"
: >"$OUT/tcpdump.pids"

capture() { # interface file
	tcpdump -i "$1" -n -U -Q in -w "$OUT/$2" "udp and dst port 5350" \
		>"$OUT/$2.err" 2>&1 &
	echo $! >>"$OUT/tcpdump.pids"
}
capture epair0b lan-0.pcap
capture epair1b lan-1.pcap
capture epair2b wan-0.pcap
sleep 1

miniupnpd/miniupnpd -d -f "$WORK/miniupnpd.conf" >"$OUT/miniupnpd.log" 2>&1 &
daemon=$!
sleep 8
kill "$daemon" 2>/dev/null || true
kill $(cat "$OUT/tcpdump.pids") 2>/dev/null || true
sleep 1

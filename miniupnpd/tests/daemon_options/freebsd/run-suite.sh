#!/bin/sh
# Runs inside the FreeBSD VM as root, from the daemon tree: the daemon_options corpus on pf.
#
#   run-suite.sh RESULTS_DIR
#
# The topology, with epair(4) and vnet jails that share the root filesystem (as pcp_wire/freebsd):
#   bridge0 LAN 172.28.41.1: jail client (.2), jail neighbour (.3, an HTTP server)
#   bridge1 WAN 198.51.100.1: jail wan (.3, the runner; .5, the STUN server)
# The runner cannot run on the router: the daemon ignores a sender it routes through lo0.
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 RESULTS_DIR" >&2; exit 2; }
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
RESULTS=$(CDPATH='' cd -- "$1" && pwd)
RUNNER=$HERE/run_daemon_options_cases.py
WORK=/tmp/daemon-options
LOG=$WORK/miniupnpd.log
CALLS=$WORK/calls
LAN4=172.28.41 LAN6=2001:db8:1:: WAN4=198.51.100 WAN6=2001:db8:9000::
LEASES="/var/tmp/miniupnpd.leases /var/tmp/miniupnpd.leases6 /var/tmp/other.leases /var/tmp/pinholes.leases"
STATUS=0
rm -rf "$WORK"
mkdir -p "$CALLS"
. "$HERE/../common/freebsd_lib.sh"
. "$HERE/../common/e2e_lib.sh"

# the build of run-docker.sh, as pcp_e2e builds it: PCP PEER only where pf supports it, and no
# PF_ENABLE_FILTER_RULES (pf/obsdrdr.c does not compile with it, so queue, quickrules and the
# STUN filter test fail)
peer=$(freebsd_peer_option)     # reads miniupnpd/pcpserver.c, so before the cd
(cd miniupnpd && ./configure --firewall=pf --ipv6 --leasefile $peer --igd2 --vendorcfg --https --disable-tests >/dev/null \
	&& freebsd_link_pfctl \
	&& { grep -q lssl bsdmake.inc || echo 'LIBS += -lssl -lcrypto' >> bsdmake.inc; } \
	&& make -f Makefile.bsd >"$WORK/build.log" 2>&1) || {
	tail -40 "$WORK/build.log" >&2
	echo "FAIL: build" >&2
	exit 1
}
mkdir -p /etc/miniupnpd
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=router -days 2 \
	-keyout /etc/miniupnpd/private-key.pem -out /etc/miniupnpd/certificate.pem 2>/dev/null

CALL_LOOP=
cleanup() {
	result=$?
	trap - EXIT INT TERM
	[ -z "$CALL_LOOP" ] || kill "$CALL_LOOP" 2>/dev/null || true
	pkill -x miniupnpd 2>/dev/null || true
	for name in client neighbour wan; do jail -r "$name" >/dev/null 2>&1 || true; done
	exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

kldload -n if_epair if_bridge pf || true
ifconfig epair0 create >/dev/null
ifconfig epair1 create >/dev/null
ifconfig epair2 create >/dev/null
ifconfig bridge0 create >/dev/null
ifconfig bridge1 create >/dev/null
ifconfig bridge0 addm epair0a addm epair1a up
ifconfig bridge1 addm epair2a up
ifconfig epair0a up
ifconfig epair1a up
ifconfig epair2a up
ifconfig bridge0 inet "$LAN4.1/24"
ifconfig bridge0 inet6 "${LAN6}1/64"
ifconfig bridge1 inet "$WAN4.1/24"
ifconfig bridge1 inet6 "${WAN6}1/64"
sysctl net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1 >/dev/null
# pf sees the bridge, where the rules of the daemon are, not its members
sysctl net.link.bridge.pfil_member=0 net.link.bridge.pfil_bridge=1 >/dev/null
freebsd_make_jail client epair0b "$LAN4.2" "${LAN6}2" "$LAN4.1" "${LAN6}1"
freebsd_make_jail neighbour epair1b "$LAN4.3" "${LAN6}3" "$LAN4.1" "${LAN6}1"
freebsd_make_jail wan epair2b "$WAN4.3" "${WAN6}3" "$WAN4.1" "${WAN6}1"
jexec wan ifconfig epair2b inet "$WAN4.5/32" alias
sleep 3 # let IPv6 DAD finish

# the VM's own default routes would win over the WAN; SSH keeps the connected route
freebsd_clear_default_routes
route -n add -net default "$WAN4.3" >/dev/null
route -n add -inet6 default "${WAN6}3" >/dev/null

mkdir -p "$WORK/srv"
echo neighbour-served >"$WORK/srv/index.html"
# not http.server: HTTPServer looks up the name of its address before listen(), and a jail has no DNS
jexec neighbour sh -c "cd $WORK/srv && exec python3 -c \"
import http.server, socketserver
socketserver.TCPServer(('$LAN4.3', 45300), http.server.SimpleHTTPRequestHandler).serve_forever()\"" >/dev/null 2>&1 &
jexec wan python3 "$HERE/stun_server.py" >/dev/null 2>&1 &
attempt=0
until jexec client fetch -q -T 1 -o /dev/null "http://$LAN4.3:45300/" 2>/dev/null; do
	attempt=$((attempt + 1))
	[ "$attempt" -lt 100 ] || { echo "FAIL: the neighbour's HTTP server did not start" >&2; exit 1; }
	sleep 0.1
done

cat >"$WORK/pf.conf" <<'PF'
nat-anchor "miniupnpd"
rdr-anchor "miniupnpd"
block in on bridge1 all
pass in quick on bridge1 inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }
anchor "miniupnpd"
pass in on bridge0 all keep state
pass out all keep state
PF
pfctl -F all >/dev/null 2>&1 || true
pfctl -e >/dev/null 2>&1 || true
pfctl -f "$WORK/pf.conf"

cat >"$WORK/base.conf" <<'CONF'
ext_ifname=bridge1
ext_allow_private_ipv4=yes
listening_ip=bridge0
enable_upnp=no
enable_pcp_pmp=yes
lease_file=/var/tmp/miniupnpd.leases
max_lifetime=600
secure_mode=yes
allow 1024-65535 0.0.0.0/0 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
CONF

listening() { grep -Ec 'Listening for|HTTP listening' "$LOG" || true; }

# start_process: the daemon of $WORK/opt.conf; ready at a listening line it wrote after this call.
# The rules go, as after a reboot, and the lease file stays.
start_process() {
	pkill -x miniupnpd 2>/dev/null || true
	sleep 0.3
	for anchor in miniupnpd optanchor; do pfctl -a "$anchor" -F all >/dev/null 2>&1 || true; done
	before=$(listening)
	miniupnpd/miniupnpd -d -f "$WORK/opt.conf" >>"$LOG" 2>&1 &
	process=$!
	attempt=0
	while [ "$attempt" -lt 150 ]; do
		kill -0 "$process" 2>/dev/null || return 1
		if [ "$(listening)" -gt "$before" ]; then sleep 0.5; return 0; fi
		attempt=$((attempt + 1))
		sleep 0.1
	done
	return 1
}

router_call() {
	case $1 in
		ruleset) pfctl -a 'miniupnpd/*' -sn; pfctl -a 'miniupnpd/*' -sr ;;
		ruleset:*) pfctl -a "${1#ruleset:}" -sn; pfctl -a "${1#ruleset:}" -sr ;;
		log) cat "$LOG" ;;
		cat:*) cat "$(printf '%s' "${1#cat:}" | sed 's#/var/lib/miniupnpd#/var/tmp#')" ;;
		restart) start_process && echo restarted ;;
		# a reload of the firewall: the rules are gone, and the daemon is not told
		# (the rules are in the anchor itself, or in child anchors of it)
		firewall-flush)
			for child in $(pfctl -a miniupnpd -sA); do pfctl -a "$child" -F all; done >/dev/null 2>&1
			pfctl -a miniupnpd -F all >/dev/null 2>&1
			echo flushed ;;
		wan-reserved) echo changed ;;	# the WAN of this fixture is reserved already
		wan-probe:*) jexec wan python3 -c "
import urllib.request
try:
    print(urllib.request.urlopen('http://$WAN4.1:${1#wan-probe:}/', timeout=5).read().decode())
except OSError as error:
    print('no connection', error)" ;;
		*) echo "unknown router command: $1" ;;
	esac
}

(
	while :; do
		e2e_serve_router_calls "$CALLS" || sleep 0.05
	done
) &
CALL_LOOP=$!

# start_daemon CONFIG-WORD...: the base configuration with these lines in place of its own
start_daemon() {
	anchor=miniupnpd
	pkill -x miniupnpd 2>/dev/null || true
	# a daemon with PCP lease records keeps them in FILE.pcp beside each lease file
	for lease in $LEASES; do rm -f "$lease" "$lease.pcp"; done
	: >"$LOG"
	: >"$WORK/extra.conf"
	for word in "$@"; do
		line=$(printf '%s' "$word" | tr + ' ' | sed -e "s/@WAN4@/$WAN4/g" -e "s/@LAN4@/$LAN4/g" -e "s/@LAN6@/$LAN6/g" \
			-e 's/eth0/bridge0/g' -e 's#/var/lib/miniupnpd#/var/tmp#g')
		[ "${line%%=*}" != anchor ] || anchor=${line#*=}
		printf '%s\n' "$line" >>"$WORK/extra.conf"
	done
	# the lines replace the base lines of the same option, as PCP_TEST_CONF_REPLACE does on Docker
	awk -f "$HERE/../common/docker/conf_replace.awk" "$WORK/extra.conf" "$WORK/base.conf" >"$WORK/opt.conf"
	grep -v '=@OFF@$' "$WORK/extra.conf" >>"$WORK/opt.conf" || true
	# the main ruleset calls the anchor of this configuration
	sed -i '' -E "s/anchor \"[^\"]*\"/anchor \"$anchor\"/" "$WORK/pf.conf"
	pfctl -f "$WORK/pf.conf"
	start_process
}

case_args=
for selected in ${DAEMON_OPTIONS_CASES:-}; do case_args="$case_args --case $selected"; done
# shellcheck disable=SC2086
runs=$(python3 "$RUNNER" --list-runs --platform freebsd $case_args)
active=-
while read -r side family config; do
	[ -n "$side" ] || continue
	if [ "$config" != "$active" ]; then
		active=$config
		echo "=== daemon: ${config:-fixture defaults}"
		down=
		# shellcheck disable=SC2086
		start_daemon $config || down=--daemon-down
	fi
	if [ "$side" = lan ]; then jail=client host4=$LAN4.1 host6=${LAN6}1
	else jail=wan host4=$WAN4.1 host6=${WAN6}1; fi
	host=$host4
	[ "$family" = ipv4 ] || host=$host6
	set --
	for word in $config; do set -- "$@" --config "$word"; done
	# shellcheck disable=SC2086
	jexec "$jail" env PYTHONDONTWRITEBYTECODE=1 python3 "$RUNNER" --router-call-dir "$CALLS" $down $case_args \
		--host "$host" --family "$family" --side "$side" --platform freebsd \
		--status-file "$RESULTS/status.md" --status-data-file "$RESULTS/status-data.json" \
		--run-info "daemon=${DAEMON_OPTIONS_DAEMON:-unknown}" --run-info "router=FreeBSD pf" "$@" </dev/null || STATUS=1
done <<EOF
$runs
EOF
cp "$LOG" "$RESULTS/miniupnpd-last.log" 2>/dev/null || true
exit "$STATUS"

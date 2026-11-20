#!/bin/sh
# Runs inside the FreeBSD or OpenBSD VM as root, from the repository root: everything the
# host driver (../run-freebsd.sh, ../run-openbsd.sh) does to the pf router.
#
#   pf-router.sh setup         build + net + start, from a clean work directory
#   pf-router.sh build [OPTIONS]  configure (extra OPTIONS, default --igd2 --pcp-peer) and make miniupnpd
#   pf-router.sh net [LAN4 LAN6 WAN4 WAN6]  configure the LAN and WAN NICs and the main pf ruleset;
#                              the address plan of the fixture slot (run-freebsd.sh --slot), as
#                              e2e_address_plan sets it (172.28.1 2001:db8:1:1:: 6.18.1 2001:db8:9000:1::)
#   pf-router.sh start [CONF]  start the daemon from a clean state (anchor, states, NAT66, leases);
#                              CONF: extra miniupnpd.conf lines, separated by commas
#                              (pcp_wire/run-openbsd.sh: enable_upnp=no)
#   pf-router.sh stop          stop the daemon
#   pf-router.sh nat66 on|off  NAT for IPv6 on the WAN, for the sections which need it
#   pf-router.sh restart       stop the daemon, flush its anchor, start it again
#   pf-router.sh rules PORTS   the rules of the miniupnpd anchor for the internal ports PORTS (an
#                              extended regular expression, 43333|44444), without the creation
#                              time and the pinhole number in their labels (ts-N, pinhole-N); what the restart check compares
#   pf-router.sh snapshot      print the router state, for the per-case snapshots
#   pf-router.sh capture start|stop   tcpdump on the LAN and WAN NICs into /tmp/pcp-e2e/cap-*.pcap
#   pf-router.sh pf-make       build the development test programs of miniupnpd/pf
#
# The first NIC is QEMU's management NIC (ssh): vtnet0 on FreeBSD, vio0 on OpenBSD. The
# second (LAN) and third (WAN) are relayed onto the Linux Docker LAN and WAN bridges, where
# the client and the traffic agents live.
#
# OpenBSD translates in the filter rules (rdr-to, nat-to, since 4.7): its main ruleset has
# no rdr-anchor and no nat-anchor, and the daemon puts pass ... rdr-to rules in its anchor.
set -u

OS=$(uname)
if [ "$OS" = OpenBSD ]; then LAN_IF=vio1; WAN_IF=vio2; else LAN_IF=vtnet1; WAN_IF=vtnet2; fi

WORK=/tmp/pcp-e2e
. "$(dirname -- "$0")/../../common/freebsd_lib.sh"
PF=$WORK/pf.conf

write_pf() {
	if [ "$OS" = OpenBSD ]; then write_pf_openbsd "${1:-off}"; return; fi
	{
		# PCP PEER NAT rules live in the anchor and must be evaluated first
		echo 'nat-anchor "miniupnpd"'
		# a 15.1 kernel lets a later rule override a match in an anchor : the
		# generic rule must not match what the anchor translated
		echo 'nat on vtnet2 inet from any to any ! tagged miniupnpd -> (vtnet2)'
		# NAT66 like the nft masquerade of the Docker fixture: the global WAN
		# address (the pool of "(vtnet2)" includes the link-local fe80::
		# address) and the source port kept (without static-port, pf NAT picks
		# a random port from 50001). The address is the one of the slot.
		if [ "${1:-off}" = on ]; then
			wan6=$(ifconfig vtnet2 inet6 | awk '$1 == "inet6" && $2 !~ /^fe80:/ { print $2; exit }')
			echo "nat on vtnet2 inet6 from any to any -> $wan6 static-port"
		fi
		cat <<'PF'
rdr-anchor "miniupnpd"
block in on vtnet2 all
pass in quick on vtnet2 inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }
anchor "miniupnpd"
pass in on vtnet1 all keep state
pass out all keep state
PF
	} >"$PF"
	pfctl -f "$PF"
}

# NAT44 and NAT66 as on FreeBSD, with match ... nat-to; the anchor holds the pass ... rdr-to
# rules of the mappings.
write_pf_openbsd() {
	{
		echo "match out on $WAN_IF inet from !($WAN_IF) nat-to ($WAN_IF)"
		if [ "${1:-off}" = on ]; then
			wan6=$(ifconfig $WAN_IF inet6 | awk '$1 == "inet6" && $2 !~ /^fe80:/ { print $2; exit }')
			echo "match out on $WAN_IF inet6 from !($WAN_IF) nat-to $wan6 static-port"
		fi
		cat <<PF
block in on $WAN_IF all
pass in quick on $WAN_IF inet6 proto icmp6 icmp6-type { neighbrsol, neighbradv }
anchor "miniupnpd"
pass in on $LAN_IF all keep state
pass out all keep state
PF
	} >"$PF"
	pfctl -f "$PF"
}

# is the daemon listening on its PCP port?
pcp_listening() {
	if [ "$OS" = OpenBSD ]; then
		netstat -an -f inet -p udp | grep -q '\.5351 '
	else
		sockstat -4l | grep -q ':5351'
	fi
}

# the rules are in child anchors of miniupnpd, and its own rules send packets there
flush_anchor() {
	for child in $(pfctl -a miniupnpd -sA 2>/dev/null); do
		pfctl -a "$child" -F all >/dev/null 2>&1 || true
	done
	pfctl -a miniupnpd -F all >/dev/null 2>&1 || true
}

# A host name of a WAN peer, which the daemon resolves with the system resolver.
cmd_host() {
	sed -i.bak "/ ${1:?name}\$/d" /etc/hosts
	for address in "$2" "$3"; do
		echo "$address $1" >>/etc/hosts
	done
}

cmd_lose_rules() {
	count() {
		for anchor in miniupnpd $(pfctl -a miniupnpd -sA 2>/dev/null); do
			pfctl -a "$anchor" -sn 2>/dev/null
			pfctl -a "$anchor" -sr 2>/dev/null
		done | grep -c .
	}
	before=$(count)
	flush_anchor
	echo "$before $(count)"
}

# restart : a cold start of the daemon, the rules of its anchor are lost, as after a
# reboot. restart keep : a restart of the service, the rules stay in the firewall.
cmd_restart() {
	set -e
	kill "$(cat "$WORK/miniupnpd.pid")" 2>/dev/null || true
	sleep 2
	[ "${1:-}" = keep ] || flush_anchor
	nohup miniupnpd/miniupnpd -d -f "$WORK/miniupnpd.conf" >>"$WORK/miniupnpd.log" 2>&1 &
	echo $! >"$WORK/miniupnpd.pid"
	sleep 3
	kill -0 "$(cat "$WORK/miniupnpd.pid")" || { echo "FAIL: daemon" >&2; exit 1; }
}

cmd_rules() {
	freebsd_rules_normalised "${1:?ports}"
}

cmd_snapshot() {
	echo "=== miniupnpd process ==="; ps -ww -p "$(cat "$WORK/miniupnpd.pid")" -o pid,command
	echo "=== miniupnpd configuration ==="; cat "$WORK/miniupnpd.conf"
	echo "=== interfaces ==="; ifconfig
	echo "=== routes ==="; netstat -rn
	echo "=== pf main rules ==="; pfctl -vsn 2>&1; pfctl -vsr 2>&1
	echo "=== pf miniupnpd anchor ==="; pfctl -a 'miniupnpd/*' -vsn 2>&1; pfctl -a 'miniupnpd/*' -vsr 2>&1
	echo "=== pf states ==="; pfctl -ss 2>&1
	echo "=== lease file ==="; cat /var/tmp/miniupnpd.leases 2>/dev/null || echo "(none)"
	echo "=== lease file6 ==="; cat /var/tmp/miniupnpd.leases6 2>/dev/null || echo "(none)"
}

cmd_capture() {
	case "${1:-}" in
	start)
		rm -f "$WORK"/cap-*.pcap "$WORK/cap.pids"
		# OpenBSD's tcpdump has no -U: the capture is whole once it is stopped
		unbuffered=-U; [ "$OS" = OpenBSD ] && unbuffered=
		for i in $LAN_IF $WAN_IF; do
			nohup tcpdump $unbuffered -n -i $i -s 0 -w "$WORK/cap-$i.pcap" >"$WORK/cap-$i.log" 2>&1 </dev/null &
			echo $! >>"$WORK/cap.pids"
		done
		sleep 1
		;;
	stop)
		kill -INT $(cat "$WORK/cap.pids") 2>/dev/null
		sleep 1
		;;
	*) echo "usage: $0 capture start|stop" >&2; exit 2 ;;
	esac
}

# The Makefile of miniupnpd/pf always links -lpfctl, which only FreeBSD 15 has (in
# /usr/lib/private on 14): without it the programs are linked without the library, with
# the ioctl interface of pf like the daemon. Run after setup, which ran configure.
cmd_pf_make() {
	pfctl_dir=$(dirname "$(ls /usr/lib/private/libpfctl.* 2>/dev/null | head -n 1)")
	cd miniupnpd/pf || exit 1
	make clean >/dev/null 2>&1
	if [ "$pfctl_dir" = . ]; then
		make LIBS="" 2>&1
	else
		make LDFLAGS="-L$pfctl_dir -Wl,-rpath,$pfctl_dir" LIBS="-lpfctl -lnv" 2>&1
	fi
	echo "make exit status: $?"
	ls -la testobsdrdr testpfpinhole 2>&1
}

# Build miniupnpd. Object files are kept, so a second build compiles only what changed:
# configure runs again only when what it depends on changed (the stamp) or its output
# is missing, and then everything is rebuilt. configure always rewrites config.h and
# bsdmake.inc (dropping the LDFLAGS and LIBS appended below), so the stamp guards both.
# Makefile.bsd only lists the .c files as prerequisites, so make depend writes .depend
# after every configure, or a changed header would leave stale objects.
cmd_build() {
	set -e
	mkdir -p "$WORK"
	pfctl_dir=$(dirname "$(ls /usr/lib/private/libpfctl.* 2>/dev/null | head -n 1)")   # part of the stamp
	options="--firewall=pf --ipv6 --leasefile --disable-tests ${1:---igd2 $(freebsd_peer_option)}"
	link_pfctl=freebsd_link_pfctl; [ "$OS" = OpenBSD ] && link_pfctl=true
	stamp=$( { echo "$options $pfctl_dir $(uname -r)"
		cat miniupnpd/configure miniupnpd/VERSION miniupnpd/Makefile.bsd; } | cksum)
	: >"$WORK/build.log"
	if [ "$(cat miniupnpd/.e2e-configure.stamp 2>/dev/null)" != "$stamp" ] ||
		[ ! -f miniupnpd/config.h ] || [ ! -f miniupnpd/bsdmake.inc ]; then
		echo "configure: $options" >>"$WORK/build.log"
		(cd miniupnpd && ./configure $options >/dev/null \
			&& $link_pfctl \
			&& { make -f Makefile.bsd clean; make -f Makefile.bsd depend; } >>"$WORK/build.log" 2>&1) || {
			tail -40 "$WORK/build.log" >&2
			echo "FAIL: configure" >&2
			exit 1
		}
		echo "$stamp" >miniupnpd/.e2e-configure.stamp
	fi
	(cd miniupnpd && make -j"$(sysctl -n hw.ncpu)" -f Makefile.bsd >>"$WORK/build.log" 2>&1) || {
		tail -40 "$WORK/build.log" >&2
		echo "FAIL: build" >&2
		exit 1
	}
}

# the addresses on the LAN and WAN NICs and the main ruleset of pf
cmd_net() {
	set -e
	lan4=${1:-172.28.41}; lan6=${2:-2001:db8:1::}; wan4=${3:-198.51.100}; wan6=${4:-2001:db8:9000::}
	mkdir -p "$WORK"
	sysctl net.inet.ip.forwarding=1 >/dev/null
	sysctl net.inet6.ip6.forwarding=1 >/dev/null
	ifconfig $LAN_IF up
	ifconfig $LAN_IF inet "$lan4.1/24"
	ifconfig $LAN_IF inet6 "${lan6}1/64" alias
	ifconfig $LAN_IF inet6 fd42:1::1/64 alias
	ifconfig $WAN_IF up
	ifconfig $WAN_IF inet "$wan4.1/24"
	ifconfig $WAN_IF inet6 "${wan6}1/64" alias
	sleep 3 # let IPv6 DAD finish

	[ "$OS" = OpenBSD ] || kldload -n pf || true
	pfctl -F all >/dev/null 2>&1 || true
	pfctl -e >/dev/null 2>&1 || true
	write_pf off
}

# Stop the daemon if it runs and wait until it is gone.
# has the VM got the addresses of this slot?
cmd_has_net() {
	ifconfig $LAN_IF | grep -q "inet $1.1 "
}

cmd_stop() {
	if [ -f "$WORK/miniupnpd.pid" ]; then
		pid=$(cat "$WORK/miniupnpd.pid")
		kill "$pid" 2>/dev/null || true
		i=0
		while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 20 ]; do i=$((i + 1)); sleep 0.5; done
		kill -9 "$pid" 2>/dev/null || true
	fi
}

# Write the configuration of the daemon and start it from a clean state: what an earlier
# run left behind (the rules of its anchor, pf states, NAT66, lease files, logs) would
# give wrong results. The main ruleset stays loaded. restart, which keeps the lease
# file on purpose, is a different thing.
cmd_start() {
	set -e
	mkdir -p "$WORK"
	cmd_stop
	flush_anchor
	pfctl -F states >/dev/null 2>&1 || true
	write_pf off
	rm -f /var/tmp/miniupnpd.leases /var/tmp/miniupnpd.leases6 "$WORK"/cap-*
	cat >"$WORK/miniupnpd.conf" <<'CONF'
ext_ifname=WAN_IF
tag=miniupnpd
ext_allow_private_ipv4=yes
listening_ip=LAN_IF
enable_upnp=yes
http_port=5000
enable_pcp_pmp=yes
lease_file=/var/tmp/miniupnpd.leases
lease_file6=/var/tmp/miniupnpd.leases6
max_lifetime=600
secure_mode=yes
allow 1024-65535 0.0.0.0/0 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
CONF
	sed -i.bak "s/=WAN_IF\$/=$WAN_IF/; s/=LAN_IF\$/=$LAN_IF/" "$WORK/miniupnpd.conf" && rm -f "$WORK/miniupnpd.conf.bak"
	# extra configuration lines, separated by commas (a suite on this fixture)
	printf '%s\n' "${1:-}" | tr ',' '\n' >>"$WORK/miniupnpd.conf"
	nohup miniupnpd/miniupnpd -d -f "$WORK/miniupnpd.conf" >"$WORK/miniupnpd.log" 2>&1 &
	echo $! >"$WORK/miniupnpd.pid"
	# the daemon answers on its PCP port once it is ready
	i=0
	until pcp_listening || [ "$i" -ge 20 ]; do i=$((i + 1)); sleep 0.5; done
	kill -0 "$(cat "$WORK/miniupnpd.pid")" && pcp_listening || {
		cat "$WORK/miniupnpd.log" >&2; echo "FAIL: daemon" >&2; exit 1; }
}

cmd_setup() {
	rm -rf "$WORK"
	cmd_build
	cmd_net
	cmd_start
	echo "$OS router ready"
}

command=${1:-}
[ "$#" -eq 0 ] || shift
case "$command" in
setup) cmd_setup ;;
build) cmd_build "$@" ;;
net) cmd_net "$@" ;;
has-net) cmd_has_net "$@" ;;
start) cmd_start "$@" ;;
stop) cmd_stop ;;
nat66) write_pf "${1:-off}" ;;
restart) cmd_restart "$@" ;;
lose-rules) cmd_lose_rules ;;
host) cmd_host "$@" ;;
rules) cmd_rules "$@" ;;
snapshot) cmd_snapshot ;;
capture) cmd_capture "$@" ;;
pf-make) cmd_pf_make ;;
*) echo "usage: $0 setup | build | net | start | stop | nat66 on|off | restart [keep] | rules PORTS | snapshot | capture start|stop | pf-make" >&2; exit 2 ;;
esac

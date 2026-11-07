#!/bin/sh
# Runs inside the Debian VM as root, from the repository root: everything the host driver
# (../run-debian-iptables.sh) does to the iptables router. The commands are those of
# ../freebsd/pf-router.sh.
#
#   iptables-router.sh build [OPTIONS]  configure (extra OPTIONS, default --igd2 --pcp-peer) and make miniupnpd
#   iptables-router.sh net LAN4 LAN6 WAN4 WAN6   name the LAN and WAN interfaces, give them the
#                                    addresses of the fixture slot and start the firewall
#   iptables-router.sh has-net LAN4  has the VM got the addresses of this slot?
#   iptables-router.sh start         start the daemon from a clean state
#   iptables-router.sh stop          stop the daemon
#   iptables-router.sh nat66 on|off  NAT for IPv6 on the WAN, for the sections which need it
#   iptables-router.sh restart       stop the daemon, flush its chains, start it again
#   iptables-router.sh rules PORTS   the rules of miniupnpd for the internal ports PORTS (an
#                                    extended regular expression, 43333|44444)
#   iptables-router.sh restored      how many times the daemon logged the restore of its PCP lease file
#   iptables-router.sh snapshot      print the router state, for the per-case snapshots
#   iptables-router.sh capture start|stop   tcpdump on lan0 and wan0 into /tmp/pcp-e2e/cap-*.pcap
#
# The first NIC is QEMU's management NIC (ssh). Debian names the others by their PCI slot, so
# they are found by the MAC addresses the driver gives them, and renamed lan0 and wan0.
set -u

WORK=/tmp/pcp-e2e
SCRIPTS=miniupnpd/netfilter

flush_chains() {
	iptables -w -t nat -F MINIUPNPD 2>/dev/null || true
	iptables -w -t nat -F MINIUPNPD-POSTROUTING 2>/dev/null || true
	iptables -w -t mangle -F MINIUPNPD 2>/dev/null || true
	iptables -w -t filter -F MINIUPNPD 2>/dev/null || true
	ip6tables -w -t filter -F MINIUPNPD 2>/dev/null || true
}

# A host name of a WAN peer, which the daemon resolves with the system resolver.
cmd_host() {
	sed -i.bak "/ ${1:?name}\$/d" /etc/hosts
	for address in "$2" "$3"; do
		echo "$address $1" >>/etc/hosts
	done
}

cmd_lose_rules() {
	count() { { iptables-save; ip6tables-save; } | grep -c '^-A MINIUPNPD'; }
	before=$(count)
	flush_chains
	echo "$before $(count)"
}

cmd_nat66() {
	ip6tables -w -t nat -D POSTROUTING -o wan0 -j MASQUERADE 2>/dev/null || true
	if [ "${1:-off}" = on ]; then
		ip6tables -w -t nat -A POSTROUTING -o wan0 -j MASQUERADE
	fi
}

# rename the NIC with this MAC address
name_nic() {
	nic=$(ip -o link | awk -v mac="$1" 'index($0, mac) { sub(":", "", $2); print $2; exit }')
	[ -n "$nic" ] || { echo "FAIL: no NIC with the MAC address $1" >&2; exit 1; }
	[ "$nic" = "$2" ] && return 0
	ip link set "$nic" down
	ip link set "$nic" name "$2"
}

cmd_has_net() {
	ip -4 -o address show dev lan0 2>/dev/null | grep -q "inet $1.1/"
}

cmd_net() {
	set -e
	lan4=$1; lan6=$2; wan4=$3; wan6=$4
	mkdir -p "$WORK"
	name_nic 52:54:00:41:00:01 lan0
	name_nic 52:54:00:09:00:01 wan0
	sysctl -q net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
		net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
	sysctl -q net.ipv6.conf.lan0.accept_ra=0 net.ipv6.conf.wan0.accept_ra=0
	ip link set lan0 up
	ip address replace "$lan4.1/24" dev lan0
	ip address replace "${lan6}1/64" dev lan0 nodad
	ip address replace fd42:1::1/64 dev lan0 nodad
	ip link set wan0 up
	ip address replace "$wan4.1/24" dev wan0
	ip address replace "${wan6}1/64" dev wan0 nodad

	sh "$SCRIPTS/iptables_init.sh" -i wan0
	sh "$SCRIPTS/ip6tables_init.sh" -i wan0
	# a gateway: LAN to WAN and what belongs to it, and inbound only through a mapping
	iptables -w -P FORWARD DROP
	ip6tables -w -P FORWARD DROP
	for ipt in iptables ip6tables; do
		$ipt -w -I FORWARD -i lan0 -o wan0 -j ACCEPT
		$ipt -w -I FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	done
	iptables -w -t nat -A POSTROUTING -o wan0 -j MASQUERADE
}

cmd_build() {
	set -e
	mkdir -p "$WORK"
	options="--firewall=iptables --ipv6 --leasefile --disable-tests ${1:---igd2 --pcp-peer}"
	stamp=$( { echo "$options $(uname -r)"
		cat miniupnpd/configure miniupnpd/VERSION miniupnpd/Makefile.linux; } | cksum)
	: >"$WORK/build.log"
	if [ "$(cat miniupnpd/.e2e-configure.stamp 2>/dev/null)" != "$stamp" ] || [ ! -f miniupnpd/config.h ]; then
		echo "configure: $options" >>"$WORK/build.log"
		(cd miniupnpd && ./configure $options >/dev/null \
			&& make -f Makefile.linux clean >>"$WORK/build.log" 2>&1) || {
			tail -40 "$WORK/build.log" >&2
			echo "FAIL: configure" >&2
			exit 1
		}
		echo "$stamp" >miniupnpd/.e2e-configure.stamp
	fi
	(cd miniupnpd && make -j"$(nproc)" -f Makefile.linux miniupnpd >>"$WORK/build.log" 2>&1) || {
		tail -40 "$WORK/build.log" >&2
		echo "FAIL: build" >&2
		exit 1
	}
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

cmd_restart() {
	set -e
	# a cold start of the daemon : its rules are lost, as after a reboot
	cmd_stop
	flush_chains
	nohup miniupnpd/miniupnpd -d -f "$WORK/miniupnpd.conf" >>"$WORK/miniupnpd.log" 2>&1 &
	echo $! >"$WORK/miniupnpd.pid"
	sleep 3
	kill -0 "$(cat "$WORK/miniupnpd.pid")" || { echo "FAIL: daemon" >&2; exit 1; }
}

# The rules of the daemon without their counters.
cmd_rules() {
	{ iptables-save; ip6tables-save; } | grep -E "$1" | sed 's/^\[[0-9:]*\] //' | sort || true
}

cmd_restored() {
	grep -c 'Restored .* PCP and NAT-PMP mappings' "$WORK/miniupnpd.log"
}

cmd_snapshot() {
	echo "=== miniupnpd process ==="; ps -ww -p "$(cat "$WORK/miniupnpd.pid")" -o pid,command
	echo "=== miniupnpd configuration ==="; cat "$WORK/miniupnpd.conf"
	echo "=== interfaces ==="; ip address
	echo "=== routes ==="; ip -4 route; ip -6 route
	echo "=== iptables rules ==="; iptables-save -c 2>&1
	echo "=== ip6tables rules ==="; ip6tables-save -c 2>&1
	echo "=== connections ==="; conntrack -L 2>/dev/null
	echo "=== lease file ==="; cat /var/tmp/miniupnpd.leases 2>/dev/null || echo "(none)"
	echo "=== lease file6 ==="; cat /var/tmp/miniupnpd.leases6 2>/dev/null || echo "(none)"
}

cmd_capture() {
	case "${1:-}" in
	start)
		rm -f "$WORK"/cap-*.pcap "$WORK/cap.pids"
		for i in lan0 wan0; do
			nohup tcpdump -U -n -i $i -s 0 -w "$WORK/cap-$i.pcap" >"$WORK/cap-$i.log" 2>&1 </dev/null &
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

# Write the configuration of the daemon and start it from a clean state: what an earlier
# run left behind would give wrong results. The firewall itself stays. restart, which keeps
# the lease file on purpose, is a different thing.
cmd_start() {
	set -e
	mkdir -p "$WORK"
	cmd_stop
	flush_chains
	conntrack -F >/dev/null 2>&1 || true
	cmd_nat66 off
	rm -f /var/tmp/miniupnpd.leases /var/tmp/miniupnpd.leases6 "$WORK"/cap-*
	cat >"$WORK/miniupnpd.conf" <<'CONF'
ext_ifname=wan0
ext_allow_private_ipv4=yes
listening_ip=lan0
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
	# extra configuration lines, separated by commas (a suite on this fixture)
	printf '%s\n' "${1:-}" | tr ',' '\n' >>"$WORK/miniupnpd.conf"
	nohup miniupnpd/miniupnpd -d -f "$WORK/miniupnpd.conf" >"$WORK/miniupnpd.log" 2>&1 &
	echo $! >"$WORK/miniupnpd.pid"
	# the daemon answers on its PCP port once it is ready
	i=0
	until ss -lun | grep -q ':5351' || [ "$i" -ge 20 ]; do i=$((i + 1)); sleep 0.5; done
	kill -0 "$(cat "$WORK/miniupnpd.pid")" && ss -lun | grep -q ':5351' || {
		cat "$WORK/miniupnpd.log" >&2; echo "FAIL: daemon" >&2; exit 1; }
}

command=${1:-}
[ "$#" -eq 0 ] || shift
case "$command" in
build) cmd_build "$@" ;;
net) cmd_net "$@" ;;
has-net) cmd_has_net "$@" ;;
start) cmd_start "$@" ;;
stop) cmd_stop ;;
nat66) cmd_nat66 "$@" ;;
restart) cmd_restart ;;
lose-rules) cmd_lose_rules ;;
host) cmd_host "$@" ;;
rules) cmd_rules "$@" ;;
restored) cmd_restored ;;
snapshot) cmd_snapshot ;;
capture) cmd_capture "$@" ;;
*) echo "usage: $0 build | net | has-net | start | stop | nat66 on|off | restart | rules PORTS | restored | snapshot | capture start|stop" >&2; exit 2 ;;
esac

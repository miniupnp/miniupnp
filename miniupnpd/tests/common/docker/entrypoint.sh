#!/bin/sh
set -eu

# The addresses of the WAN (the drivers pass those of their PCP_TEST_SLOT).
export PCP_TEST_WAN4="${PCP_TEST_WAN4:-198.51.100}"
PCP_TEST_WAN6_PREFIX=${PCP_TEST_WAN6_PREFIX:-fd42:5351:5352}

# The default fixture uses a dummy WAN. Traffic tests attach a real WAN bridge.
if [ "${PCP_TEST_REAL_WAN:-0}" = 1 ]; then
	python3 - <<'PY'
import json
import os
import subprocess

interfaces = json.loads(subprocess.check_output(["ip", "-j", "address"]))
wan = next(item["ifname"] for item in interfaces
           if any(addr.get("local") == os.environ["PCP_TEST_WAN4"] + ".1" for addr in item["addr_info"]))
renames = {wan: "wan0"}
if wan == "eth0":
    renames["eth1"] = "eth0"
for old, new in renames.items():
    subprocess.run(["ip", "link", "set", old, "down"], check=True)
    subprocess.run(["ip", "link", "set", old, "name", new], check=True)
    subprocess.run(["ip", "link", "set", new, "up"], check=True)
# Linux may flush global IPv6 addresses on link-down. Restore Docker's static
# assignments before miniupnpd enumerates the LAN and opens its PCP sockets.
for item in interfaces:
    for addr in item["addr_info"]:
        if addr["family"] == "inet6" and addr["scope"] == "global":
            subnet = str(addr["local"]) + "/" + str(addr["prefixlen"])
            subprocess.run(["ip", "-6", "address", "replace", subnet, "dev",
                            renames.get(item["ifname"], item["ifname"]), "nodad"], check=True)
PY
else
	ip link add wan0 type dummy
	ip link set wan0 up
	ip address add "$PCP_TEST_WAN4.1/24" dev wan0
fi

# Like a real router, optionally send the default route out of the WAN so
# multicast without an explicit output interface would leave through it.
if [ "${PCP_TEST_WAN_DEFAULT_ROUTE:-0}" = 1 ]; then
	ip route replace default via "$PCP_TEST_WAN4.254" dev wan0
	ip -6 route replace default via "$PCP_TEST_WAN6_PREFIX::ff" dev wan0
fi

cat > /etc/miniupnpd.conf <<'EOF'
ext_ifname=wan0
ext_allow_private_ipv4=yes
listening_ip=eth0
enable_upnp=no
enable_pcp_pmp=yes
lease_file=/var/lib/miniupnpd/miniupnpd.leases
lease_file6=/var/lib/miniupnpd/miniupnpd.leases6
max_lifetime=600
secure_mode=yes
allow 1024-65535 0.0.0.0/0 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
EOF

# PCP_TEST_CONF_REPLACE=1: the lines of PCP_TEST_EXTRA_CONF replace the default ones of the same
# option instead of following them (conf_replace.awk).
if [ "${PCP_TEST_CONF_REPLACE:-0}" = 1 ] && [ -n "${PCP_TEST_EXTRA_CONF:-}" ]; then
	printf '%s\n' "$PCP_TEST_EXTRA_CONF" |
		awk -f /usr/local/share/miniupnpd-test/conf_replace.awk - /etc/miniupnpd.conf > /etc/miniupnpd.conf.new
	mv /etc/miniupnpd.conf.new /etc/miniupnpd.conf
fi

# UPnP IGD mode: HTTP on a fixed port and a short SSDP announce interval; PCP_TEST_UPNP_UUID fixes the
# UDN when the cases expect one. The first enable_upnp=no of a file wins, so it is replaced.
if [ "${PCP_TEST_ENABLE_UPNP:-no}" = yes ]; then
	sed -i 's/^enable_upnp=no$/enable_upnp=yes/' /etc/miniupnpd.conf
	printf '%s\n' http_port=5000 notify_interval=30 >> /etc/miniupnpd.conf
	if [ -n "${PCP_TEST_UPNP_UUID:-}" ]; then
		echo "uuid=$PCP_TEST_UPNP_UUID" >> /etc/miniupnpd.conf
	fi
fi

# more settings for a test (lines of the configuration file)
if [ -n "${PCP_TEST_EXTRA_CONF:-}" ]; then
	printf '%s\n' "$PCP_TEST_EXTRA_CONF" >> /etc/miniupnpd.conf
	sed -i '/=@OFF@$/d' /etc/miniupnpd.conf     # key=@OFF@: leave the option out
fi

# Bind the IPv6 PCP socket to the LAN address instead of "::", as routers with
# several LANs effectively do (a single-LAN "::" socket is pinned to its device).
if [ "${PCP_TEST_IPV6_LISTENING_IP:-0}" = 1 ]; then
	lan6=$(ip -6 -o address show dev eth0 scope global | awk '{sub("/.*", "", $4); print $4; exit}')
	echo "ipv6_listening_ip=$lan6" >> /etc/miniupnpd.conf
fi

if [ "${PCP_TEST_CONF_REPLACE:-0}" = 1 ]; then
	/etc/miniupnpd/scripts/nft_init.sh -f /etc/miniupnpd.conf     # the table and chain options
else
	/etc/miniupnpd/scripts/nft_init.sh
fi
# A stand-in for minissdpd that records what the daemon submits to its socket.
minissdpd_socket=$(sed -n 's/^minissdpdsocket=//p' /etc/miniupnpd.conf)
if [ -n "$minissdpd_socket" ]; then
	rm -f "$minissdpd_socket"
	python3 -c '
import socket, sys
# holding the SSDP port makes the daemon fall back to minissdpd
ssdp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ssdp.bind(("0.0.0.0", 1900))
server = socket.socket(socket.AF_UNIX)
server.bind(sys.argv[1])
server.listen(4)
while True:
    connection = server.accept()[0]
    with open("/tmp/minissdpd.received", "ab") as received:
        received.write(connection.recv(4096))
    connection.close()
' "$minissdpd_socket" &
	sleep 0.5
fi
# an --https build needs a certificate at start, also without https_port
if [ "${PCP_TEST_CONF_REPLACE:-0}" = 1 ] && command -v openssl >/dev/null; then
	openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=router -days 2 \
		-keyout /etc/miniupnpd/private-key.pem -out /etc/miniupnpd/certificate.pem 2>/dev/null
fi
if [ "${PCP_TEST_REAL_WAN:-0}" = 1 ]; then
	# Return packets are part of established flows; new inbound traffic still
	# needs the mapping/pinhole rule and the forward chain retains policy drop.
	# The forward chain is in the table nft_init.sh made: with PCP_TEST_CONF_REPLACE
	# a case may name it (upnp_table_name, upnp_nftables_family_split).
	family=inet table=filter
	if [ "${PCP_TEST_CONF_REPLACE:-0}" = 1 ]; then
		table=$(sed -n 's/^upnp_table_name=//p' /etc/miniupnpd.conf | tail -n 1)
		table=${table:-filter}
		grep -q '^upnp_nftables_family_split=yes' /etc/miniupnpd.conf && family=ip
	fi
	nft insert rule "$family" "$table" forward ct state established,related accept || {
		echo "entrypoint: no forward chain in nft table $family $table for the established-flow rule" >&2
		exit 1
	}
fi
# Record the daemon's outgoing PCP multicast traffic from before it starts: one
# capture per LAN (eth0) and WAN (wan0) interface, for the daemon-restart fixture.
if [ -n "${PCP_TEST_CAPTURE_DIR:-}" ]; then
	mkdir -p "$PCP_TEST_CAPTURE_DIR"
	tcpdump -i eth0 -n -U -Q out -w "$PCP_TEST_CAPTURE_DIR/lan-0.pcap" 'udp and dst port 5350' 2>/dev/null &
	tcpdump -i wan0 -n -U -Q out -w "$PCP_TEST_CAPTURE_DIR/wan-0.pcap" 'udp and dst port 5350' 2>/dev/null &
	sleep 1
fi
mkdir -p /var/lib/miniupnpd
# PCP_TEST_QUIET=1: without -d (the log mask is then LOG_NOTICE, no debug lines), for
# long runs. The daemon goes to the background: wait for it, and stop it with the
# container (it then writes its pending PCP lease file save).
if [ "${PCP_TEST_QUIET:-0}" = 1 ]; then
	rm -f /var/run/miniupnpd.pid
	/usr/sbin/miniupnpd -f /etc/miniupnpd.conf "$@" || exit 1
	sleep 1
	pid=$(cat /var/run/miniupnpd.pid 2>/dev/null)
	[ -n "$pid" ] || { echo "miniupnpd did not start" >&2; exit 1; }
	trap 'kill "$pid" 2>/dev/null; while kill -0 "$pid" 2>/dev/null; do sleep 0.2; done; exit 0' TERM INT
	while kill -0 "$pid" 2>/dev/null; do sleep 1 & wait $!; done
	exit 1
fi
exec /usr/sbin/miniupnpd -d -f /etc/miniupnpd.conf "$@"

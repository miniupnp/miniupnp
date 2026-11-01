#!/bin/sh
set -eu

# The default fixture uses a dummy WAN. Traffic tests attach a real WAN bridge.
if [ "${PCP_TEST_REAL_WAN:-0}" = 1 ]; then
	python3 - <<'PY'
import json
import subprocess

interfaces = json.loads(subprocess.check_output(["ip", "-j", "address"]))
wan = next(item["ifname"] for item in interfaces
           if any(addr.get("local") == "198.51.100.1" for addr in item["addr_info"]))
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
	ip address add 198.51.100.1/24 dev wan0
fi

# Like a real router, optionally send the default route out of the WAN so
# multicast without an explicit output interface would leave through it.
if [ "${PCP_TEST_WAN_DEFAULT_ROUTE:-0}" = 1 ]; then
	ip route replace default via 198.51.100.254 dev wan0
	ip -6 route replace default via fd42:5351:5352::ff dev wan0
fi

cat > /etc/miniupnpd.conf <<'EOF'
ext_ifname=wan0
ext_allow_private_ipv4=yes
listening_ip=eth0
enable_upnp=no
enable_pcp_pmp=yes
max_lifetime=600
secure_mode=yes
allow 1024-65535 0.0.0.0/0 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
EOF

# Bind the IPv6 PCP socket to the LAN address instead of "::", as routers with
# several LANs effectively do (a single-LAN "::" socket is pinned to its device).
if [ "${PCP_TEST_IPV6_LISTENING_IP:-0}" = 1 ]; then
	lan6=$(ip -6 -o address show dev eth0 scope global | awk '{sub("/.*", "", $4); print $4; exit}')
	echo "ipv6_listening_ip=$lan6" >> /etc/miniupnpd.conf
fi

/etc/miniupnpd/scripts/nft_init.sh
if [ "${PCP_TEST_REAL_WAN:-0}" = 1 ]; then
	# Return packets are part of established flows; new inbound traffic still
	# needs the mapping/pinhole rule and the forward chain retains policy drop.
	nft insert rule inet filter forward ct state established,related accept
fi
mkdir -p /var/lib/miniupnpd
exec /usr/sbin/miniupnpd -d -f /etc/miniupnpd.conf "$@"

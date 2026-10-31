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

/etc/miniupnpd/scripts/nft_init.sh
if [ "${PCP_TEST_REAL_WAN:-0}" = 1 ]; then
	# Return packets are part of established flows; new inbound traffic still
	# needs the mapping/pinhole rule and the forward chain retains policy drop.
	nft insert rule inet filter forward ct state established,related accept
fi
mkdir -p /var/lib/miniupnpd
exec /usr/sbin/miniupnpd -d -f /etc/miniupnpd.conf "$@"

#!/bin/sh
# Runs inside the Debian VM as root, once: what the iptables router needs, for the cached
# image. miniupnpd uses libiptc, so the iptables commands must use the same legacy tables.
set -eu

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
	build-essential pkg-config libcap-dev libcap-ng-dev uuid-dev \
	iptables libiptc-dev libxtables-dev libnfnetlink-dev conntrack \
	iproute2 tcpdump rsync >/dev/null
update-alternatives --set iptables /usr/sbin/iptables-legacy
update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
modules="ip_tables iptable_filter iptable_nat iptable_mangle ip6_tables ip6table_filter ip6table_nat ip6table_mangle"
# shellcheck disable=SC2086
printf '%s\n' $modules >/etc/modules-load.d/miniupnpd-test.conf
# the driver starts the commands of the router from /root/miniupnp, as the login user
chmod 755 /root

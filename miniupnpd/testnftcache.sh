#!/bin/sh
# Run testnftcache against the nf_tables of the kernel, in a container whose
# network namespace holds its ruleset. Needs Docker and an image with gcc,
# libnftnl, libmnl and nft (TESTNFTCACHE_IMAGE). From the miniupnpd directory
# of a tree configured for nftables.
set -e
IMAGE=${TESTNFTCACHE_IMAGE:-debian:trixie}
SRC=$(cd "$(dirname "$0")" && pwd)

docker run --rm --cap-add NET_ADMIN -v "$SRC:/src:ro" --entrypoint sh "$IMAGE" -ec '
	if ! command -v nft >/dev/null || [ ! -e /usr/include/libnftnl/set.h ]; then
		apt-get -qq update >/dev/null
		apt-get -qq install -y gcc libnftnl-dev libmnl-dev nftables iproute2 >/dev/null
	fi
	mkdir /build && cp -r /src/. /build/ && cd /build
	gcc -Wall -g -fsanitize=address -I. -DUSE_NETFILTER -DUSE_NFTABLES -o testnftcache \
		testnftcache.c netfilter_nft/nftnlrdr.c netfilter_nft/nftnlrdr_misc.c \
		netfilter_nft/nftpinhole.c -lnftnl -lmnl
	ip link add wan0 type dummy
	nft -f - <<EOF2
table inet filter {
	chain forward { type filter hook forward priority 0; policy drop; jump miniupnpd; }
	chain miniupnpd { }
	chain prerouting { type nat hook prerouting priority dstnat; jump prerouting_miniupnpd; }
	chain prerouting_miniupnpd { }
	chain postrouting { type nat hook postrouting priority srcnat; jump postrouting_miniupnpd; }
	chain postrouting_miniupnpd { }
}
EOF2
	./testnftcache
'

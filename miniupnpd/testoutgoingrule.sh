#!/bin/sh
# Run testoutgoingrule against the nf_tables of the kernel, in a container
# whose network namespace holds its ruleset: it never touches the host's.
# Needs Docker and an image with gcc, libnftnl, libmnl and nft
# (TESTOUTGOINGRULE_IMAGE). From the miniupnpd directory; $1 is a build
# directory under it, configured with --firewall=nftables --pcp-peer.
set -e
IMAGE=${TESTOUTGOINGRULE_IMAGE:-miniupnpd-nfttest:trixie}
SRC=$(cd "$(dirname "$0")" && pwd)
BUILD=${1:?usage: $0 <build directory under miniupnpd/>}

docker run --rm --cap-add NET_ADMIN -v "$SRC:/src:ro" -e BUILD="$BUILD" \
	--entrypoint sh "$IMAGE" -ec '
	mkdir /build && cp -r /src/. /build/ && cd /build
	gcc -Wall -Wextra -g -fsanitize=address -I"$BUILD" -I. -D_GNU_SOURCE \
		-o testoutgoingrule testoutgoingrule.c \
		netfilter_nft/nftnlrdr.c netfilter_nft/nftnlrdr_misc.c -lnftnl -lmnl
	ip link add wan0 type dummy
	nft -f - <<EOF
table inet filter {
	chain forward { type filter hook forward priority 0; policy drop; jump miniupnpd; }
	chain miniupnpd { }
	chain prerouting { type nat hook prerouting priority dstnat; jump prerouting_miniupnpd; }
	chain prerouting_miniupnpd { }
	chain postrouting { type nat hook postrouting priority srcnat; jump postrouting_miniupnpd; }
	chain postrouting_miniupnpd { }
}
EOF
	./testoutgoingrule
'

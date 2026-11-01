FROM debian:trixie-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential git pkg-config libcap-dev libcap-ng-dev uuid-dev \
      libmnl-dev libnftnl-dev nftables iproute2 python3 python3-yaml tcpdump ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src
RUN cd /src/miniupnpd \
 && ./configure --firewall=nftables --pcp-peer --ipv6 --disable-tests \
 && make -j2 \
 && install -D -m 0755 miniupnpd /usr/sbin/miniupnpd \
 && install -D -m 0755 netfilter_nft/scripts/nft_init.sh /etc/miniupnpd/scripts/nft_init.sh \
 && install -D -m 0644 netfilter_nft/scripts/miniupnpd_functions.sh /etc/miniupnpd/scripts/miniupnpd_functions.sh

COPY miniupnpd/tests/pcp_pmp/docker/entrypoint.sh /usr/local/bin/miniupnpd-test-entrypoint
RUN chmod 0755 /usr/local/bin/miniupnpd-test-entrypoint

EXPOSE 5351/udp
ENTRYPOINT ["/usr/local/bin/miniupnpd-test-entrypoint"]

# The tools of the Docker suites, shared by all slots and worktrees. There is no source here:
# e2e_build_daemon (e2e_lib.sh) compiles the daemon in this image into a directory of the host, which
# the router mounts at /opt/miniupnpd, and the suites mount miniupnpd/tests at /pcp-tests.
FROM debian:trixie-slim

# what a build variant needs from Debian
ARG EXTRA_PACKAGES=
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential git pkg-config libcap-dev libcap-ng-dev uuid-dev \
      libmnl-dev libnftnl-dev nftables iproute2 python3 python3-yaml tcpdump ca-certificates $EXTRA_PACKAGES \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/miniupnpd \
 && ln -s /opt/miniupnpd/miniupnpd /usr/sbin/miniupnpd \
 && ln -s /opt/miniupnpd/scripts /etc/miniupnpd/scripts

COPY entrypoint.sh /usr/local/bin/miniupnpd-test-entrypoint
COPY conf_replace.awk /usr/local/share/miniupnpd-test/conf_replace.awk
RUN chmod 0755 /usr/local/bin/miniupnpd-test-entrypoint

EXPOSE 5351/udp
ENTRYPOINT ["/usr/local/bin/miniupnpd-test-entrypoint"]

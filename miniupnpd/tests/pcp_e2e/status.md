# PCP end-to-end Test Status

One column per platform; a run updates only its own platform's column (raw results: `.tmp/tests/pcp_e2e/status-data.json`).

## Platforms

- **linux**: **41 PASS**, **0 XFAIL**, **50 FAIL**, **0 SKIP** (updated 2026-11-07T12:12:39+01:00; ipv4: branch `dev/pcp-test-harness`, selection `all`, artifacts `.tmp/pcp-e2e/2026-11-07T11-09-19Z-slot4 (daemon startup/final logs and per-case captures/snapshots)`, router `Linux nftables`, cases `53`; ipv6: branch `dev/pcp-test-harness`, selection `all`, artifacts `.tmp/pcp-e2e/2026-11-07T11-09-19Z-slot4 (daemon startup/final logs and per-case captures/snapshots)`, router `Linux nftables`, cases `38`)
- **freebsd**: **67 PASS**, **0 XFAIL**, **1 FAIL**, **0 SKIP** (updated 2026-11-06T18:29:40+01:00; ipv4: branch `dev/pcp-test-harness`, selection `map-single-udp-only`, artifacts `.tmp/pcp-e2e/freebsd-2026-11-06T17-26-12Z-slot6`, router `FreeBSD 14.5 pf`, peers `Linux Docker`, cases `1`; ipv6: branch `dev/pcp-test-harness`, selection `map-single-udp-only`, artifacts `.tmp/pcp-e2e/freebsd-2026-11-06T17-26-12Z-slot6`, router `FreeBSD 14.5 pf`, peers `Linux Docker`, cases `1`)
- **debian-iptables**: **33 PASS**, **0 XFAIL**, **43 FAIL**, **0 SKIP** (updated 2026-11-06T18:28:54+01:00; ipv4: branch `dev/pcp-test-harness`, selection `all`, artifacts `.tmp/pcp-e2e/freebsd-2026-11-06T17-22-03Z-slot5`, router `Debian 13 iptables`, peers `Linux Docker`, cases `44`; ipv6: branch `dev/pcp-test-harness`, selection `all`, artifacts `.tmp/pcp-e2e/freebsd-2026-11-06T17-22-03Z-slot5`, router `Debian 13 iptables`, peers `Linux Docker`, cases `35`)
- **openbsd**: **34 PASS**, **0 XFAIL**, **57 FAIL**, **0 SKIP** (updated 2026-11-13T09:48:25+01:00; ipv4: branch `test/openbsd-pf`, selection `all`, artifacts `.tmp/claude/out/2026-11-13-openbsd-tests/e2e4/artifacts/freebsd-2026-11-13T08-38-02Z-slot8`, router `OpenBSD 8.0 pf`, peers `Linux Docker`, cases `53`; ipv6: branch `test/openbsd-pf`, selection `all`, artifacts `.tmp/claude/out/2026-11-13-openbsd-tests/e2e4/artifacts/freebsd-2026-11-13T08-38-02Z-slot8`, router `OpenBSD 8.0 pf`, peers `Linux Docker`, cases `38`)

## Results by section

### MAP

PCP MAP mapping lifecycle and protocol scenarios.

| Case | Protocol | Family | linux | freebsd | debian-iptables | openbsd | Result / note |
|---|---|---|---|---|---|---|---|
| map-single-udp-only | pcp | ipv4 | PASS | PASS | PASS | PASS | A UDP mapping forwards UDP traffic and does not create a TCP mapping. |
| map-single-udp-only | pcp | ipv6 | PASS | PASS | PASS | PASS | A UDP mapping forwards UDP traffic and does not create a TCP mapping. |
| map-single-tcp-only | pcp | ipv4 | PASS | PASS | PASS | PASS | A TCP mapping forwards TCP traffic and does not create a UDP mapping. |
| map-single-tcp-only | pcp | ipv6 | PASS | PASS | PASS | PASS | A TCP mapping forwards TCP traffic and does not create a UDP mapping. |
| map-udp-and-tcp-same-port | pcp | ipv4 | PASS | PASS | PASS | PASS | UDP and TCP mappings can coexist on the same external and internal port. |
| map-udp-and-tcp-same-port | pcp | ipv6 | PASS | PASS | PASS | PASS | UDP and TCP mappings can coexist on the same external and internal port. |
| map-same-protocol-and-port-conflicts | pcp | ipv4 | PASS | PASS | PASS | PASS | A second mapping cannot steal an occupied external protocol and port tuple. |
| map-same-protocol-and-port-conflicts | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected CANNOT_PROVIDE_EXTERNAL, got SUCCESS; debian-iptables: PCP response expected CANNOT_PROVIDE_EXTERNAL, got SUCCESS; openbsd: PCP response expected CANNOT_PROVIDE_EXTERNAL, got SUCCESS |
| map-ipv6-prefer-failure-preserves-mapping | pcp | ipv6 | FAIL | — | — | FAIL | linux: PCP response expected CANNOT_PROVIDE_EXTERNAL, got SUCCESS; openbsd: PCP response expected CANNOT_PROVIDE_EXTERNAL, got NO_RESOURCES |
| map-renewal-keeps-forwarding | pcp | ipv4 | PASS | PASS | PASS | PASS | Renewing a mapping keeps its forwarding behavior active. |
| map-renewal-keeps-forwarding | pcp | ipv6 | PASS | PASS | PASS | FAIL | openbsd: PCP response expected SUCCESS, got NO_RESOURCES |
| map-renewal-adds-lost-rule | pcp | ipv4 | PASS | — | — | PASS | The firewall lost the rules of a mapping, and a renewal makes the mapping pass traffic again. |
| map-renewal-adds-lost-rule | pcp | ipv6 | FAIL | — | — | PASS | linux: PCP response expected SUCCESS, got NO_RESOURCES |
| map-delete-stops-forwarding | pcp | ipv4 | PASS | PASS | PASS | PASS | Deleting a mapping removes the forwarding path for new flows. |
| map-delete-stops-forwarding | pcp | ipv6 | PASS | PASS | PASS | PASS | Deleting a mapping removes the forwarding path for new flows. |
| map-unfiltered-allows-independent-peers | pcp | ipv4 | PASS | PASS | PASS | PASS | An unrestricted PCP MAP accepts traffic from either WAN peer. |
| map-unfiltered-allows-independent-peers | pcp | ipv6 | PASS | PASS | PASS | PASS | An unrestricted PCP MAP accepts traffic from either WAN peer. |
| map-repeated-renewals-then-delete-stops-forwarding | pcp | ipv4 | PASS | — | — | PASS | Create a mapping, renew it three times, delete it once, and check that no rule is left to forward. |
| map-repeated-renewals-then-delete-stops-forwarding | pcp | ipv6 | PASS | — | — | FAIL | openbsd: PCP response expected SUCCESS, got NO_RESOURCES |
| map-tcp-repeated-renewals-then-delete-stops-forwarding | pcp | ipv4 | PASS | — | — | PASS | The TCP form of the repeated-renewal case. |
| map-tcp-repeated-renewals-then-delete-stops-forwarding | pcp | ipv6 | PASS | — | — | FAIL | openbsd: PCP response expected SUCCESS, got NO_RESOURCES |

### FILTER

PCP MAP FILTER peer and source-port policy scenarios.

| Case | Protocol | Family | linux | freebsd | debian-iptables | openbsd | Result / note |
|---|---|---|---|---|---|---|---|
| map-filter-exact-peer-and-port | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: udp 6.18.4.1:41002: expected blocked; got {'delivered': True}; debian-iptables: udp 6.18.5.1:41002: expected blocked; got {'delivered': True}; openbsd: udp 6.18.8.1:41002: expected blocked; got {'delivered': True} |
| map-filter-exact-peer-and-port | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp 2001:db8:1:4::2:41002: expected blocked; got {'delivered': True}; debian-iptables: udp 2001:db8:1:5::2:41002: expected blocked; got {'delivered': True}; openbsd: udp 2001:db8:1:8::2:41002: expected blocked; got {'delivered': True} |
| map-filter-restricts-remote-port | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: tcp 6.18.4.1:41003: expected blocked; got {'delivered': True}; debian-iptables: tcp 6.18.5.1:41003: expected blocked; got {'delivered': True}; openbsd: tcp 6.18.8.1:41003: expected blocked; got {'delivered': True} |
| map-filter-restricts-remote-port | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: tcp 2001:db8:1:4::2:41003: expected blocked; got {'delivered': True}; debian-iptables: tcp 2001:db8:1:5::2:41003: expected blocked; got {'delivered': True}; openbsd: tcp 2001:db8:1:8::2:41003: expected blocked; got {'delivered': True} |
| map-filter-prefix-allows-subnet | pcp | ipv4 | PASS | PASS | PASS | PASS | A /24 IPv4 or /64 IPv6 prefix permits peers in the same subnet. |
| map-filter-prefix-allows-subnet | pcp | ipv6 | PASS | PASS | PASS | PASS | A /24 IPv4 or /64 IPv6 prefix permits peers in the same subnet. |
| map-filter-narrow-prefix-rejects-outside-subnet | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: udp 6.18.4.1:41005: expected blocked; got {'delivered': True}; debian-iptables: udp 6.18.5.1:41005: expected blocked; got {'delivered': True}; openbsd: udp 6.18.8.1:41005: expected blocked; got {'delivered': True} |
| map-filter-narrow-prefix-rejects-outside-subnet | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp 2001:db8:1:4::2:41005: expected blocked; got {'delivered': True}; debian-iptables: udp 2001:db8:1:5::2:41005: expected blocked; got {'delivered': True}; openbsd: udp 2001:db8:1:8::2:41005: expected blocked; got {'delivered': True} |
| map-filter-multiple-options-add-peers | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: udp 6.18.4.1:41006: expected blocked; got {'delivered': True}; debian-iptables: udp 6.18.5.1:41006: expected blocked; got {'delivered': True}; openbsd: udp 6.18.8.1:41006: expected blocked; got {'delivered': True} |
| map-filter-multiple-options-add-peers | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp 2001:db8:1:4::2:41006: expected blocked; got {'delivered': True}; debian-iptables: udp 2001:db8:1:5::2:41006: expected blocked; got {'delivered': True}; openbsd: udp 2001:db8:1:8::2:41006: expected blocked; got {'delivered': True} |
| map-filter-options-at-message-limit | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: udp 6.18.4.1:41017: expected blocked; got {'delivered': True}; debian-iptables: udp 6.18.5.1:41017: expected blocked; got {'delivered': True}; openbsd: udp 6.18.8.1:41017: expected blocked; got {'delivered': True} |
| map-filter-options-at-message-limit | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp 2001:db8:1:4::2:41017: expected blocked; got {'delivered': True}; debian-iptables: udp 2001:db8:1:5::2:41017: expected blocked; got {'delivered': True}; openbsd: udp 2001:db8:1:8::2:41017: expected blocked; got {'delivered': True} |
| map-filter-refresh-adds-peer | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: udp 6.18.4.1:41007: expected blocked; got {'delivered': True}; debian-iptables: udp 6.18.5.1:41007: expected blocked; got {'delivered': True}; openbsd: udp 6.18.8.1:41007: expected blocked; got {'delivered': True} |
| map-filter-refresh-adds-peer | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp 2001:db8:1:4::2:41007: expected blocked; got {'delivered': True}; debian-iptables: udp 2001:db8:1:5::2:41007: expected blocked; got {'delivered': True}; openbsd: PCP response expected SUCCESS, got NO_RESOURCES |
| map-filter-refresh-replaces-peer-set | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: udp 6.18.4.1:41008: expected blocked; got {'delivered': True}; debian-iptables: udp 6.18.5.1:41008: expected blocked; got {'delivered': True}; openbsd: udp 6.18.8.1:41008: expected blocked; got {'delivered': True} |
| map-filter-refresh-replaces-peer-set | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp 2001:db8:1:4::2:41008: expected blocked; got {'delivered': True}; debian-iptables: udp 2001:db8:1:5::2:41008: expected blocked; got {'delivered': True}; openbsd: PCP response expected SUCCESS, got NO_RESOURCES |
| map-filter-prefix-zero-removes-all | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: udp 6.18.4.1:41009: expected blocked; got {'delivered': True}; debian-iptables: udp 6.18.5.1:41009: expected blocked; got {'delivered': True}; openbsd: udp 6.18.8.1:41009: expected blocked; got {'delivered': True} |
| map-filter-prefix-zero-removes-all | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp 2001:db8:1:4::2:41009: expected blocked; got {'delivered': True}; debian-iptables: udp 2001:db8:1:5::2:41009: expected blocked; got {'delivered': True}; openbsd: udp 2001:db8:1:8::2:41009: expected blocked; got {'delivered': True} |
| map-filter-refresh-without-options-preserves-policy | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: udp 6.18.4.1:41019: expected blocked; got {'delivered': True}; debian-iptables: udp 6.18.5.1:41019: expected blocked; got {'delivered': True}; openbsd: udp 6.18.8.1:41019: expected blocked; got {'delivered': True} |
| map-filter-refresh-without-options-preserves-policy | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp 2001:db8:1:4::2:41019: expected blocked; got {'delivered': True}; debian-iptables: udp 2001:db8:1:5::2:41019: expected blocked; got {'delivered': True}; openbsd: PCP response expected SUCCESS, got NO_RESOURCES |
| map-filter-delete-and-recreate-clears-policy | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: udp 6.18.4.1:41022: expected blocked; got {'delivered': True}; debian-iptables: udp 6.18.5.1:41022: expected blocked; got {'delivered': True}; openbsd: udp 6.18.8.1:41022: expected blocked; got {'delivered': True} |
| map-filter-delete-and-recreate-clears-policy | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp 2001:db8:1:4::2:41022: expected blocked; got {'delivered': True}; debian-iptables: udp 2001:db8:1:5::2:41022: expected blocked; got {'delivered': True}; openbsd: udp 2001:db8:1:8::2:41022: expected blocked; got {'delivered': True} |

### PEER

PCP PEER mappings restricted to a remote endpoint.

| Case | Protocol | Family | linux | freebsd | debian-iptables | openbsd | Result / note |
|---|---|---|---|---|---|---|---|
| peer-create-before-first-packet-udp | pcp | ipv4 | FAIL | PASS | PASS | FAIL | linux: PCP PEER udp expected WAN tuple 6.18.4.1:43020; got {'token_hex': '2f60c8518b6fb3fae383881b77cd4724', 'source': '6.18.4.1', 'source_port': 41020}; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-create-before-first-packet-udp | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; debian-iptables: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-create-before-first-packet-tcp | pcp | ipv4 | FAIL | PASS | PASS | FAIL | linux: PCP PEER tcp expected WAN tuple 6.18.4.1:43021; got {'token_hex': '56e27940f73f573c2b772cd2fbe6218f', 'source': '6.18.4.1', 'source_port': 41021}; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-create-before-first-packet-tcp | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; debian-iptables: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-processes-options-at-message-limit | pcp | ipv4 | PASS | PASS | PASS | FAIL | openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-processes-options-at-message-limit | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; debian-iptables: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-adopts-existing-udp-mapping | pcp | ipv4 | PASS | PASS | PASS | FAIL | openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-adopts-existing-udp-mapping | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; debian-iptables: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-adopts-existing-tcp-mapping | pcp | ipv4 | PASS | PASS | PASS | FAIL | openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-adopts-existing-tcp-mapping | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; debian-iptables: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-recreates-remembered-tcp-mapping | pcp | ipv4 | FAIL | PASS | PASS | FAIL | linux: PCP PEER tcp expected WAN tuple 6.18.4.1:43040; got {'token_hex': '5185faddf06401f269fada3495e1efd3', 'source': '6.18.4.1', 'source_port': 41040}; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-recreates-remembered-tcp-mapping | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; debian-iptables: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-rejects-unavailable-external-address | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: PCP PEER response did not honor the suggested external address; debian-iptables: PCP PEER response did not honor the suggested external address; openbsd: PCP response expected CANNOT_PROVIDE_EXTERNAL, got UNSUPP_OPCODE |
| peer-rejects-mismatched-port-on-renewal | pcp | ipv4 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected CANNOT_PROVIDE_EXTERNAL, got SUCCESS; debian-iptables: PCP response expected CANNOT_PROVIDE_EXTERNAL, got SUCCESS; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-rejects-mismatched-port-on-renewal | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; debian-iptables: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-rejects-prefer-failure | pcp | ipv4 | PASS | PASS | PASS | FAIL | openbsd: PCP response expected MALFORMED_REQUEST, got UNSUPP_OPCODE |
| peer-rejects-prefer-failure | pcp | ipv6 | PASS | PASS | PASS | FAIL | openbsd: PCP response expected MALFORMED_REQUEST, got UNSUPP_OPCODE |
| peer-ipv6-udp-restricts-remote-endpoint | pcp | ipv6 | FAIL | — | — | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-ipv6-tcp-restricts-remote-endpoint | pcp | ipv6 | FAIL | — | — | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| peer-ipv6-rejects-unavailable-external-port | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected CANNOT_PROVIDE_EXTERNAL, got UNSUPP_OPCODE; debian-iptables: PCP response expected CANNOT_PROVIDE_EXTERNAL, got UNSUPP_OPCODE; openbsd: PCP response expected CANNOT_PROVIDE_EXTERNAL, got UNSUPP_OPCODE |
| peer-ipv6-rejects-unavailable-external-address | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected CANNOT_PROVIDE_EXTERNAL, got UNSUPP_OPCODE; debian-iptables: PCP response expected CANNOT_PROVIDE_EXTERNAL, got UNSUPP_OPCODE; openbsd: PCP response expected CANNOT_PROVIDE_EXTERNAL, got UNSUPP_OPCODE |
| peer-ipv6-coexists-with-filtered-map | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; debian-iptables: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |

### NAT

NAT-PMP IPv4 address discovery and IPv6 PCP mapping with NAT66.

| Case | Protocol | Family | linux | freebsd | debian-iptables | openbsd | Result / note |
|---|---|---|---|---|---|---|---|
| natpmp-public-address | natpmp | ipv4 | PASS | PASS | PASS | PASS | Request and verify the gateway's external IPv4 address. |
| ipv6-pcp-map-reachability | pcp | ipv6 | PASS | PASS | PASS | PASS | With the client using the NAT66-only ULA, PCP MAP preserves that address and opens its firewall rule. |
| ipv6-nat66-pcp-peer-reachability | pcp | ipv6 | FAIL | FAIL | FAIL | FAIL | linux: PCP response expected SUCCESS, got UNSUPP_OPCODE; freebsd: PCP PEER udp expected WAN tuple 2001:db8:9000::1:41104; got {'token_hex': '99f264bceae270560fb20b458f8905c2', 'source': '2001:db8:9000::1', 'source_port': 55532}; debian-iptables: PCP response expected SUCCESS, got UNSUPP_OPCODE; openbsd: PCP response expected SUCCESS, got UNSUPP_OPCODE |
| ipv6-nat66-pcp-map-filter | pcp | ipv6 | FAIL | PASS | FAIL | FAIL | linux: udp fd42:1::2:41105: expected blocked; got {'delivered': True}; debian-iptables: udp fd42:1::2:41105: expected blocked; got {'delivered': True}; openbsd: udp fd42:1::2:41105: expected blocked; got {'delivered': True} |

### PMP

NAT-PMP UDP and TCP mapping creation, renewal, and deletion.

| Case | Protocol | Family | linux | freebsd | debian-iptables | openbsd | Result / note |
|---|---|---|---|---|---|---|---|
| natpmp-single-udp-lifecycle | natpmp | ipv4 | PASS | PASS | PASS | PASS | Create, renew, and delete a UDP mapping, checking forwarding before deletion and blocking after. |
| natpmp-single-tcp-lifecycle | natpmp | ipv4 | PASS | PASS | PASS | PASS | Create and delete a TCP mapping and verify its forwarding path is removed. |
| natpmp-udp-and-tcp-same-port | natpmp | ipv4 | PASS | PASS | PASS | PASS | UDP and TCP NAT-PMP mappings can share the same private and public port numbers. |
| natpmp-renewal-adds-lost-rule | natpmp | ipv4 | PASS | — | — | PASS | The firewall lost the rules of a mapping, and a renewal makes the mapping pass traffic again. |
| natpmp-repeated-renewals-then-delete-stops-forwarding | natpmp | ipv4 | PASS | — | — | PASS | Create a UDP mapping, renew it three times, delete it once, and check forwarding stops. |
| natpmp-delete-finds-mapping-by-private-port | natpmp | ipv4 | PASS | — | — | PASS | Two crossed mappings (41253->41254 and 41254->41253); deleting the first leaves the second. |

### UPnP

UPnP IGD port mappings (SOAP AddPortMapping / DeletePortMapping), which share the firewall rule code with PCP. Needs a daemon with enable_upnp=yes, so the section only runs with --enable-upnp.

| Case | Protocol | Family | linux | freebsd | debian-iptables | openbsd | Result / note |
|---|---|---|---|---|---|---|---|
| upnp-udp-lifecycle | upnp | ipv4 | PASS | PASS | PASS | PASS | Add a permanent UDP mapping, check forwarding, delete it, and check forwarding stops. |
| upnp-tcp-lifecycle | upnp | ipv4 | PASS | PASS | PASS | PASS | Add a permanent TCP mapping, check forwarding, delete it, and check forwarding stops. |
| upnp-renewal-adds-lost-rule | upnp | ipv4 | PASS | — | — | PASS | The firewall lost the rules of a mapping, and a renewal makes the mapping pass traffic again. |
| upnp-udp-lease-expiry | upnp | ipv4 | PASS | PASS | PASS | PASS | A mapping with a short lease forwards traffic and is removed by the daemon when the lease ends. |
| upnp-udp-and-tcp-same-port | upnp | ipv4 | PASS | PASS | PASS | PASS | UDP and TCP mappings share a port number, and deleting the UDP one leaves the TCP one in place. |
| upnp-delete-unknown-mapping | upnp | ipv4 | FAIL | PASS | FAIL | PASS | linux: UPnP response expected UPNP_714, got SUCCESS; debian-iptables: UPnP response expected UPNP_714, got SUCCESS |
| upnp-update-internal-port-then-delete | upnp | ipv4 | PASS | — | — | FAIL | openbsd: cleanup of UPnP udp/41255 returned UPNP_714 |
| upnp-repeated-renewals-then-delete-stops-forwarding | upnp | ipv4 | PASS | — | — | PASS | Add a UDP mapping, renew its lease three times, delete it once, and check forwarding stops. |
| owner-upnp-second-eport-on-pcp-filter-refused | pcp+upnp | ipv4 | FAIL | — | FAIL | FAIL | linux: UPnP response expected UPNP_729, got SUCCESS; debian-iptables: UPnP response expected UPNP_729, got SUCCESS; openbsd: UPnP response expected UPNP_729, got SUCCESS |
| owner-upnp-same-eport-other-iport-refused | pcp+upnp | ipv4 | FAIL | — | FAIL | FAIL | linux: UPnP response expected UPNP_729, got SUCCESS; debian-iptables: UPnP response expected UPNP_729, got SUCCESS; openbsd: UPnP response expected UPNP_729, got SUCCESS |
| owner-upnp-same-tuple-refused | pcp+upnp | ipv4 | FAIL | — | FAIL | FAIL | linux: UPnP response expected UPNP_729, got SUCCESS; debian-iptables: UPnP response expected UPNP_729, got SUCCESS; openbsd: UPnP response expected UPNP_729, got SUCCESS |
| owner-upnp-delete-of-pcp-refused | pcp+upnp | ipv4 | FAIL | — | FAIL | FAIL | linux: UPnP response expected UPNP_606, got SUCCESS; debian-iptables: UPnP response expected UPNP_606, got SUCCESS; openbsd: UPnP response expected UPNP_606, got SUCCESS |
| owner-upnp-two-eports-allowed | upnp | ipv4 | PASS | — | PASS | PASS | One owner keeps several external ports to one internal port. |
| owner-pcp-on-upnp-internal-refused | pcp+upnp | ipv4 | FAIL | — | FAIL | FAIL | linux: PCP response expected NOT_AUTHORIZED, got SUCCESS; debian-iptables: PCP response expected NOT_AUTHORIZED, got SUCCESS; openbsd: PCP response expected NOT_AUTHORIZED, got SUCCESS |
| owner-upnp-on-natpmp-internal-refused | natpmp+upnp | ipv4 | FAIL | — | FAIL | FAIL | linux: UPnP response expected UPNP_729, got SUCCESS; debian-iptables: UPnP response expected UPNP_729, got SUCCESS; openbsd: UPnP response expected UPNP_729, got SUCCESS |
| owner-peer-on-eport-of-other-internal-port-refused | pcp | ipv4 | FAIL | — | FAIL | FAIL | linux: PCP response expected CANNOT_PROVIDE_EXTERNAL, got SUCCESS; debian-iptables: PCP response expected CANNOT_PROVIDE_EXTERNAL, got SUCCESS; openbsd: PCP response expected CANNOT_PROVIDE_EXTERNAL, got UNSUPP_OPCODE |

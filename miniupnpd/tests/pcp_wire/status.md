# PCP/NAT-PMP Test Status

One column per platform; a run updates only its own platform's column (raw results: `pcp-wire-data/status-data.json`).

## Platforms

- **linux**: **248 PASS**, **67 XFAIL**, **26 FAIL**, **29 SKIP** (updated 2026-11-07T11:37:55+00:00; ipv4: target `pcp-router:5351`, protocol `both`, profile `baseline`, lifecycle `on`; ipv6: target `pcp-router:5351`, protocol `pcp`, profile `baseline`, lifecycle `on`)
- **freebsd**: **203 PASS**, **62 XFAIL**, **24 FAIL**, **58 SKIP** (updated 2026-11-03T13:37:11+00:00; ipv4: target `127.0.0.1:5351`, protocol `pcp`, profile `baseline`, lifecycle `on`; ipv6: target `127.0.0.1:5351`, protocol `pcp`, profile `baseline`, lifecycle `on`)
- Capture directory (linux, last run): `/pcp-wire-captures/2026-11-07_12-37-47.346085107_map-udplite-lifecycle`

## Results by section

### RFC 6887 PCP: Base protocol and malformed packets

Header handling, core opcodes, error responses, address-family behavior, and malformed datagrams.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| announce-v2 | pcp | ipv4 | PASS | PASS | Send a PCP v2 ANNOUNCE and accept success or network failure depending on gateway state. |
| announce-v2 | pcp | ipv6 | PASS | PASS | Send a PCP v2 ANNOUNCE and accept success or network failure depending on gateway state. |
| unsupported-version | pcp | ipv4 | PASS | PASS | Send unsupported PCP version 3 and check the supported-version error response. |
| unsupported-version | pcp | ipv6 | PASS | PASS | Send unsupported PCP version 3 and check the supported-version error response. |
| unsupported-opcode-v2 | pcp | ipv4 | PASS | PASS | Send an unknown PCP v2 opcode and check UNSUPP_OPCODE. |
| unsupported-opcode-v2 | pcp | ipv6 | PASS | PASS | Send an unknown PCP v2 opcode and check UNSUPP_OPCODE. |
| short-header | pcp | ipv4 | PASS | PASS | Send a two-byte PCP datagram; the server should silently discard it. |
| short-header | pcp | ipv6 | PASS | PASS | Send a two-byte PCP datagram; the server should silently discard it. |
| minimum-short-header | pcp | ipv4 | PASS | PASS | Send a three-byte PCP header and check the malformed-request response. |
| minimum-short-header | pcp | ipv6 | PASS | PASS | Send a three-byte PCP header and check the malformed-request response. |
| reserved-common-header | pcp | ipv4 | PASS | PASS | Set reserved common-header bits and check the server response. |
| reserved-common-header | pcp | ipv6 | PASS | PASS | Set reserved common-header bits and check the server response. |
| truncated-common-header | pcp | ipv4 | PASS | PASS | Remove one byte from the common PCP header. |
| truncated-common-header | pcp | ipv6 | PASS | PASS | Remove one byte from the common PCP header. |
| truncated-map-v1 | pcp | ipv4 | PASS | PASS | Send a PCP v1 MAP request without its MAP body. |
| truncated-map-v1 | pcp | ipv6 | PASS | PASS | Send a PCP v1 MAP request without its MAP body. |
| truncated-map-v2 | pcp | ipv4 | PASS | PASS | Send a PCP v2 MAP request without its MAP body. |
| truncated-map-v2 | pcp | ipv6 | PASS | PASS | Send a PCP v2 MAP request without its MAP body. |
| truncated-map-nonce-four-bytes | pcp | ipv4 | PASS | PASS | Truncate a v2 MAP body after only four of the twelve nonce bytes. |
| truncated-map-nonce-four-bytes | pcp | ipv6 | PASS | PASS | Truncate a v2 MAP body after only four of the twelve nonce bytes. |
| truncated-map-nonce-eight-bytes | pcp | ipv4 | PASS | PASS | Truncate a v2 MAP body after only eight of the twelve nonce bytes. |
| truncated-map-nonce-eight-bytes | pcp | ipv6 | PASS | PASS | Truncate a v2 MAP body after only eight of the twelve nonce bytes. |
| misaligned-length | pcp | ipv4 | PASS | PASS | Append one byte to ANNOUNCE and verify error-response padding. |
| misaligned-length | pcp | ipv6 | PASS | PASS | Append one byte to ANNOUNCE and verify error-response padding. |
| oversized-packet | pcp | ipv4 | PASS | PASS | Send a datagram larger than PCP_MAX_LEN and check the capped error response. |
| oversized-packet | pcp | ipv6 | PASS | PASS | Send a datagram larger than PCP_MAX_LEN and check the capped error response. |
| response-as-request | pcp | ipv4 | PASS | PASS | Set the response bit on a PCP packet and verify it is ignored. |
| response-as-request | pcp | ipv6 | PASS | PASS | Set the response bit on a PCP packet and verify it is ignored. |
| protocol-zero-nonzero-port | pcp | ipv4 | PASS | PASS | Send a MAP request using IP protocol zero and check invalid-parameter handling. |
| protocol-zero-nonzero-port | pcp | ipv6 | PASS | PASS | Send a MAP request using IP protocol zero and check invalid-parameter handling. |
| prefer-failure-address-mismatch | pcp | ipv4 | PASS | PASS | Suggest a non-local external address with PREFER_FAILURE and check the mismatch error. |
| ipv6-source-address | pcp | ipv6 | PASS | PASS | Send PCP over IPv6 using the actual IPv6 source address in the client field. |

### RFC 6887 PCP: Unsolicited ANNOUNCE

Multicast restart announcements sent by the gateway on its own, which a request/response case cannot observe. The fixture restarts the daemon from a cold start and records outgoing traffic on every LAN and WAN interface.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| startup-announce-lan-only | pcp | ipv4 | PASS | FAIL | freebsd: no ANNOUNCE to 224.0.0.1 on lan-0; no ANNOUNCE to 224.0.0.1 on lan-1; 2 ANNOUNCE packet(s) to 224.0.0.1 leaked on wan-0 |
| startup-announce-lan-only | pcp | ipv6 | PASS | FAIL | freebsd: no ANNOUNCE to ff02::1 on lan-0; no ANNOUNCE to ff02::1 on lan-1 |
| startup-announce-retransmission | pcp | ipv4 | FAIL | FAIL | linux: lan-0: 1 ANNOUNCE packet(s), expected 2-10; freebsd: no ANNOUNCE to 224.0.0.1 on lan-0; no ANNOUNCE to 224.0.0.1 on lan-1; 2 ANNOUNCE packet(s) to 224.0.0.1 leaked on wan-0 |
| startup-announce-retransmission | pcp | ipv6 | FAIL | FAIL | linux: lan-0: 1 ANNOUNCE packet(s), expected 2-10; freebsd: no ANNOUNCE to ff02::1 on lan-0; no ANNOUNCE to ff02::1 on lan-1 |

### RFC 6887 PCP: Mapping Update (rapid recovery)

Unsolicited MAP responses a gateway sends on its own after it repairs its mappings, for example when the external address changes. Each case renumbers the external address through a fixture after the client has created the mapping, and records the packets the client receives (fixtures/docker.sh provides wan-renumber; without it these cases report SKIP). The known_failure records that miniupnpd does not implement the mechanism.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| mapping-update-after-wan-change | pcp | ipv4 | XFAIL | SKIP | linux: no Mapping Update (unsolicited MAP response) after the external address change; expected: miniupnpd does not implement PCP Mapping Update (RFC 6887 §14.2); after a WAN address change it only multicasts an ANNOUNCE.; freebsd: requires wan-renumber fixture (not provided by any fixture yet) |
| mapping-update-three-transmissions | pcp | ipv4 | XFAIL | SKIP | linux: no Mapping Update (unsolicited MAP response) after the external address change; expected: miniupnpd does not implement PCP Mapping Update (RFC 6887 §14.2); after a WAN address change it only multicasts an ANNOUNCE.; freebsd: requires wan-renumber fixture (not provided by any fixture yet) |
| mapping-update-echoes-third-party | pcp | ipv4 | XFAIL | SKIP | linux: creating the mapping returned UNSUPP_OPTION; expected: miniupnpd does not implement PCP Mapping Update (RFC 6887 §14.2); after a WAN address change it only multicasts an ANNOUNCE.; freebsd: requires wan-renumber fixture (not provided by any fixture yet) |
| mapping-update-prefer-failure | pcp | ipv4 | XFAIL | SKIP | linux: creating the mapping returned MALFORMED_OPTION; expected: miniupnpd does not implement PCP Mapping Update (RFC 6887 §14.2); after a WAN address change it only multicasts an ANNOUNCE.; freebsd: requires wan-renumber fixture (not provided by any fixture yet) |
| mapping-update-omits-optional-options | pcp | ipv4 | XFAIL | SKIP | linux: no Mapping Update (unsolicited MAP response) after the external address change; expected: miniupnpd does not implement PCP Mapping Update (RFC 6887 §14.2); after a WAN address change it only multicasts an ANNOUNCE.; freebsd: requires wan-renumber fixture (not provided by any fixture yet) |
| mapping-update-stops-after-refresh | pcp | ipv4 | XFAIL | SKIP | linux: no Mapping Update (unsolicited MAP response) after the external address change; expected: miniupnpd does not implement PCP Mapping Update (RFC 6887 §14.2); after a WAN address change it only multicasts an ANNOUNCE.; freebsd: requires wan-renumber fixture (not provided by any fixture yet) |

### RFC 6887 PCP: Options and extensions

Option parsing, duplicate handling, unknown options, and optional or mandatory extension behavior.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| unknown-mandatory-option | pcp | ipv4 | PASS | PASS | Add an unknown mandatory option to MAP; expect unsupported-option handling. |
| unknown-mandatory-option | pcp | ipv6 | PASS | PASS | Add an unknown mandatory option to MAP; expect unsupported-option handling. |
| duplicate-prefer-failure | pcp | ipv4 | PASS | PASS | Repeat PREFER_FAILURE and check the duplicate-option error. |
| duplicate-prefer-failure | pcp | ipv6 | PASS | PASS | Repeat PREFER_FAILURE and check the duplicate-option error. |
| duplicate-third-party | pcp | ipv4 | PASS | PASS | Repeat THIRD_PARTY and check the duplicate-option error. |
| duplicate-third-party | pcp | ipv6 | PASS | PASS | Repeat THIRD_PARTY and check the duplicate-option error. |
| prefer-failure-without-suggestion | pcp | ipv4 | PASS | PASS | Set PREFER_FAILURE without suggesting an external address or port. |
| prefer-failure-without-suggestion | pcp | ipv6 | PASS | PASS | Set PREFER_FAILURE without suggesting an external address or port. |
| prefer-failure-port-unavailable | pcp | ipv4 | PASS | PASS | Occupy a public UDP port, request it for another MAP with PREFER_FAILURE, require CANNOT_PROVIDE_EXTERNAL, and verify the first mapping remains intact. |
| third-party-disabled | pcp | ipv4 | PASS | PASS | Request THIRD_PARTY mapping while third-party requests are disabled. |
| third-party-disabled | pcp | ipv6 | PASS | PASS | Request THIRD_PARTY mapping while third-party requests are disabled. |
| filter-wrong-length | pcp | ipv4 | PASS | PASS | Send a FILTER option with an invalid payload length. |
| filter-wrong-length | pcp | ipv6 | PASS | PASS | Send a FILTER option with an invalid payload length. |
| truncated-third-party-option | pcp | ipv4 | PASS | PASS | Declare a THIRD_PARTY payload that is absent from the packet. |
| truncated-third-party-option | pcp | ipv6 | PASS | PASS | Declare a THIRD_PARTY payload that is absent from the packet. |
| description-extension-ignored | pcp | ipv4 | PASS | PASS | Send an RFC 7220 DESCRIPTION option with UTF-8 client text. |
| description-extension-ignored | pcp | ipv6 | PASS | PASS | Send an RFC 7220 DESCRIPTION option with UTF-8 client text. |
| description-echo-renew-clear | pcp | ipv4 | FAIL | SKIP | linux: step 2 (lease_file): lease file: expected 1 line(s) of kind=PCP-M, internal_port=52801, nonce=d1d2d3d4d5d6d7d8d9dadbdc, label=Camera, found 0; freebsd: requires the daemon's PCP lease file (--state-file or --state-command) |
| description-truncated | pcp | ipv4 | FAIL | FAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 192-byte pcp response, got 272; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 192-byte pcp response, got 272 |
| description-invalid-utf8-ignored | pcp | ipv4 | FAIL | FAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72 |
| description-duplicate | pcp | ipv4 | FAIL | FAIL | linux: unexpected result code 0; freebsd: unexpected result code 0 |
| description-too-long | pcp | ipv4 | FAIL | FAIL | linux: unexpected result code 0; freebsd: unexpected result code 0 |
| description-peer-echo | pcp | ipv4 | FAIL | SKIP | linux: step 2 (lease_file): lease file: expected 1 line(s) of kind=PCP-P, internal_port=52806, nonce=d6d2d3d4d5d6d7d8d9dadbdc, label=Camera, found 0; freebsd: requires pcp-peer, unsupported on this platform |
| port-set-extension-ignored | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-extension-ignored | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| third-party-id-extension-unsupported | pcp | ipv4 | PASS | PASS | Send the RFC 7843 THIRD_PARTY_ID option. |
| third-party-id-extension-unsupported | pcp | ipv6 | PASS | PASS | Send the RFC 7843 THIRD_PARTY_ID option. |

### RFC 6887 PCP: Mapping lifecycle

Mutating MAP and PEER create, renew, and delete flows; enabled with --mutating.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| pcp-then-pmp-same-mapping-refused | both | ipv4 | PASS | PASS | Create a PCP-owned UDP mapping, then try to claim the exact tuple through NAT-PMP; the NAT-PMP operation is expected to fail. |
| pcp-then-pmp-port-conflict-preserves-pcp | both | ipv4 | PASS | PASS | Keep a PCP mapping on a requested public port, make a conflicting PMP request for another private port, then verify PMP uses a different port and PCP still renews its original mapping. |
| map-v1-lifecycle | pcp | ipv4 | PASS | PASS | Create, renew with changed lifetimes, and delete a PCP v1 MAP. |
| map-v2-lifecycle | pcp | ipv4 | PASS | PASS | Create, renew with changed lifetimes, and delete a PCP v2 MAP while checking its nonce. |
| map-v2-nonce-pattern-echo | pcp | ipv4 | PASS | PASS | Create and remove four mappings while checking zero, all-one, alternating-byte, and boundary-bit nonce echoes. Zero and all-one values are wire test patterns, not client randomness guidance. |
| map-v2-nonce-mismatch-refresh | pcp | ipv4 | FAIL | XFAIL | linux: unexpected lifecycle result code 0; freebsd: unexpected lifecycle result code 0; expected: The current backend accepts a MAP refresh with a mismatched nonce; RFC 6887 requires NOT_AUTHORIZED in the Simple Threat Model. |
| map-v2-nonce-identical-retry | pcp | ipv4 | PASS | PASS | Retry a create request with the same key and nonce, and require the existing external port to be reused. |
| peer-v2-lifecycle | pcp | ipv4 | FAIL | SKIP | linux: lease file /pcp-wire-daemon-state/miniupnpd.leases /pcp-wire-daemon-state/miniupnpd.leases6: PCP-P line for internal port 42001 is missing; freebsd: requires pcp-peer, unsupported on this platform |
| map-ipv6-renew-zero-suggestion-udp | pcp | ipv6 | PASS | — | RFC 6887 §11.3: a renewal of an IPv6 mapping, with a zero or a changed suggested port, returns the existing external port (the internal port), not 0 or the suggestion. |
| map-ipv6-renew-zero-suggestion-tcp | pcp | ipv6 | PASS | — | RFC 6887 §11.3: the TCP form of the #926 case; a client that restarts and reuses its nonce asks again with suggested port 0 and must get the internal port back. |
| map-ipv6-renew-wrong-nonce | pcp | ipv6 | PASS | — | RFC 6887 §11.2: another nonce may neither renew nor delete an IPv6 mapping (NOT_AUTHORIZED), and the owner's nonce still renews it afterwards. |
| map-renewal-extends-expiry | pcp | ipv4 | FAIL | — | linux: step 1 (pcp_map): response matched none of the expected replies: granted_lifetime was 120, expected 6 |
| map-suggested-external-ipv4-all-zeros | pcp | ipv4 | PASS | — | RFC 6887 §5, §11.1: ::ffff:0.0.0.0 in the suggested external address means no preference for an IPv4 address, so the MAP succeeds. |
| map-suggested-external-ipv4-all-zeros-prefer-failure | pcp | ipv4 | PASS | — | RFC 6887 §13.2: with PREFER_FAILURE, an all-zeros suggested address is not a mismatch; only the free suggested port binds the server. |
| map-udplite-lifecycle | pcp | ipv4 | PASS | — | RFC 3828, RFC 6887 §11.1: a MAP for UDP-Lite (protocol 136) is created, renewed with the same external port and deleted. |
| map-udplite-lifecycle | pcp | ipv6 | PASS | — | RFC 3828, RFC 6887 §11.1: a MAP for UDP-Lite (protocol 136) is created, renewed with the same external port and deleted. |

### RFC 6887 PCP: Edge cases

Additional packet framing, option validation, nonce ownership, renewal, deletion, PEER and epoch probes.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| common-header-truncated-4 | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-4 | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-7 | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-7 | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-8 | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-8 | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-12 | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-12 | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-16 | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-16 | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-20 | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-20 | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| map-body-truncated-28 | pcp | ipv4 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-28 | pcp | ipv6 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-36 | pcp | ipv4 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-36 | pcp | ipv6 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-40 | pcp | ipv4 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-40 | pcp | ipv6 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-44 | pcp | ipv4 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-44 | pcp | ipv6 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-48 | pcp | ipv4 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-48 | pcp | ipv6 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-52 | pcp | ipv4 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-52 | pcp | ipv6 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-56 | pcp | ipv4 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-56 | pcp | ipv6 | PASS | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-24 | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-24 | pcp | ipv6 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-36 | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-36 | pcp | ipv6 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-40 | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-40 | pcp | ipv6 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-60 | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-60 | pcp | ipv6 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-64 | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-64 | pcp | ipv6 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-68 | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-68 | pcp | ipv6 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-72 | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-72 | pcp | ipv6 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-76 | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-body-truncated-76 | pcp | ipv6 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| announce-client-address-mismatch | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| announce-client-address-mismatch | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| map-client-address-mismatch | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| map-client-address-mismatch | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| announce-misaligned-1 | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| announce-misaligned-1 | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| announce-misaligned-2 | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| announce-misaligned-2 | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| announce-misaligned-3 | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| announce-misaligned-3 | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| oversized-announce-1101 | pcp | ipv4 | PASS | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1101 | pcp | ipv6 | PASS | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1102 | pcp | ipv4 | PASS | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1102 | pcp | ipv6 | PASS | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1103 | pcp | ipv4 | PASS | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1103 | pcp | ipv6 | PASS | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1105 | pcp | ipv4 | PASS | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1105 | pcp | ipv6 | PASS | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| prefer-failure-invalid-length-1 | pcp | ipv4 | PASS | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-1 | pcp | ipv6 | PASS | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-2 | pcp | ipv4 | PASS | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-2 | pcp | ipv6 | PASS | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-4 | pcp | ipv4 | PASS | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-4 | pcp | ipv6 | PASS | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| optional-option-length-overrun | pcp | ipv4 | PASS | PASS | RFC 6887 §7.3: malformed overall option structure is an error even when its option code is optional. |
| optional-option-length-overrun | pcp | ipv6 | PASS | PASS | RFC 6887 §7.3: malformed overall option structure is an error even when its option code is optional. |
| filter-invalid-ipv4-prefix-129 | pcp | ipv4 | PASS | PASS | RFC 6887 §13.3: reject an out-of-range FILTER prefix length. |
| filter-invalid-ipv4-prefix-95 | pcp | ipv4 | PASS | PASS | RFC 6887 §13.3: reject an out-of-range FILTER prefix length. |
| filter-invalid-ipv4-prefix-24 | pcp | ipv4 | PASS | — | RFC 6887 §13.3: reject an IPv4 FILTER sent with a bare IPv4 mask length (/24) instead of 96 + 24. |
| filter-invalid-ipv6-prefix-129 | pcp | ipv4 | PASS | PASS | RFC 6887 §13.3: reject an out-of-range FILTER prefix length. |
| filter-on-map-deletion | pcp | ipv4 | PASS | PASS | RFC 6887 §13.3: FILTER in a MAP deletion must return MALFORMED_OPTION. |
| filter-on-map-deletion | pcp | ipv6 | PASS | PASS | RFC 6887 §13.3: FILTER in a MAP deletion must return MALFORMED_OPTION. |
| prefer-failure-on-map-deletion | pcp | ipv4 | PASS | PASS | RFC 6887 §11.3: a mandatory option that does not make sense for deletion returns MALFORMED_OPTION. |
| prefer-failure-on-map-deletion | pcp | ipv6 | PASS | PASS | RFC 6887 §11.3: a mandatory option that does not make sense for deletion returns MALFORMED_OPTION. |
| prefer-failure-zero-port-explicit-address | pcp | ipv4 | PASS | FAIL | freebsd: step 1 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0 |
| map-udp-renew-changed-suggestion | pcp | ipv4 | FAIL | FAIL | linux: step 2 (pcp_map): response matched none of the expected replies: port was 50217, expected 50117; freebsd: step 2 (pcp_map): response matched none of the expected replies: port was 50217, expected 50117 |
| map-udp-renew-zero-suggestion | pcp | ipv4 | PASS | PASS | RFC 6887 §11.3: renewal with the same mapping key and nonce must return the existing external port, regardless of a changed or zero suggestion. |
| map-udp-delete-nonexistent | pcp | ipv4 | PASS | PASS | RFC 6887 §15.1: deleting a nonexistent mapping succeeds, making deletion retransmissions safe. |
| map-udp-delete-identical-retry | pcp | ipv4 | PASS | PASS | RFC 6887 §15.1: repeated deletion returns SUCCESS with lifetime zero. |
| map-tcp-renew-changed-suggestion | pcp | ipv4 | FAIL | FAIL | linux: step 2 (pcp_map): response matched none of the expected replies: port was 50206, expected 50106; freebsd: step 2 (pcp_map): response matched none of the expected replies: port was 50206, expected 50106 |
| map-tcp-renew-zero-suggestion | pcp | ipv4 | PASS | PASS | RFC 6887 §11.3: renewal with the same mapping key and nonce must return the existing external port, regardless of a changed or zero suggestion. |
| map-tcp-delete-nonexistent | pcp | ipv4 | PASS | PASS | RFC 6887 §15.1: deleting a nonexistent mapping succeeds, making deletion retransmissions safe. |
| map-tcp-delete-identical-retry | pcp | ipv4 | PASS | PASS | RFC 6887 §15.1: repeated deletion returns SUCCESS with lifetime zero. |
| map-nonce-mismatch-changed-port | pcp | ipv4 | FAIL | FAIL | linux: step 2 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0; freebsd: step 2 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0 |
| map-wrong-nonce-delete-preserves-original | pcp | ipv4 | PASS | FAIL | freebsd: step 2 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0 |
| map-delete-port-zero-keeps-other-nonce | pcp | ipv4 | FAIL | — | linux: step 4 (pcp_map): response matched none of the expected replies: unexpected pcp result code 2 |
| map-error-no-state-unknown-mandatory | pcp | ipv4 | PASS | PASS | RFC 6887 §7.3: a rejected create must leave no nonce ownership behind; a fresh nonce must subsequently create the same tuple. |
| map-error-no-state-bad-prefer-failure | pcp | ipv4 | PASS | PASS | RFC 6887 §7.3: a rejected create must leave no nonce ownership behind; a fresh nonce must subsequently create the same tuple. |
| optional-unknown-option-padding-1 | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| optional-unknown-option-padding-2 | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| optional-unknown-option-padding-3 | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| map-reserved-body-ignored-and-cleared | pcp | ipv4 | PASS | FAIL | freebsd: step 1 (pcp_map): response matched none of the expected replies: protocol_and_reserved was 301989887, expected 285212672 |
| peer-reserved-body-ignored-and-cleared | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| peer-prefer-failure-forbidden | pcp | ipv4 | PASS | SKIP | freebsd: requires pcp-peer, unsupported on this platform |
| announce-epoch-and-reserved-response | pcp | ipv4 | PASS | PASS | RFC 6887 §§7.2, 8.5: repeated ANNOUNCE replies have nondecreasing epochs and zero common reserved fields; this does not check reboot reset or clock rate. |
| announce-epoch-and-reserved-response | pcp | ipv6 | PASS | PASS | RFC 6887 §§7.2, 8.5: repeated ANNOUNCE replies have nondecreasing epochs and zero common reserved fields; this does not check reboot reset or clock rate. |
| announce-ignores-lifetime-300 | pcp | ipv4 | PASS | FAIL | freebsd: ANNOUNCE lifetime was 300, expected 0 |
| announce-ignores-lifetime-300 | pcp | ipv6 | PASS | FAIL | freebsd: ANNOUNCE lifetime was 300, expected 0 |
| announce-ignores-lifetime-4294967295 | pcp | ipv4 | PASS | FAIL | freebsd: ANNOUNCE lifetime was 600, expected 0 |
| announce-ignores-lifetime-4294967295 | pcp | ipv6 | PASS | FAIL | freebsd: ANNOUNCE lifetime was 600, expected 0 |
| announce-mandatory-unknown-option | pcp | ipv4 | PASS | FAIL | freebsd: unexpected result code 0 |
| announce-mandatory-unknown-option | pcp | ipv6 | PASS | FAIL | freebsd: unexpected result code 0 |
| announce-optional-unknown-option | pcp | ipv4 | PASS | PASS | RFC 6887 §§7.3, 14.1: apply mandatory/optional option processing to ANNOUNCE; omit ignored options on success. |
| announce-optional-unknown-option | pcp | ipv6 | PASS | PASS | RFC 6887 §§7.3, 14.1: apply mandatory/optional option processing to ANNOUNCE; omit ignored options on success. |
| map-reserved-pcp-udp-port-5350 | pcp | ipv4 | PASS | PASS | RFC 6887 §11.3: external UDP ports 5350 and 5351 cannot be mapped to clients; with PREFER_FAILURE return CANNOT_PROVIDE_EXTERNAL. |
| map-reserved-pcp-udp-port-5351 | pcp | ipv4 | PASS | PASS | RFC 6887 §11.3: external UDP ports 5350 and 5351 cannot be mapped to clients; with PREFER_FAILURE return CANNOT_PROVIDE_EXTERNAL. |
| peer-wrong-nonce-refresh | pcp | ipv4 | FAIL | SKIP | linux: step 2 (pcp_peer): response matched none of the expected replies: unexpected pcp result code 0; freebsd: requires pcp-peer, unsupported on this platform |
| map-tcp-create-renew-delete | pcp | ipv4 | PASS | PASS | RFC 6887 §§11, 15.1: exercise a TCP MAP lifecycle separately from the existing UDP lifecycle. |
| map-error-echo-opcode-and-options | pcp | ipv4 | PASS | PASS | RFC 6887 §§7.3, 8.2: error responses preserve the complete opcode body and options. |
| map-error-echo-opcode-and-options | pcp | ipv6 | PASS | PASS | RFC 6887 §§7.3, 8.2: error responses preserve the complete opcode body and options. |
| unsupported-opcode-echo-payload | pcp | ipv4 | PASS | PASS | RFC 6887 §8.2: preserve unknown opcode payload bytes in error responses. |
| unsupported-opcode-echo-payload | pcp | ipv6 | PASS | PASS | RFC 6887 §8.2: preserve unknown opcode payload bytes in error responses. |
| long-error-lifetime-default | pcp | ipv4 | PASS | PASS | RFC 6887 §7.4: long-lived errors SHOULD default to a 30-minute error lifetime. |
| long-error-lifetime-default | pcp | ipv6 | PASS | PASS | RFC 6887 §7.4: long-lived errors SHOULD default to a 30-minute error lifetime. |

### RFC 7652 PCP: Authentication extension profile

PA-Initiation and EAP exchange support. The daemon does not implement this optional authentication profile; the probe is recorded as an expected failure.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| auth-extension-unsupported | pcp | ipv4 | PASS | PASS | Send the RFC 7652 AUTHENTICATION_TAG option without an established PA session. |
| auth-extension-unsupported | pcp | ipv6 | PASS | PASS | Send the RFC 7652 AUTHENTICATION_TAG option without an established PA session. |
| auth-initiation-unsupported | pcp | ipv4 | PASS | PASS | Send a valid RFC 7652 PA-Initiation with a NONCE; baseline daemon rejects the AUTHENTICATION opcode. |
| auth-initiation-unsupported | pcp | ipv6 | PASS | PASS | Send a valid RFC 7652 PA-Initiation with a NONCE; baseline daemon rejects the AUTHENTICATION opcode. |
| rfc7652-initiation-supported | pcp | ipv4 | XFAIL | XFAIL | linux: unexpected result code 4; expected: The optional RFC 7652 authentication profile is not implemented by miniupnpd.; freebsd: unexpected result code 4; expected: The optional RFC 7652 authentication profile is not implemented by miniupnpd. |
| rfc7652-initiation-supported | pcp | ipv6 | XFAIL | XFAIL | linux: unexpected result code 4; expected: The optional RFC 7652 authentication profile is not implemented by miniupnpd.; freebsd: unexpected result code 4; expected: The optional RFC 7652 authentication profile is not implemented by miniupnpd. |
| auth-initiation-invalid-sequence | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-initiation-invalid-sequence | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-valid-next | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-valid-next | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-large-jump | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-large-jump | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-replay-modified | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-replay-modified | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-eap-reply-unsupported | pcp | ipv4 | PASS | PASS | Send an RFC 7652 EAP response PA-Client message without an established session. |
| auth-eap-reply-unsupported | pcp | ipv6 | PASS | PASS | Send an RFC 7652 EAP response PA-Client message without an established session. |
| rfc7652-nonce-zero-echo | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-zero-echo | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-all-ones-echo | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-all-ones-echo | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-high-low-bits-echo | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-high-low-bits-echo | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-duplicate | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-duplicate | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-short | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-short | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-long | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-long | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-reserved-bits | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-reserved-bits | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL); freebsd: prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |

### RFC 7753 PCP Extension for Port-Set Allocation: Fallback and framing

IPv4/IPv6 single-port fallback for unprocessed option 130, with TCP/UDP lifecycle and common framing checks.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| port-set-single-port-fallback-size-2-flags-0 | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-2-flags-0 | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-16-flags-0 | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-16-flags-0 | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-65535-flags-0 | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-65535-flags-0 | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-1 | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-1 | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-254 | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-254 | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-option-reserved-byte-ignored | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-option-reserved-byte-ignored | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-truncated-option-envelope | pcp | ipv4 | PASS | PASS | RFC 6887 §7.3 and RFC 7753 §4: reject an option declaring five payload bytes when only four are present, even if the option is unprocessed. |
| port-set-truncated-option-envelope | pcp | ipv6 | PASS | PASS | RFC 6887 §7.3 and RFC 7753 §4: reject an option declaring five payload bytes when only four are present, even if the option is unprocessed. |
| port-set-single-port-renew-and-delete | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/port-set-extension-ignored (XFAIL); freebsd: prerequisite did not pass: pcp/port-set-extension-ignored (XFAIL) |
| port-set-single-port-renew-and-delete | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/port-set-extension-ignored (XFAIL); freebsd: prerequisite did not pass: pcp/port-set-extension-ignored (XFAIL) |
| port-set-extension-ignored-tcp | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-extension-ignored-tcp | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-2-flags-0-tcp | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-2-flags-0-tcp | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-16-flags-0-tcp | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-16-flags-0-tcp | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-65535-flags-0-tcp | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-65535-flags-0-tcp | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-1-tcp | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-1-tcp | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-254-tcp | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-254-tcp | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-option-reserved-byte-ignored-tcp | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-option-reserved-byte-ignored-tcp | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-truncated-option-envelope-tcp | pcp | ipv4 | PASS | PASS | RFC 6887 §7.3 and RFC 7753 §4: reject an option declaring five payload bytes when only four are present, even if the option is unprocessed. |
| port-set-truncated-option-envelope-tcp | pcp | ipv6 | PASS | PASS | RFC 6887 §7.3 and RFC 7753 §4: reject an option declaring five payload bytes when only four are present, even if the option is unprocessed. |
| port-set-single-port-renew-and-delete-tcp | pcp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: pcp/port-set-extension-ignored-tcp (XFAIL); freebsd: prerequisite did not pass: pcp/port-set-extension-ignored-tcp (XFAIL) |
| port-set-single-port-renew-and-delete-tcp | pcp | ipv6 | SKIP | SKIP | linux: prerequisite did not pass: pcp/port-set-extension-ignored-tcp (XFAIL); freebsd: prerequisite did not pass: pcp/port-set-extension-ignored-tcp (XFAIL) |
| port-set-fallback-udp-zero-size | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-zero-size | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-duplicate | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-duplicate | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-first-port-mismatch | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-first-port-mismatch | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-zero-length | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-zero-length | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-short-payload | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-short-payload | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-long-payload | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-long-payload | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-with-prefer-failure | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-with-prefer-failure | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-envelope-overrun-udp-5-0 | pcp | ipv4 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-5-0 | pcp | ipv6 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-5-4 | pcp | ipv4 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-5-4 | pcp | ipv6 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-9-8 | pcp | ipv4 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-9-8 | pcp | ipv6 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-65535-0 | pcp | ipv4 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-65535-0 | pcp | ipv6 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-fallback-tcp-zero-size | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-zero-size | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-duplicate | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-duplicate | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-first-port-mismatch | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-first-port-mismatch | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-zero-length | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-zero-length | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-short-payload | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-short-payload | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-long-payload | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-long-payload | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-with-prefer-failure | pcp | ipv4 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-with-prefer-failure | pcp | ipv6 | XFAIL | XFAIL | linux: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented.; freebsd: step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-envelope-overrun-tcp-5-0 | pcp | ipv4 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-5-0 | pcp | ipv6 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-5-4 | pcp | ipv4 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-5-4 | pcp | ipv6 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-9-8 | pcp | ipv4 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-9-8 | pcp | ipv6 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-65535-0 | pcp | ipv4 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-65535-0 | pcp | ipv6 | PASS | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |

### RFC 6886 NAT-PMP: Protocol behavior

Public address, mapping request validation, malformed traffic, and mutating UDP/TCP mapping lifecycles.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| public-address | natpmp | ipv4 | PASS | PASS | Request the NAT-PMP public address and validate its response. |
| unsupported-opcode | natpmp | ipv4 | PASS | PASS | Send an unknown NAT-PMP opcode and check the unsupported-opcode result. |
| truncated-mapping | natpmp | ipv4 | PASS | PASS | Send only a NAT-PMP mapping opcode; the incomplete request should be ignored. |
| response-as-request | natpmp | ipv4 | PASS | PASS | Set the response bit on a NAT-PMP packet and verify it is ignored. |
| zero-private-port | natpmp | ipv4 | PASS | PASS | Request a NAT-PMP mapping with private port zero and check refusal. |
| udp-mapping-lifecycle | natpmp | ipv4 | PASS | PASS | Create, renew, and delete a NAT-PMP UDP mapping. |
| tcp-mapping-lifecycle | natpmp | ipv4 | PASS | PASS | Create, renew, and delete a NAT-PMP TCP mapping. |
| truncated-udp-length-0 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 0-byte mapping request without creating a mapping. |
| truncated-udp-length-1 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 1-byte mapping request without creating a mapping. |
| truncated-udp-length-3 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 3-byte mapping request without creating a mapping. |
| truncated-udp-length-4 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 4-byte mapping request without creating a mapping. |
| truncated-udp-length-5 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 5-byte mapping request without creating a mapping. |
| truncated-udp-length-6 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 6-byte mapping request without creating a mapping. |
| truncated-udp-length-7 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 7-byte mapping request without creating a mapping. |
| truncated-udp-length-8 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 8-byte mapping request without creating a mapping. |
| truncated-udp-length-9 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 9-byte mapping request without creating a mapping. |
| truncated-udp-length-10 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 10-byte mapping request without creating a mapping. |
| truncated-udp-length-11 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 11-byte mapping request without creating a mapping. |
| truncated-tcp-length-3 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 3-byte mapping request without creating a mapping. |
| truncated-tcp-length-4 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 4-byte mapping request without creating a mapping. |
| truncated-tcp-length-5 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 5-byte mapping request without creating a mapping. |
| truncated-tcp-length-6 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 6-byte mapping request without creating a mapping. |
| truncated-tcp-length-7 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 7-byte mapping request without creating a mapping. |
| truncated-tcp-length-8 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 8-byte mapping request without creating a mapping. |
| truncated-tcp-length-9 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 9-byte mapping request without creating a mapping. |
| truncated-tcp-length-10 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 10-byte mapping request without creating a mapping. |
| truncated-tcp-length-11 | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: discard an incomplete 11-byte mapping request without creating a mapping. |
| response-opcode-129-ignored | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.5: silently ignore packets with the response bit set, including mapping opcodes. |
| response-opcode-130-ignored | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.5: silently ignore packets with the response bit set, including mapping opcodes. |
| response-opcode-255-ignored | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.5: silently ignore packets with the response bit set, including mapping opcodes. |
| unsupported-opcode-echo-body | natpmp | ipv4 | FAIL | FAIL | linux: expected 12-byte response, got 8; freebsd: expected 12-byte response, got 8 |
| refused-mapping-response-fields | natpmp | ipv4 | FAIL | FAIL | linux: unassigned external port was 49000, expected 0; freebsd: unassigned external port was 49000, expected 0 |
| reserved-mapping-bits-ignored | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: ignore nonzero reserved request bits and grant an otherwise valid mapping. |
| udp-delete-idempotent-and-ignore-public-port | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.4: ignore the suggested public port when deleting; repeated deletion returns success, private port, external port zero and lifetime zero. |
| udp-retry-changed-suggestion | natpmp | ipv4 | FAIL | FAIL | linux: step 2 (natpmp): response matched none of the expected replies: external_port was 49111, expected 49011; freebsd: step 2 (natpmp): response matched none of the expected replies: external_port was 49111, expected 49011 |
| udp-identical-retry | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: retransmitting an identical mapping request preserves the public port. |
| udp-short-lease-not-increased | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: a one-second request should not be granted a longer lifetime (SHOULD NOT). |
| tcp-delete-idempotent-and-ignore-public-port | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.4: ignore the suggested public port when deleting; repeated deletion returns success, private port, external port zero and lifetime zero. |
| tcp-retry-changed-suggestion | natpmp | ipv4 | FAIL | FAIL | linux: step 2 (natpmp): response matched none of the expected replies: external_port was 49112, expected 49012; freebsd: step 2 (natpmp): response matched none of the expected replies: external_port was 49112, expected 49012 |
| tcp-identical-retry | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: retransmitting an identical mapping request preserves the public port. |
| tcp-short-lease-not-increased | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: a one-second request should not be granted a longer lifetime (SHOULD NOT). |
| same-protocol-conflict-retry | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: a public-port conflict gets another port; retransmission keeps that alternate port and does not displace the first mapping. |
| same-client-tcp-udp-companion-port | natpmp | ipv4 | PASS | PASS | RFC 6886 §3.3: the same client can map TCP and UDP to the same public port; deleting UDP must preserve the TCP mapping. |
| public-address-epoch-monotonic | natpmp | ipv4 | PASS | PASS | RFC 6886 §§3.2, 3.6: repeated public-address replies use a nondecreasing epoch. This checks continuity, not clock rate or reset behavior. |
| udp-delete-all-preserves-tcp | natpmp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: natpmp/udp-retry-changed-suggestion (FAIL), natpmp/tcp-retry-changed-suggestion (FAIL); freebsd: prerequisite did not pass: natpmp/udp-retry-changed-suggestion (FAIL), natpmp/tcp-retry-changed-suggestion (FAIL) |
| udp-mapping-expires | natpmp | ipv4 | SKIP | SKIP | linux: prerequisite did not pass: natpmp/udp-retry-changed-suggestion (FAIL); freebsd: prerequisite did not pass: natpmp/udp-retry-changed-suggestion (FAIL) |
| udp-delete-mapping-with-other-public-port | natpmp | ipv4 | PASS | — | RFC 6886 §3.4: a deletion finds the mapping by its private port; with a public port other than the private port the mapping is removed and its public port can be used again. |

### Lease files across a daemon restart and expiry

The daemon records its PCP and NAT-PMP mappings in lease_file (IPv4) and lease_file6 (IPv6) and creates them again after a restart. The driver runs each lease-restart case in two phases, restarting the daemon in between: "create" makes the mappings and checks the lease file lines (and keeps them), "verify" checks that the same lines are back, then deletes the mappings. The lease-expiry cases need the short-lifetime profile (pcp_min_lifetime_override=2).

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| lease-restart-ipv4 | pcp | ipv4 | FAIL | SKIP | linux: step 5 (lease_file): lease file: expected 4 line(s) of kind=PCP-F, family=IPv4, internal_port=43333, found 0; freebsd: requires pcp-peer, unsupported on this platform |
| lease-restart-ipv6 | pcp | ipv6 | FAIL | SKIP | linux: step 4 (lease_file): lease file: expected 4 line(s) of kind=PCP-F, family=IPv6, internal_port=43335, found 0; freebsd: requires lease-restart driver (--phase) |
| lease-min-lifetime-without-option | pcp | ipv4 | PASS | — | min_lifetime=2 without pcp_min_lifetime_override does not go under the 120 s minimum. |

### Two LAN clients

Mappings of one LAN client are owned by it; a second client on another LAN address (the runner's --second-client) cannot take over, delete or reuse them.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| pcp-two-clients-same-suggested-port | pcp | ipv4 | PASS | — | The second client asks for the external port the first client holds; it gets a mapping on another external port. |
| pcp-two-clients-delete-is-isolated | pcp | ipv4 | PASS | — | A delete from the second client with the first client's nonce and internal port leaves the first client's mapping; its external port is still taken. |
| natpmp-two-clients-same-public-port | natpmp | ipv4 | PASS | — | The second client asks for the public port the first client holds; it gets another public port. |
| natpmp-two-clients-delete-all-isolated | natpmp | ipv4 | PASS | — | A UDP delete-all of the second client leaves the first client's UDP mapping; its public port is still taken. |
| natpmp-two-clients-companion-port-reserved | natpmp | ipv4 | FAIL | — | linux: step 2 (natpmp): response matched none of the expected replies: port unexpectedly equals 47313 |
| natpmp-same-client-maps-companion-port | natpmp | ipv4 | PASS | — | A client which maps TCP gets the same public port on UDP; the companion port is reserved for it, not against it. |
| pcp-two-clients-companion-port-reserved | pcp | ipv4 | FAIL | — | linux: step 2 (pcp_map): response matched none of the expected replies: port unexpectedly equals 47303 |
| pcp-same-client-maps-companion-port | pcp | ipv4 | PASS | — | A client which maps TCP gets the same external port on UDP, even with PREFER_FAILURE. |
| natpmp-holder-blocks-pcp-other-client | pcp | ipv4 | FAIL | — | linux: step 2 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0 |

### RFC 6887 PCP: Many mappings

Many PEER mappings from one client, created, updated and deleted with a bounded number of requests in flight.

| Case | Protocol | Family | linux | freebsd | Result / note |
|---|---|---|---|---|---|
| peer-bulk-10000-update | pcp | ipv4 | SKIP | — | linux: requires --scale (a long run, not part of the default runs) |

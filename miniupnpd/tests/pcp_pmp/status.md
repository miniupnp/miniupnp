# PCP/NAT-PMP Test Status

Updated: 2026-10-31T19:49:43+00:00

## Run

- Target: `pcp-router:5351`
- Protocol: `both`
- Address family: `ipv4`
- Server profile: `baseline`
- Mapping lifecycle tests: `enabled`
- Totals: **112 PASS**, **38 XFAIL**, **40 FAIL**, **15 SKIP**
- Capture directory: `/pcp-pmp-captures/2026-10-31_20-49-10.894844616_all`

## Results by section

### RFC 6887 PCP: Base protocol and malformed packets

Header handling, core opcodes, error responses, address-family behavior, and malformed datagrams.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| announce-v2 | pcp | PASS | Send a PCP v2 ANNOUNCE and accept success or network failure depending on gateway state. |
| unsupported-version | pcp | PASS | Send unsupported PCP version 3 and check the supported-version error response. |
| unsupported-opcode-v2 | pcp | PASS | Send an unknown PCP v2 opcode and check UNSUPP_OPCODE. |
| short-header | pcp | PASS | Send a two-byte PCP datagram; the server should silently discard it. |
| minimum-short-header | pcp | FAIL | unexpected PCP response version 0 |
| reserved-common-header | pcp | PASS | Set reserved common-header bits and check the server response. |
| truncated-common-header | pcp | FAIL | unexpected PCP response version 0 |
| truncated-map-v1 | pcp | PASS | Send a PCP v1 MAP request without its MAP body. |
| truncated-map-v2 | pcp | PASS | Send a PCP v2 MAP request without its MAP body. |
| truncated-map-nonce-four-bytes | pcp | PASS | Truncate a v2 MAP body after only four of the twelve nonce bytes. |
| truncated-map-nonce-eight-bytes | pcp | PASS | Truncate a v2 MAP body after only eight of the twelve nonce bytes. |
| misaligned-length | pcp | FAIL | unexpected PCP response version 0 |
| oversized-packet | pcp | FAIL | unexpected result code 0 |
| response-as-request | pcp | PASS | Set the response bit on a PCP packet and verify it is ignored. |
| protocol-zero-nonzero-port | pcp | PASS | Send a MAP request using IP protocol zero and check invalid-parameter handling. |
| prefer-failure-address-mismatch | pcp | PASS | Suggest a non-local external address with PREFER_FAILURE and check the mismatch error. |

### RFC 6887 PCP: Options and extensions

Option parsing, duplicate handling, unknown options, and optional or mandatory extension behavior.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| unknown-mandatory-option | pcp | PASS | Add an unknown mandatory option to MAP; expect unsupported-option handling. |
| duplicate-prefer-failure | pcp | PASS | Repeat PREFER_FAILURE and check the duplicate-option error. |
| duplicate-third-party | pcp | PASS | Repeat THIRD_PARTY and check the duplicate-option error. |
| prefer-failure-without-suggestion | pcp | PASS | Set PREFER_FAILURE without suggesting an external address or port. |
| prefer-failure-port-unavailable | pcp | PASS | Occupy a public UDP port, request it for another MAP with PREFER_FAILURE, require CANNOT_PROVIDE_EXTERNAL, and verify the first mapping remains intact. |
| third-party-disabled | pcp | PASS | Request THIRD_PARTY mapping while third-party requests are disabled. |
| filter-wrong-length | pcp | PASS | Send a FILTER option with an invalid payload length. |
| truncated-third-party-option | pcp | PASS | Declare a THIRD_PARTY payload that is absent from the packet. |
| description-extension-ignored | pcp | PASS | Send an RFC 7220 DESCRIPTION option with UTF-8 client text. |
| port-set-extension-ignored | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| third-party-id-extension-unsupported | pcp | PASS | Send the RFC 7843 THIRD_PARTY_ID option. |

### RFC 6887 PCP: Mapping lifecycle

Mutating MAP and PEER create, renew, and delete flows; enabled with --mutating.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| pcp-then-pmp-same-mapping-refused | both | XFAIL | step 2 (natpmp): response matched none of the expected replies: unexpected natpmp result code 0; expected: Current backend allows NAT-PMP to replace a PCP-owned mapping with the same tuple; this case requires the PMP attempt to be refused. |
| pcp-then-pmp-port-conflict-preserves-pcp | both | PASS | Keep a PCP mapping on a requested public port, make a conflicting PMP request for another private port, then verify PMP uses a different port and PCP still renews its original mapping. |
| map-v1-lifecycle | pcp | PASS | Create, renew with changed lifetimes, and delete a PCP v1 MAP. |
| map-v2-lifecycle | pcp | PASS | Create, renew with changed lifetimes, and delete a PCP v2 MAP while checking its nonce. |
| map-v2-nonce-pattern-echo | pcp | PASS | Create and remove four mappings while checking zero, all-one, alternating-byte, and boundary-bit nonce echoes. Zero and all-one values are wire test patterns, not client randomness guidance. |
| map-v2-nonce-mismatch-refresh | pcp | XFAIL | unexpected lifecycle result code 0; expected: The current backend accepts a MAP refresh with a mismatched nonce; RFC 6887 requires NOT_AUTHORIZED in the Simple Threat Model. |
| map-v2-nonce-identical-retry | pcp | PASS | Retry a create request with the same key and nonce, and require the existing external port to be reused. |
| peer-v2-lifecycle | pcp | PASS | Create and delete a PCP v2 PEER mapping for the configured remote peer. |

### RFC 6887 PCP: Edge cases

Additional packet framing, option validation, nonce ownership, renewal, deletion, PEER and epoch probes.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| common-header-truncated-4 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-7 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-8 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-12 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-16 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-20 | pcp | FAIL | unexpected PCP response version 0 |
| map-body-truncated-28 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-36 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-40 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-44 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-48 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-52 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-56 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-24 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-36 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-40 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-60 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-64 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-68 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-72 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-76 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| announce-client-address-mismatch | pcp | FAIL | unexpected result code 0 |
| map-client-address-mismatch | pcp | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| announce-misaligned-1 | pcp | FAIL | unexpected PCP response version 0 |
| announce-misaligned-2 | pcp | FAIL | unexpected PCP response version 0 |
| announce-misaligned-3 | pcp | FAIL | unexpected PCP response version 0 |
| oversized-announce-1101 | pcp | FAIL | unexpected result code 0 |
| oversized-announce-1102 | pcp | FAIL | unexpected result code 0 |
| oversized-announce-1103 | pcp | FAIL | unexpected result code 0 |
| oversized-announce-1105 | pcp | FAIL | unexpected result code 0 |
| prefer-failure-invalid-length-1 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-2 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-4 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| optional-option-length-overrun | pcp | PASS | RFC 6887 §7.3: malformed overall option structure is an error even when its option code is optional. |
| filter-invalid-ipv4-prefix-129 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0; expected: FILTER handling is incomplete; miniupnpd checks the option length but does not validate its prefix length. |
| filter-invalid-ipv4-prefix-95 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0; expected: FILTER handling is incomplete; miniupnpd checks the option length but does not validate its prefix length. |
| filter-invalid-ipv6-prefix-129 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0; expected: FILTER handling is incomplete; miniupnpd checks the option length but does not validate its prefix length. |
| filter-on-map-deletion | pcp | FAIL | unexpected result code 8 |
| prefer-failure-on-map-deletion | pcp | FAIL | unexpected result code 8 |
| prefer-failure-zero-port-explicit-address | pcp | FAIL | step 1 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0 |
| map-udp-renew-changed-suggestion | pcp | FAIL | step 2 (pcp_map): response matched none of the expected replies: port was 50217, expected 50117 |
| map-udp-renew-zero-suggestion | pcp | PASS | RFC 6887 §11.3: renewal with the same mapping key and nonce must return the existing external port, regardless of a changed or zero suggestion. |
| map-udp-delete-nonexistent | pcp | FAIL | step 1 (pcp_map): response matched none of the expected replies: unexpected pcp result code 8 |
| map-udp-delete-identical-retry | pcp | FAIL | step 3 (pcp_map): response matched none of the expected replies: unexpected pcp result code 8 |
| map-tcp-renew-changed-suggestion | pcp | FAIL | step 2 (pcp_map): response matched none of the expected replies: port was 50206, expected 50106 |
| map-tcp-renew-zero-suggestion | pcp | PASS | RFC 6887 §11.3: renewal with the same mapping key and nonce must return the existing external port, regardless of a changed or zero suggestion. |
| map-tcp-delete-nonexistent | pcp | FAIL | step 1 (pcp_map): response matched none of the expected replies: unexpected pcp result code 8 |
| map-tcp-delete-identical-retry | pcp | FAIL | step 3 (pcp_map): response matched none of the expected replies: unexpected pcp result code 8 |
| map-nonce-mismatch-changed-port | pcp | FAIL | step 2 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0 |
| map-wrong-nonce-delete-preserves-original | pcp | PASS | RFC 6887 §§11.3, 15.1: a deletion with a wrong nonce is refused and the original mapping remains renewable. |
| map-error-no-state-unknown-mandatory | pcp | PASS | RFC 6887 §7.3: a rejected create must leave no nonce ownership behind; a fresh nonce must subsequently create the same tuple. |
| map-error-no-state-bad-prefer-failure | pcp | PASS | RFC 6887 §7.3: a rejected create must leave no nonce ownership behind; a fresh nonce must subsequently create the same tuple. |
| optional-unknown-option-padding-1 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| optional-unknown-option-padding-2 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| optional-unknown-option-padding-3 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| map-reserved-body-ignored-and-cleared | pcp | FAIL | step 1 (pcp_map): response matched none of the expected replies: protocol_and_reserved was 301989887, expected 285212672 |
| peer-reserved-body-ignored-and-cleared | pcp | FAIL | step 1 (pcp_peer): response matched none of the expected replies: protocol_and_reserved was 301989887, expected 285212672 |
| peer-prefer-failure-forbidden | pcp | PASS | RFC 6887 §12.1: PREFER_FAILURE is not allowed on PEER and must return MALFORMED_REQUEST. |
| announce-epoch-and-reserved-response | pcp | PASS | RFC 6887 §§7.2, 8.5: repeated ANNOUNCE replies have nondecreasing epochs and zero common reserved fields; this does not check reboot reset or clock rate. |
| announce-ignores-lifetime-300 | pcp | FAIL | ANNOUNCE lifetime was 300, expected 0 |
| announce-ignores-lifetime-4294967295 | pcp | FAIL | ANNOUNCE lifetime was 600, expected 0 |
| announce-mandatory-unknown-option | pcp | FAIL | unexpected result code 0 |
| announce-optional-unknown-option | pcp | XFAIL | expected 24-byte response, got 28; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| map-reserved-pcp-udp-port-5350 | pcp | FAIL | step 1 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0 |
| map-reserved-pcp-udp-port-5351 | pcp | FAIL | step 1 (pcp_map): response matched none of the expected replies: unexpected pcp result code 0 |
| peer-wrong-nonce-refresh | pcp | FAIL | step 2 (pcp_peer): response matched none of the expected replies: unexpected pcp result code 0 |
| map-tcp-create-renew-delete | pcp | PASS | RFC 6887 §§11, 15.1: exercise a TCP MAP lifecycle separately from the existing UDP lifecycle. |
| map-error-echo-opcode-and-options | pcp | PASS | RFC 6887 §§7.3, 8.2: error responses preserve the complete opcode body and options. |
| unsupported-opcode-echo-payload | pcp | PASS | RFC 6887 §8.2: preserve unknown opcode payload bytes in error responses. |
| long-error-lifetime-default | pcp | PASS | RFC 6887 §7.4: long-lived errors SHOULD default to a 30-minute error lifetime. |

### RFC 7652 PCP: Authentication extension profile

PA-Initiation and EAP exchange support. The daemon does not implement this optional authentication profile; the probe is recorded as an expected failure.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| auth-extension-unsupported | pcp | PASS | Send the RFC 7652 AUTHENTICATION_TAG option without an established PA session. |
| auth-initiation-unsupported | pcp | PASS | Send a valid RFC 7652 PA-Initiation with a NONCE; baseline daemon rejects the AUTHENTICATION opcode. |
| rfc7652-initiation-supported | pcp | XFAIL | unexpected result code 4; expected: The optional RFC 7652 authentication profile is not implemented by miniupnpd. |
| auth-initiation-invalid-sequence | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-valid-next | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-large-jump | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-replay-modified | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-eap-reply-unsupported | pcp | PASS | Send an RFC 7652 EAP response PA-Client message without an established session. |
| rfc7652-nonce-zero-echo | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-all-ones-echo | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-high-low-bits-echo | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-duplicate | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-short | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-long | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-reserved-bits | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |

### RFC 7753 PCP Extension for Port-Set Allocation: Fallback and framing

IPv4/IPv6 single-port fallback for unprocessed option 130, with TCP/UDP lifecycle and common framing checks.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| port-set-single-port-fallback-size-2-flags-0 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-16-flags-0 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-65535-flags-0 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-1 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-254 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-option-reserved-byte-ignored | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-truncated-option-envelope | pcp | PASS | RFC 6887 §7.3 and RFC 7753 §4: reject an option declaring five payload bytes when only four are present, even if the option is unprocessed. |
| port-set-single-port-renew-and-delete | pcp | SKIP | prerequisite did not pass: pcp/port-set-extension-ignored (XFAIL) |
| port-set-extension-ignored-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-2-flags-0-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-16-flags-0-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-65535-flags-0-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-1-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-254-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-option-reserved-byte-ignored-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-truncated-option-envelope-tcp | pcp | PASS | RFC 6887 §7.3 and RFC 7753 §4: reject an option declaring five payload bytes when only four are present, even if the option is unprocessed. |
| port-set-single-port-renew-and-delete-tcp | pcp | SKIP | prerequisite did not pass: pcp/port-set-extension-ignored-tcp (XFAIL) |
| port-set-fallback-udp-zero-size | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-duplicate | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-first-port-mismatch | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-zero-length | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-short-payload | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-long-payload | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-with-prefer-failure | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-envelope-overrun-udp-5-0 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-5-4 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-9-8 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-65535-0 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-fallback-tcp-zero-size | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-duplicate | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-first-port-mismatch | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-zero-length | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-short-payload | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-long-payload | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-with-prefer-failure | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-envelope-overrun-tcp-5-0 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-5-4 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-9-8 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-65535-0 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |

### RFC 6886 NAT-PMP: Protocol behavior

Public address, mapping request validation, malformed traffic, and mutating UDP/TCP mapping lifecycles.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| public-address | natpmp | PASS | Request the NAT-PMP public address and validate its response. |
| unsupported-opcode | natpmp | PASS | Send an unknown NAT-PMP opcode and check the unsupported-opcode result. |
| truncated-mapping | natpmp | PASS | Send only a NAT-PMP mapping opcode; the incomplete request should be ignored. |
| response-as-request | natpmp | PASS | Set the response bit on a NAT-PMP packet and verify it is ignored. |
| zero-private-port | natpmp | PASS | Request a NAT-PMP mapping with private port zero and check refusal. |
| udp-mapping-lifecycle | natpmp | PASS | Create, renew, and delete a NAT-PMP UDP mapping. |
| tcp-mapping-lifecycle | natpmp | PASS | Create, renew, and delete a NAT-PMP TCP mapping. |
| truncated-udp-length-0 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 0-byte mapping request without creating a mapping. |
| truncated-udp-length-1 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 1-byte mapping request without creating a mapping. |
| truncated-udp-length-3 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 3-byte mapping request without creating a mapping. |
| truncated-udp-length-4 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 4-byte mapping request without creating a mapping. |
| truncated-udp-length-5 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 5-byte mapping request without creating a mapping. |
| truncated-udp-length-6 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 6-byte mapping request without creating a mapping. |
| truncated-udp-length-7 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 7-byte mapping request without creating a mapping. |
| truncated-udp-length-8 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 8-byte mapping request without creating a mapping. |
| truncated-udp-length-9 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 9-byte mapping request without creating a mapping. |
| truncated-udp-length-10 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 10-byte mapping request without creating a mapping. |
| truncated-udp-length-11 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 11-byte mapping request without creating a mapping. |
| truncated-tcp-length-3 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 3-byte mapping request without creating a mapping. |
| truncated-tcp-length-4 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 4-byte mapping request without creating a mapping. |
| truncated-tcp-length-5 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 5-byte mapping request without creating a mapping. |
| truncated-tcp-length-6 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 6-byte mapping request without creating a mapping. |
| truncated-tcp-length-7 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 7-byte mapping request without creating a mapping. |
| truncated-tcp-length-8 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 8-byte mapping request without creating a mapping. |
| truncated-tcp-length-9 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 9-byte mapping request without creating a mapping. |
| truncated-tcp-length-10 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 10-byte mapping request without creating a mapping. |
| truncated-tcp-length-11 | natpmp | PASS | RFC 6886 §3.3: discard an incomplete 11-byte mapping request without creating a mapping. |
| response-opcode-129-ignored | natpmp | PASS | RFC 6886 §3.5: silently ignore packets with the response bit set, including mapping opcodes. |
| response-opcode-130-ignored | natpmp | PASS | RFC 6886 §3.5: silently ignore packets with the response bit set, including mapping opcodes. |
| response-opcode-255-ignored | natpmp | PASS | RFC 6886 §3.5: silently ignore packets with the response bit set, including mapping opcodes. |
| unsupported-opcode-echo-body | natpmp | FAIL | expected 12-byte response, got 8 |
| refused-mapping-response-fields | natpmp | FAIL | unassigned external port was 49000, expected 0 |
| reserved-mapping-bits-ignored | natpmp | PASS | RFC 6886 §3.3: ignore nonzero reserved request bits and grant an otherwise valid mapping. |
| udp-delete-idempotent-and-ignore-public-port | natpmp | PASS | RFC 6886 §3.4: ignore the suggested public port when deleting; repeated deletion returns success, private port, external port zero and lifetime zero. |
| udp-retry-changed-suggestion | natpmp | FAIL | step 2 (natpmp): response matched none of the expected replies: external_port was 49111, expected 49011 |
| udp-identical-retry | natpmp | PASS | RFC 6886 §3.3: retransmitting an identical mapping request preserves the public port. |
| udp-short-lease-not-increased | natpmp | PASS | RFC 6886 §3.3: a one-second request should not be granted a longer lifetime (SHOULD NOT). |
| tcp-delete-idempotent-and-ignore-public-port | natpmp | PASS | RFC 6886 §3.4: ignore the suggested public port when deleting; repeated deletion returns success, private port, external port zero and lifetime zero. |
| tcp-retry-changed-suggestion | natpmp | FAIL | step 2 (natpmp): response matched none of the expected replies: external_port was 49112, expected 49012 |
| tcp-identical-retry | natpmp | PASS | RFC 6886 §3.3: retransmitting an identical mapping request preserves the public port. |
| tcp-short-lease-not-increased | natpmp | PASS | RFC 6886 §3.3: a one-second request should not be granted a longer lifetime (SHOULD NOT). |
| same-protocol-conflict-retry | natpmp | PASS | RFC 6886 §3.3: a public-port conflict gets another port; retransmission keeps that alternate port and does not displace the first mapping. |
| same-client-tcp-udp-companion-port | natpmp | PASS | RFC 6886 §3.3: the same client can map TCP and UDP to the same public port; deleting UDP must preserve the TCP mapping. |
| public-address-epoch-monotonic | natpmp | PASS | RFC 6886 §§3.2, 3.6: repeated public-address replies use a nondecreasing epoch. This checks continuity, not clock rate or reset behavior. |
| udp-delete-all-preserves-tcp | natpmp | SKIP | prerequisite did not pass: natpmp/udp-retry-changed-suggestion (FAIL), natpmp/tcp-retry-changed-suggestion (FAIL) |
| udp-mapping-expires | natpmp | SKIP | prerequisite did not pass: natpmp/udp-retry-changed-suggestion (FAIL) |


---

# PCP/NAT-PMP Test Status

Updated: 2026-10-31T19:49:49+00:00

## Run

- Target: `pcp-router:5351`
- Protocol: `pcp`
- Address family: `ipv6`
- Server profile: `baseline`
- Mapping lifecycle tests: `enabled`
- Totals: **58 PASS**, **30 XFAIL**, **23 FAIL**, **13 SKIP**
- Capture directory: `/pcp-pmp-captures/2026-10-31_20-49-10.894844616_all`

## Results by section

### RFC 6887 PCP: Base protocol and malformed packets

Header handling, core opcodes, error responses, address-family behavior, and malformed datagrams.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| announce-v2 | pcp | PASS | Send a PCP v2 ANNOUNCE and accept success or network failure depending on gateway state. |
| unsupported-version | pcp | PASS | Send unsupported PCP version 3 and check the supported-version error response. |
| unsupported-opcode-v2 | pcp | PASS | Send an unknown PCP v2 opcode and check UNSUPP_OPCODE. |
| short-header | pcp | PASS | Send a two-byte PCP datagram; the server should silently discard it. |
| minimum-short-header | pcp | FAIL | unexpected PCP response version 0 |
| reserved-common-header | pcp | PASS | Set reserved common-header bits and check the server response. |
| truncated-common-header | pcp | FAIL | unexpected PCP response version 0 |
| truncated-map-v1 | pcp | PASS | Send a PCP v1 MAP request without its MAP body. |
| truncated-map-v2 | pcp | PASS | Send a PCP v2 MAP request without its MAP body. |
| truncated-map-nonce-four-bytes | pcp | PASS | Truncate a v2 MAP body after only four of the twelve nonce bytes. |
| truncated-map-nonce-eight-bytes | pcp | PASS | Truncate a v2 MAP body after only eight of the twelve nonce bytes. |
| misaligned-length | pcp | FAIL | unexpected PCP response version 0 |
| oversized-packet | pcp | FAIL | unexpected result code 0 |
| response-as-request | pcp | PASS | Set the response bit on a PCP packet and verify it is ignored. |
| protocol-zero-nonzero-port | pcp | PASS | Send a MAP request using IP protocol zero and check invalid-parameter handling. |
| ipv6-source-address | pcp | PASS | Send PCP over IPv6 using the actual IPv6 source address in the client field. |

### RFC 6887 PCP: Options and extensions

Option parsing, duplicate handling, unknown options, and optional or mandatory extension behavior.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| unknown-mandatory-option | pcp | PASS | Add an unknown mandatory option to MAP; expect unsupported-option handling. |
| duplicate-prefer-failure | pcp | PASS | Repeat PREFER_FAILURE and check the duplicate-option error. |
| duplicate-third-party | pcp | PASS | Repeat THIRD_PARTY and check the duplicate-option error. |
| prefer-failure-without-suggestion | pcp | PASS | Set PREFER_FAILURE without suggesting an external address or port. |
| third-party-disabled | pcp | PASS | Request THIRD_PARTY mapping while third-party requests are disabled. |
| filter-wrong-length | pcp | PASS | Send a FILTER option with an invalid payload length. |
| truncated-third-party-option | pcp | PASS | Declare a THIRD_PARTY payload that is absent from the packet. |
| description-extension-ignored | pcp | PASS | Send an RFC 7220 DESCRIPTION option with UTF-8 client text. |
| port-set-extension-ignored | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| third-party-id-extension-unsupported | pcp | PASS | Send the RFC 7843 THIRD_PARTY_ID option. |

### RFC 6887 PCP: Edge cases

Additional packet framing, option validation, nonce ownership, renewal, deletion, PEER and epoch probes.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| common-header-truncated-4 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-7 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-8 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-12 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-16 | pcp | FAIL | unexpected PCP response version 0 |
| common-header-truncated-20 | pcp | FAIL | unexpected PCP response version 0 |
| map-body-truncated-28 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-36 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-40 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-44 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-48 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-52 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| map-body-truncated-56 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-24 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-36 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-40 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-60 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-64 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-68 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-72 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| peer-body-truncated-76 | pcp | PASS | RFC 6887 §§8.2, 11.1, 12.1: reject an incomplete opcode body; preserve the opcode in the padded error response. |
| announce-client-address-mismatch | pcp | FAIL | unexpected result code 0 |
| map-client-address-mismatch | pcp | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| announce-misaligned-1 | pcp | FAIL | unexpected PCP response version 0 |
| announce-misaligned-2 | pcp | FAIL | unexpected PCP response version 0 |
| announce-misaligned-3 | pcp | FAIL | unexpected PCP response version 0 |
| oversized-announce-1101 | pcp | FAIL | unexpected result code 0 |
| oversized-announce-1102 | pcp | FAIL | unexpected result code 0 |
| oversized-announce-1103 | pcp | FAIL | unexpected result code 0 |
| oversized-announce-1105 | pcp | FAIL | unexpected result code 0 |
| prefer-failure-invalid-length-1 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-2 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-4 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| optional-option-length-overrun | pcp | PASS | RFC 6887 §7.3: malformed overall option structure is an error even when its option code is optional. |
| filter-on-map-deletion | pcp | FAIL | unexpected result code 0 |
| prefer-failure-on-map-deletion | pcp | FAIL | unexpected result code 0 |
| announce-epoch-and-reserved-response | pcp | PASS | RFC 6887 §§7.2, 8.5: repeated ANNOUNCE replies have nondecreasing epochs and zero common reserved fields; this does not check reboot reset or clock rate. |
| announce-ignores-lifetime-300 | pcp | FAIL | ANNOUNCE lifetime was 300, expected 0 |
| announce-ignores-lifetime-4294967295 | pcp | FAIL | ANNOUNCE lifetime was 600, expected 0 |
| announce-mandatory-unknown-option | pcp | FAIL | unexpected result code 0 |
| announce-optional-unknown-option | pcp | XFAIL | expected 24-byte response, got 28; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| map-error-echo-opcode-and-options | pcp | PASS | RFC 6887 §§7.3, 8.2: error responses preserve the complete opcode body and options. |
| unsupported-opcode-echo-payload | pcp | PASS | RFC 6887 §8.2: preserve unknown opcode payload bytes in error responses. |
| long-error-lifetime-default | pcp | PASS | RFC 6887 §7.4: long-lived errors SHOULD default to a 30-minute error lifetime. |

### RFC 7652 PCP: Authentication extension profile

PA-Initiation and EAP exchange support. The daemon does not implement this optional authentication profile; the probe is recorded as an expected failure.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| auth-extension-unsupported | pcp | PASS | Send the RFC 7652 AUTHENTICATION_TAG option without an established PA session. |
| auth-initiation-unsupported | pcp | PASS | Send a valid RFC 7652 PA-Initiation with a NONCE; baseline daemon rejects the AUTHENTICATION opcode. |
| rfc7652-initiation-supported | pcp | XFAIL | unexpected result code 4; expected: The optional RFC 7652 authentication profile is not implemented by miniupnpd. |
| auth-initiation-invalid-sequence | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-valid-next | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-large-jump | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-sequence-replay-modified | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| auth-eap-reply-unsupported | pcp | PASS | Send an RFC 7652 EAP response PA-Client message without an established session. |
| rfc7652-nonce-zero-echo | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-all-ones-echo | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-high-low-bits-echo | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-duplicate | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-short | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-long | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |
| rfc7652-nonce-reserved-bits | pcp | SKIP | prerequisite did not pass: pcp/rfc7652-initiation-supported (XFAIL) |

### RFC 7753 PCP Extension for Port-Set Allocation: Fallback and framing

IPv4/IPv6 single-port fallback for unprocessed option 130, with TCP/UDP lifecycle and common framing checks.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| port-set-single-port-fallback-size-2-flags-0 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-16-flags-0 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-65535-flags-0 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-1 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-254 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-option-reserved-byte-ignored | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-truncated-option-envelope | pcp | PASS | RFC 6887 §7.3 and RFC 7753 §4: reject an option declaring five payload bytes when only four are present, even if the option is unprocessed. |
| port-set-single-port-renew-and-delete | pcp | SKIP | prerequisite did not pass: pcp/port-set-extension-ignored (XFAIL) |
| port-set-extension-ignored-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-2-flags-0-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-16-flags-0-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-65535-flags-0-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-1-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-single-port-fallback-size-1-flags-254-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-option-reserved-byte-ignored-tcp | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-truncated-option-envelope-tcp | pcp | PASS | RFC 6887 §7.3 and RFC 7753 §4: reject an option declaring five payload bytes when only four are present, even if the option is unprocessed. |
| port-set-single-port-renew-and-delete-tcp | pcp | SKIP | prerequisite did not pass: pcp/port-set-extension-ignored-tcp (XFAIL) |
| port-set-fallback-udp-zero-size | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-duplicate | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-first-port-mismatch | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-zero-length | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-short-payload | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-long-payload | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-udp-with-prefer-failure | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-envelope-overrun-udp-5-0 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-5-4 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-9-8 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-udp-65535-0 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-fallback-tcp-zero-size | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-duplicate | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 84; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-first-port-mismatch | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-zero-length | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 64; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-short-payload | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-long-payload | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 72; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-fallback-tcp-with-prefer-failure | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 76; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| port-set-envelope-overrun-tcp-5-0 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-5-4 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-9-8 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |
| port-set-envelope-overrun-tcp-65535-0 | pcp | PASS | RFC 6887 section 7.3: reject a PORT_SET envelope whose declared payload exceeds the datagram. |

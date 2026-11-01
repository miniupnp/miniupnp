# PCP/NAT-PMP Test Status

Updated: 2026-11-01T11:59:35+00:00

## Run

- Target: `pcp-router:5351`
- Protocol: `both`
- Address family: `ipv4`
- Server profile: `baseline`
- Mapping lifecycle tests: `enabled`
- Totals: **162 PASS**, **32 XFAIL**, **3 FAIL**, **13 SKIP**
- Capture directory: `/pcp-pmp-captures/2026-11-01_12-58-47.615573361_all`

## Results by section

### RFC 6887 PCP: Base protocol and malformed packets

Header handling, core opcodes, error responses, address-family behavior, and malformed datagrams.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| announce-v2 | pcp | PASS | Send a PCP v2 ANNOUNCE and accept success or network failure depending on gateway state. |
| unsupported-version | pcp | PASS | Send unsupported PCP version 3 and check the supported-version error response. |
| unsupported-opcode-v2 | pcp | PASS | Send an unknown PCP v2 opcode and check UNSUPP_OPCODE. |
| short-header | pcp | PASS | Send a two-byte PCP datagram; the server should silently discard it. |
| minimum-short-header | pcp | PASS | Send a three-byte PCP header and check the malformed-request response. |
| reserved-common-header | pcp | FAIL | unexpected result code 12 |
| truncated-common-header | pcp | PASS | Remove one byte from the common PCP header. |
| truncated-map-v1 | pcp | PASS | Send a PCP v1 MAP request without its MAP body. |
| truncated-map-v2 | pcp | PASS | Send a PCP v2 MAP request without its MAP body. |
| truncated-map-nonce-four-bytes | pcp | PASS | Truncate a v2 MAP body after only four of the twelve nonce bytes. |
| truncated-map-nonce-eight-bytes | pcp | PASS | Truncate a v2 MAP body after only eight of the twelve nonce bytes. |
| misaligned-length | pcp | PASS | Append one byte to ANNOUNCE and verify error-response padding. |
| oversized-packet | pcp | PASS | Send a datagram larger than PCP_MAX_LEN and check the capped error response. |
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
| pcp-then-pmp-same-mapping-refused | both | PASS | Known-failure case met its expected behavior. |
| pcp-then-pmp-port-conflict-preserves-pcp | both | PASS | Keep a PCP mapping on a requested public port, make a conflicting PMP request for another private port, then verify PMP uses a different port and PCP still renews its original mapping. |
| map-v1-lifecycle | pcp | PASS | Create, renew with changed lifetimes, and delete a PCP v1 MAP. |
| map-v2-lifecycle | pcp | PASS | Create, renew with changed lifetimes, and delete a PCP v2 MAP while checking its nonce. |
| map-v2-nonce-pattern-echo | pcp | PASS | Create and remove four mappings while checking zero, all-one, alternating-byte, and boundary-bit nonce echoes. Zero and all-one values are wire test patterns, not client randomness guidance. |
| map-v2-nonce-mismatch-refresh | pcp | PASS | Known-failure case met its expected behavior. |
| map-v2-nonce-identical-retry | pcp | PASS | Retry a create request with the same key and nonce, and require the existing external port to be reused. |
| peer-v2-lifecycle | pcp | PASS | Create and delete a PCP v2 PEER mapping for the configured remote peer. |

### RFC 6887 PCP: Edge cases

Additional packet framing, option validation, nonce ownership, renewal, deletion, PEER and epoch probes.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| common-header-truncated-4 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-7 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-8 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-12 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-16 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-20 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
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
| announce-client-address-mismatch | pcp | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| map-client-address-mismatch | pcp | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| announce-misaligned-1 | pcp | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| announce-misaligned-2 | pcp | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| announce-misaligned-3 | pcp | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| oversized-announce-1101 | pcp | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1102 | pcp | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1103 | pcp | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1105 | pcp | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| prefer-failure-invalid-length-1 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-2 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-4 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| optional-option-length-overrun | pcp | PASS | RFC 6887 §7.3: malformed overall option structure is an error even when its option code is optional. |
| filter-invalid-ipv4-prefix-129 | pcp | PASS | Known-failure case met its expected behavior. |
| filter-invalid-ipv4-prefix-95 | pcp | PASS | Known-failure case met its expected behavior. |
| filter-invalid-ipv6-prefix-129 | pcp | PASS | Known-failure case met its expected behavior. |
| filter-on-map-deletion | pcp | PASS | RFC 6887 §13.3: FILTER in a MAP deletion must return MALFORMED_OPTION. |
| prefer-failure-on-map-deletion | pcp | PASS | RFC 6887 §11.3: a mandatory option that does not make sense for deletion returns MALFORMED_OPTION. |
| prefer-failure-zero-port-explicit-address | pcp | PASS | RFC 6887 §13.2: PREFER_FAILURE with zero suggested port is malformed even with a nonzero suggested address. |
| map-udp-renew-changed-suggestion | pcp | PASS | RFC 6887 §11.3: renewal with the same mapping key and nonce must return the existing external port, regardless of a changed or zero suggestion. |
| map-udp-renew-zero-suggestion | pcp | PASS | RFC 6887 §11.3: renewal with the same mapping key and nonce must return the existing external port, regardless of a changed or zero suggestion. |
| map-udp-delete-nonexistent | pcp | PASS | RFC 6887 §15.1: deleting a nonexistent mapping succeeds, making deletion retransmissions safe. |
| map-udp-delete-identical-retry | pcp | PASS | RFC 6887 §15.1: repeated deletion returns SUCCESS with lifetime zero. |
| map-tcp-renew-changed-suggestion | pcp | PASS | RFC 6887 §11.3: renewal with the same mapping key and nonce must return the existing external port, regardless of a changed or zero suggestion. |
| map-tcp-renew-zero-suggestion | pcp | PASS | RFC 6887 §11.3: renewal with the same mapping key and nonce must return the existing external port, regardless of a changed or zero suggestion. |
| map-tcp-delete-nonexistent | pcp | PASS | RFC 6887 §15.1: deleting a nonexistent mapping succeeds, making deletion retransmissions safe. |
| map-tcp-delete-identical-retry | pcp | PASS | RFC 6887 §15.1: repeated deletion returns SUCCESS with lifetime zero. |
| map-nonce-mismatch-changed-port | pcp | PASS | RFC 6887 §11.3: nonce authorization is keyed by internal address, protocol and port, not by the external suggestion. |
| map-wrong-nonce-delete-preserves-original | pcp | PASS | RFC 6887 §§11.3, 15.1: a deletion with a wrong nonce is refused and the original mapping remains renewable. |
| map-error-no-state-unknown-mandatory | pcp | PASS | RFC 6887 §7.3: a rejected create must leave no nonce ownership behind; a fresh nonce must subsequently create the same tuple. |
| map-error-no-state-bad-prefer-failure | pcp | PASS | RFC 6887 §7.3: a rejected create must leave no nonce ownership behind; a fresh nonce must subsequently create the same tuple. |
| optional-unknown-option-padding-1 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| optional-unknown-option-padding-2 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| optional-unknown-option-padding-3 | pcp | XFAIL | step 1 (pcp_map): response matched none of the expected replies: expected 60-byte pcp response, got 68; expected: miniupnpd echoes unprocessed optional options in replies; response option omission is not implemented. |
| map-reserved-body-ignored-and-cleared | pcp | PASS | RFC 6887 §11.1: ignore MAP reserved bytes on reception, but clear them in responses. |
| peer-reserved-body-ignored-and-cleared | pcp | PASS | RFC 6887 §12.1: ignore PEER reserved fields in requests and transmit zeros in responses. |
| peer-prefer-failure-forbidden | pcp | PASS | RFC 6887 §12.1: PREFER_FAILURE is not allowed on PEER and must return MALFORMED_REQUEST. |
| peer-prefer-failure-forbidden-create | pcp | PASS | RFC 6887 §12.1: PREFER_FAILURE on a PEER create request returns MALFORMED_REQUEST. |
| peer-implied-prefer-failure-external-address | pcp | PASS | RFC 6887 §12.1: PEER implies PREFER_FAILURE, so an external address the server cannot provide returns CANNOT_PROVIDE_EXTERNAL. |
| announce-epoch-and-reserved-response | pcp | PASS | RFC 6887 §§7.2, 8.5: repeated ANNOUNCE replies have nondecreasing epochs and zero common reserved fields; this does not check reboot reset or clock rate. |
| announce-ignores-lifetime-300 | pcp | PASS | RFC 6887 §14.1: ignore requested ANNOUNCE lifetime and transmit a zero response lifetime. |
| announce-ignores-lifetime-4294967295 | pcp | PASS | RFC 6887 §14.1: ignore requested ANNOUNCE lifetime and transmit a zero response lifetime. |
| announce-mandatory-unknown-option | pcp | PASS | RFC 6887 §§7.3, 14.1: apply mandatory/optional option processing to ANNOUNCE; omit ignored options on success. |
| announce-optional-unknown-option | pcp | PASS | Known-failure case met its expected behavior. |
| map-reserved-pcp-udp-port-5350 | pcp | PASS | RFC 6887 §11.3: external UDP ports 5350 and 5351 cannot be mapped to clients; with PREFER_FAILURE return CANNOT_PROVIDE_EXTERNAL. |
| map-reserved-pcp-udp-port-5351 | pcp | PASS | RFC 6887 §11.3: external UDP ports 5350 and 5351 cannot be mapped to clients; with PREFER_FAILURE return CANNOT_PROVIDE_EXTERNAL. |
| peer-wrong-nonce-refresh | pcp | PASS | RFC 6887 §12.3: an existing PEER five-tuple may only be refreshed with its original nonce in the Simple Threat Model. |
| peer-wrong-nonce-delete | pcp | PASS | RFC 6887 §12.3: an existing PEER five-tuple may only be deleted with its original nonce in the Simple Threat Model. |
| peer-shared-external-port-lifecycle | pcp | FAIL | step 9 (pcp_peer): response matched none of the expected replies: unexpected pcp result code 11 |
| peer-survives-shared-map-expiration | pcp | PASS | Expiration of a one-second NAT-PMP mapping preserves a longer PEER mapping sharing its external port and protocol. |
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
| unsupported-opcode-echo-body | natpmp | PASS | RFC 6886 §3.5: echo the entire unsupported-opcode request, preserving bytes after the response header. |
| refused-mapping-response-fields | natpmp | PASS | RFC 6886 §3.5: a refused mapping echoes the internal port and returns zero external port and lifetime. |
| reserved-mapping-bits-ignored | natpmp | PASS | RFC 6886 §3.3: ignore nonzero reserved request bits and grant an otherwise valid mapping. |
| udp-delete-idempotent-and-ignore-public-port | natpmp | PASS | RFC 6886 §3.4: ignore the suggested public port when deleting; repeated deletion returns success, private port, external port zero and lifetime zero. |
| udp-retry-changed-suggestion | natpmp | PASS | RFC 6886 §3.3: a retry for the same internal tuple reuses its existing public port even when the suggestion changes. |
| udp-identical-retry | natpmp | PASS | RFC 6886 §3.3: retransmitting an identical mapping request preserves the public port. |
| udp-short-lease-not-increased | natpmp | PASS | RFC 6886 §3.3: a one-second request should not be granted a longer lifetime (SHOULD NOT). |
| tcp-delete-idempotent-and-ignore-public-port | natpmp | PASS | RFC 6886 §3.4: ignore the suggested public port when deleting; repeated deletion returns success, private port, external port zero and lifetime zero. |
| tcp-retry-changed-suggestion | natpmp | PASS | RFC 6886 §3.3: a retry for the same internal tuple reuses its existing public port even when the suggestion changes. |
| tcp-identical-retry | natpmp | PASS | RFC 6886 §3.3: retransmitting an identical mapping request preserves the public port. |
| tcp-short-lease-not-increased | natpmp | PASS | RFC 6886 §3.3: a one-second request should not be granted a longer lifetime (SHOULD NOT). |
| same-protocol-conflict-retry | natpmp | PASS | RFC 6886 §3.3: a public-port conflict gets another port; retransmission keeps that alternate port and does not displace the first mapping. |
| same-client-tcp-udp-companion-port | natpmp | PASS | RFC 6886 §3.3: the same client can map TCP and UDP to the same public port; deleting UDP must preserve the TCP mapping. |
| public-address-epoch-monotonic | natpmp | PASS | RFC 6886 §§3.2, 3.6: repeated public-address replies use a nondecreasing epoch. This checks continuity, not clock rate or reset behavior. |
| udp-delete-all-preserves-tcp | natpmp | FAIL | step 5 (natpmp): response matched none of the expected replies: external_port was 49083, expected 49073 |
| udp-mapping-expires | natpmp | PASS | RFC 6886 §3.4: after a one-second lease expires, a new request can use a different public port instead of renewing the expired rule. |


---

# PCP/NAT-PMP Test Status

Updated: 2026-11-01T11:59:42+00:00

## Run

- Target: `pcp-router:5351`
- Protocol: `pcp`
- Address family: `ipv6`
- Server profile: `baseline`
- Mapping lifecycle tests: `enabled`
- Totals: **85 PASS**, **29 XFAIL**, **1 FAIL**, **13 SKIP**
- Capture directory: `/pcp-pmp-captures/2026-11-01_12-58-47.615573361_all`

## Results by section

### RFC 6887 PCP: Base protocol and malformed packets

Header handling, core opcodes, error responses, address-family behavior, and malformed datagrams.

| Case | Protocol | Status | Result / note |
|---|---|---|---|
| announce-v2 | pcp | PASS | Send a PCP v2 ANNOUNCE and accept success or network failure depending on gateway state. |
| unsupported-version | pcp | PASS | Send unsupported PCP version 3 and check the supported-version error response. |
| unsupported-opcode-v2 | pcp | PASS | Send an unknown PCP v2 opcode and check UNSUPP_OPCODE. |
| short-header | pcp | PASS | Send a two-byte PCP datagram; the server should silently discard it. |
| minimum-short-header | pcp | PASS | Send a three-byte PCP header and check the malformed-request response. |
| reserved-common-header | pcp | FAIL | unexpected result code 12 |
| truncated-common-header | pcp | PASS | Remove one byte from the common PCP header. |
| truncated-map-v1 | pcp | PASS | Send a PCP v1 MAP request without its MAP body. |
| truncated-map-v2 | pcp | PASS | Send a PCP v2 MAP request without its MAP body. |
| truncated-map-nonce-four-bytes | pcp | PASS | Truncate a v2 MAP body after only four of the twelve nonce bytes. |
| truncated-map-nonce-eight-bytes | pcp | PASS | Truncate a v2 MAP body after only eight of the twelve nonce bytes. |
| misaligned-length | pcp | PASS | Append one byte to ANNOUNCE and verify error-response padding. |
| oversized-packet | pcp | PASS | Send a datagram larger than PCP_MAX_LEN and check the capped error response. |
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
| common-header-truncated-4 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-7 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-8 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-12 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-16 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
| common-header-truncated-20 | pcp | PASS | RFC 6887 §8.2: a common header shorter than 24 bytes gets a 24-byte MALFORMED_REQUEST response. |
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
| announce-client-address-mismatch | pcp | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| map-client-address-mismatch | pcp | PASS | RFC 6887 §8.2: reject a replicated client address that differs from the packet source. |
| announce-misaligned-1 | pcp | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| announce-misaligned-2 | pcp | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| announce-misaligned-3 | pcp | PASS | RFC 6887 §8.2: pad a misaligned request to a multiple of four bytes in its error response. |
| oversized-announce-1101 | pcp | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1102 | pcp | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1103 | pcp | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| oversized-announce-1105 | pcp | PASS | RFC 6887 §§7, 8.2: detect a request beyond 1100 bytes and cap the error at 1100 bytes. |
| prefer-failure-invalid-length-1 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-2 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| prefer-failure-invalid-length-4 | pcp | PASS | RFC 6887 §§7.3, 13.2: PREFER_FAILURE has a zero-byte payload; reject other lengths. |
| optional-option-length-overrun | pcp | PASS | RFC 6887 §7.3: malformed overall option structure is an error even when its option code is optional. |
| filter-on-map-deletion | pcp | PASS | RFC 6887 §13.3: FILTER in a MAP deletion must return MALFORMED_OPTION. |
| prefer-failure-on-map-deletion | pcp | PASS | RFC 6887 §11.3: a mandatory option that does not make sense for deletion returns MALFORMED_OPTION. |
| peer-prefer-failure-forbidden-ipv6 | pcp | PASS | RFC 6887 §12.1: PREFER_FAILURE on an IPv6 PEER request returns MALFORMED_REQUEST. |
| peer-implied-prefer-failure-external-address-ipv6 | pcp | PASS | RFC 6887 §12.1: PEER implies PREFER_FAILURE for IPv6; an unavailable external address returns CANNOT_PROVIDE_EXTERNAL. |
| announce-epoch-and-reserved-response | pcp | PASS | RFC 6887 §§7.2, 8.5: repeated ANNOUNCE replies have nondecreasing epochs and zero common reserved fields; this does not check reboot reset or clock rate. |
| announce-ignores-lifetime-300 | pcp | PASS | RFC 6887 §14.1: ignore requested ANNOUNCE lifetime and transmit a zero response lifetime. |
| announce-ignores-lifetime-4294967295 | pcp | PASS | RFC 6887 §14.1: ignore requested ANNOUNCE lifetime and transmit a zero response lifetime. |
| announce-mandatory-unknown-option | pcp | PASS | RFC 6887 §§7.3, 14.1: apply mandatory/optional option processing to ANNOUNCE; omit ignored options on success. |
| announce-optional-unknown-option | pcp | PASS | Known-failure case met its expected behavior. |
| peer-wrong-nonce-refresh-ipv6 | pcp | PASS | RFC 6887 §12.3: an existing PEER five-tuple may only be refreshed with its original nonce in the Simple Threat Model. |
| peer-zero-lifetime-query-ownership-ipv6 | pcp | PASS | RFC 6887 sections 12.3 and 15: a zero-lifetime PEER request queries the retained lease and requires its original nonce. |
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

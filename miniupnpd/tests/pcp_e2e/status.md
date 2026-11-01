# PCP E2E Status

Updated: 2026-11-01T11:45:46Z

## Run

- Branch: dev/pcp-filter-peer_inc_pcp_fixes
- Address families: IPv4 and IPv6
- Scenario selection: all
- Totals: **66 PASS**, **0 FAIL** (66 family runs)
- Artifacts: .tmp/pcp-e2e/2026-11-01T11-42-40Z (daemon startup/final logs and per-case captures/snapshots)

## Results

### ipv4

#### MAP

| Case | Status | Result / note |
|---|---|---|
| map-single-udp-only | PASS | all configured assertions passed |
| map-single-tcp-only | PASS | all configured assertions passed |
| map-udp-and-tcp-same-port | PASS | all configured assertions passed |
| map-same-protocol-and-port-conflicts | PASS | all configured assertions passed |
| map-renewal-keeps-forwarding | PASS | all configured assertions passed |
| map-delete-stops-forwarding | PASS | all configured assertions passed |
| map-unfiltered-allows-independent-peers | PASS | all configured assertions passed |

#### FILTER

| Case | Status | Result / note |
|---|---|---|
| map-filter-exact-peer-and-port | PASS | all configured assertions passed |
| map-filter-restricts-remote-port | PASS | all configured assertions passed |
| map-filter-prefix-allows-subnet | PASS | all configured assertions passed |
| map-filter-narrow-prefix-rejects-outside-subnet | PASS | all configured assertions passed |
| map-filter-multiple-options-add-peers | PASS | all configured assertions passed |
| map-filter-options-at-message-limit | PASS | all configured assertions passed |
| map-filter-refresh-adds-peer | PASS | all configured assertions passed |
| map-filter-refresh-replaces-peer-set | PASS | all configured assertions passed |
| map-filter-prefix-zero-removes-all | PASS | all configured assertions passed |
| map-filter-refresh-without-options-preserves-policy | PASS | all configured assertions passed |
| map-filter-delete-and-recreate-clears-policy | PASS | all configured assertions passed |

#### PEER

| Case | Status | Result / note |
|---|---|---|
| peer-create-before-first-packet-udp | PASS | all configured assertions passed |
| peer-create-before-first-packet-tcp | PASS | all configured assertions passed |
| peer-processes-options-at-message-limit | PASS | all configured assertions passed |
| peer-adopts-existing-udp-mapping | PASS | all configured assertions passed |
| peer-adopts-existing-tcp-mapping | PASS | all configured assertions passed |
| peer-recreates-remembered-tcp-mapping | PASS | all configured assertions passed |
| peer-rejects-unavailable-external-address | PASS | all configured assertions passed |
| peer-rejects-mismatched-port-on-renewal | PASS | all configured assertions passed |
| peer-rejects-prefer-failure | PASS | all configured assertions passed |

#### NAT

| Case | Status | Result / note |
|---|---|---|
| natpmp-public-address | PASS | all configured assertions passed |

#### PMP

| Case | Status | Result / note |
|---|---|---|
| natpmp-single-udp-lifecycle | PASS | all configured assertions passed |
| natpmp-single-tcp-lifecycle | PASS | all configured assertions passed |
| natpmp-udp-and-tcp-same-port | PASS | all configured assertions passed |

### ipv6

#### MAP

| Case | Status | Result / note |
|---|---|---|
| map-single-udp-only | PASS | all configured assertions passed |
| map-single-tcp-only | PASS | all configured assertions passed |
| map-udp-and-tcp-same-port | PASS | all configured assertions passed |
| map-same-protocol-and-port-conflicts | PASS | all configured assertions passed |
| map-ipv6-prefer-failure-preserves-pinhole | PASS | all configured assertions passed |
| map-renewal-keeps-forwarding | PASS | all configured assertions passed |
| map-delete-stops-forwarding | PASS | all configured assertions passed |
| map-unfiltered-allows-independent-peers | PASS | all configured assertions passed |

#### FILTER

| Case | Status | Result / note |
|---|---|---|
| map-filter-exact-peer-and-port | PASS | all configured assertions passed |
| map-filter-restricts-remote-port | PASS | all configured assertions passed |
| map-filter-prefix-allows-subnet | PASS | all configured assertions passed |
| map-filter-narrow-prefix-rejects-outside-subnet | PASS | all configured assertions passed |
| map-filter-multiple-options-add-peers | PASS | all configured assertions passed |
| map-filter-options-at-message-limit | PASS | all configured assertions passed |
| map-filter-refresh-adds-peer | PASS | all configured assertions passed |
| map-filter-refresh-replaces-peer-set | PASS | all configured assertions passed |
| map-filter-prefix-zero-removes-all | PASS | all configured assertions passed |
| map-filter-refresh-without-options-preserves-policy | PASS | all configured assertions passed |
| map-filter-delete-and-recreate-clears-policy | PASS | all configured assertions passed |

#### PEER

| Case | Status | Result / note |
|---|---|---|
| peer-create-before-first-packet-udp | PASS | all configured assertions passed |
| peer-create-before-first-packet-tcp | PASS | all configured assertions passed |
| peer-processes-options-at-message-limit | PASS | all configured assertions passed |
| peer-adopts-existing-udp-mapping | PASS | all configured assertions passed |
| peer-adopts-existing-tcp-mapping | PASS | all configured assertions passed |
| peer-recreates-remembered-tcp-mapping | PASS | all configured assertions passed |
| peer-rejects-mismatched-port-on-renewal | PASS | all configured assertions passed |
| peer-rejects-prefer-failure | PASS | all configured assertions passed |
| peer-ipv6-udp-pinhole-restricts-remote-endpoint | PASS | all configured assertions passed |
| peer-ipv6-tcp-pinhole-restricts-remote-endpoint | PASS | all configured assertions passed |
| peer-ipv6-rejects-unavailable-external-port | PASS | all configured assertions passed |
| peer-ipv6-rejects-unavailable-external-address | PASS | all configured assertions passed |
| peer-ipv6-coexists-with-filtered-map | PASS | all configured assertions passed |

#### NAT

| Case | Status | Result / note |
|---|---|---|
| ipv6-pcp-map-reachability | PASS | all configured assertions passed |
| ipv6-nat66-pcp-peer-reachability | PASS | all configured assertions passed |
| ipv6-nat66-pcp-map-filter | PASS | all configured assertions passed |

#### PMP

| Case | Status | Result / note |
|---|---|---|

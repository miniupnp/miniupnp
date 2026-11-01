# PCP E2E Status

Updated: 2026-11-01T10:27:43Z

## Run

- Branch: dev/pcp-test-harness_E2E_inc_pcp_fixes
- Address families: IPv4 and IPv6
- Scenario selection: all
- Totals: **27 PASS**, **18 FAIL** (45 family runs)
- Artifacts: .tmp/pcp-e2e/2026-11-01T10-26-10Z (daemon startup/final logs and per-case captures/snapshots)

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
| map-filter-exact-peer-and-port | FAIL | udp 198.51.100.1:41002: expected blocked; got {'delivered': True} |
| map-filter-restricts-remote-port | FAIL | tcp 198.51.100.1:41003: expected blocked; got {'delivered': True} |
| map-filter-prefix-allows-subnet | PASS | all configured assertions passed |
| map-filter-narrow-prefix-rejects-outside-subnet | FAIL | udp 198.51.100.1:41005: expected blocked; got {'delivered': True} |
| map-filter-multiple-options-add-peers | FAIL | udp 198.51.100.1:41006: expected blocked; got {'delivered': True} |
| map-filter-refresh-adds-peer | FAIL | udp 198.51.100.1:41007: expected blocked; got {'delivered': True} |
| map-filter-refresh-replaces-peer-set | FAIL | udp 198.51.100.1:41008: expected blocked; got {'delivered': True} |
| map-filter-prefix-zero-removes-all | FAIL | udp 198.51.100.1:41009: expected blocked; got {'delivered': True} |

#### PEER

| Case | Status | Result / note |
|---|---|---|
| peer-create-before-first-packet-udp | FAIL | PCP PEER udp expected WAN tuple 198.51.100.1:43020; got {'token_hex': 'a7174218e6427cc05cc0c5c74ee72e02', 'source': '198.51.100.1', 'source_port': 41020} |
| peer-create-before-first-packet-tcp | FAIL | PCP PEER tcp expected WAN tuple 198.51.100.1:43021; got {'token_hex': 'd8f8362d371d3515e5a75a7caf884e43', 'source': '198.51.100.1', 'source_port': 41021} |
| peer-adopts-existing-udp-mapping | PASS | all configured assertions passed |
| peer-adopts-existing-tcp-mapping | PASS | all configured assertions passed |
| peer-recreates-remembered-tcp-mapping | FAIL | PCP PEER tcp expected WAN tuple 198.51.100.1:43040; got {'token_hex': 'b2885b8dd8803b2be8b596d620ece2c3', 'source': '198.51.100.1', 'source_port': 41040} |

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
| map-same-protocol-and-port-conflicts | FAIL | PCP response expected CANNOT_PROVIDE_EXTERNAL, got SUCCESS |
| map-renewal-keeps-forwarding | PASS | all configured assertions passed |
| map-delete-stops-forwarding | PASS | all configured assertions passed |
| map-unfiltered-allows-independent-peers | PASS | all configured assertions passed |

#### FILTER

| Case | Status | Result / note |
|---|---|---|
| map-filter-exact-peer-and-port | FAIL | udp 2001:db8:1::2:41002: expected blocked; got {'delivered': True} |
| map-filter-restricts-remote-port | FAIL | tcp 2001:db8:1::2:41003: expected blocked; got {'delivered': True} |
| map-filter-prefix-allows-subnet | PASS | all configured assertions passed |
| map-filter-narrow-prefix-rejects-outside-subnet | FAIL | udp 2001:db8:1::2:41005: expected blocked; got {'delivered': True} |
| map-filter-multiple-options-add-peers | FAIL | udp 2001:db8:1::2:41006: expected blocked; got {'delivered': True} |
| map-filter-refresh-adds-peer | FAIL | udp 2001:db8:1::2:41007: expected blocked; got {'delivered': True} |
| map-filter-refresh-replaces-peer-set | FAIL | udp 2001:db8:1::2:41008: expected blocked; got {'delivered': True} |
| map-filter-prefix-zero-removes-all | FAIL | udp 2001:db8:1::2:41009: expected blocked; got {'delivered': True} |

#### PEER

| Case | Status | Result / note |
|---|---|---|
| peer-create-before-first-packet-udp | PASS | all configured assertions passed |
| peer-create-before-first-packet-tcp | PASS | all configured assertions passed |
| peer-adopts-existing-udp-mapping | PASS | all configured assertions passed |
| peer-adopts-existing-tcp-mapping | PASS | all configured assertions passed |
| peer-recreates-remembered-tcp-mapping | PASS | all configured assertions passed |

#### NAT

| Case | Status | Result / note |
|---|---|---|
| ipv6-pcp-map-reachability | PASS | all configured assertions passed |

#### PMP

| Case | Status | Result / note |
|---|---|---|

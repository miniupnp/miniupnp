# PCP E2E Status

Updated: 2026-11-01T09:18:14Z

## Run

- Branch: dev/pcp-test-harness_E2E_inc_pcp_fixes
- Address families: IPv4 and IPv6
- Scenario selection: all
- Totals: **10 PASS**, **10 FAIL**
- Artifacts: .tmp/pcp-e2e/2026-11-01T09-17-28Z

## Results

### ipv4

| Case | Status | Result / note |
|---|---|---|
| map-single-udp-only | PASS | all PCP and traffic assertions passed |
| map-single-tcp-only | PASS | all PCP and traffic assertions passed |
| map-udp-and-tcp-same-port | PASS | all PCP and traffic assertions passed |
| map-same-protocol-and-port-conflicts | PASS | all PCP and traffic assertions passed |
| map-renewal-keeps-forwarding | PASS | all PCP and traffic assertions passed |
| map-delete-stops-forwarding | PASS | all PCP and traffic assertions passed |
| map-unfiltered-allows-independent-peers | PASS | all PCP and traffic assertions passed |
| map-filter-exact-peer-and-port | FAIL | udp 198.51.100.1:41002: expected blocked; got {'delivered': True} |
| map-filter-restricts-remote-port | FAIL | tcp 198.51.100.1:41003: expected blocked; got {'delivered': True} |
| map-filter-prefix-24-allows-subnet | PASS | all PCP and traffic assertions passed |
| map-filter-prefix-25-rejects-outside-subnet | FAIL | udp 198.51.100.1:41005: expected blocked; got {'delivered': True} |
| map-filter-multiple-options-add-peers | FAIL | udp 198.51.100.1:41006: expected blocked; got {'delivered': True} |
| map-filter-refresh-adds-peer | FAIL | udp 198.51.100.1:41007: expected blocked; got {'delivered': True} |
| map-filter-refresh-replaces-peer-set | FAIL | udp 198.51.100.1:41008: expected blocked; got {'delivered': True} |
| map-filter-prefix-zero-removes-all | FAIL | udp 198.51.100.1:41009: expected blocked; got {'delivered': True} |

### ipv6

| Case | Status | Result / note |
|---|---|---|
| ipv6-map-single-udp-only | PASS | all PCP and traffic assertions passed |
| ipv6-filter-prefix-128 | FAIL | udp fd42:5351:5351::2:41102: expected blocked; got {'delivered': True} |
| ipv6-filter-prefix-64 | PASS | all PCP and traffic assertions passed |
| ipv6-filter-prefix-127 | FAIL | tcp fd42:5351:5351::2:41104: expected blocked; got {'delivered': True} |
| ipv6-filter-prefix-zero-clears | FAIL | udp fd42:5351:5351::2:41105: expected blocked; got {'delivered': True} |

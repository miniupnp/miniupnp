# PCP end-to-end tests

These tests verify the forwarding behavior caused by accepted PCP MAP requests.
They are separate from `tests/pcp_pmp`, whose YAML corpus focuses on request and
response protocol behavior.

## Run

From the repository root, with Docker available:

```sh
./miniupnpd/tests/PCP_E2E/run-docker.sh
```

The script builds miniupnpd from the current checkout, starts a dual-stack
router with separate LAN and WAN interfaces, and starts three WAN traffic
agents with distinct IPv4 and IPv6 source addresses. A token echo listener runs
on the PCP client's LAN address. The runner sends PCP requests, checks
responses, probes IPv4 redirects or IPv6 pinholes through the router, and
removes created mappings using their original nonces. Docker fixtures and
networks are removed on exit.

Run selected scenarios with `--case NAME`, repeating the option as needed:

```sh
./miniupnpd/tests/PCP_E2E/run-docker.sh --case map-single-udp-only
```

Set `PCP_E2E_KEEP=1` to retain containers and networks for debugging. Run the
Python runner directly only when a compatible router, echo listener address,
and HTTP traffic agents are already available. Set `PCP_E2E_ARTIFACT_DIR` to
change the output root (default: `.tmp/pcp-e2e/`). Each run stores daemon
startup and final logs, one timestamped daemon log snapshot and runner log per
case, including `CASE START` and `CASE END` markers. These snapshots make the
daemon log timeline easy to line up with per-case packet captures. YAML case
definitions stay in `pcp-e2e-cases.yaml`.

## Current expected failures

The ordinary UDP/TCP mapping, shared-port, conflict, renewal, and deletion
scenarios pass on the current branch. The FILTER scenarios are deliberately
end-to-end: they require the request to be accepted and packets from excluded
peers or source ports to be blocked. The current daemon does not apply FILTER
to the firewall mapping, so those traffic assertions fail. In the latest full
run, 10 scenarios pass and 10 FILTER policy scenarios fail because excluded
traffic is delivered. This makes missing behavior visible instead of treating
a PCP success response as proof that the filter works.

The scenarios cover exact IPv4 peers (/32), a network prefix (/24), a narrower
network prefix (/25), source-port restrictions, multiple FILTER options in one
request, adding a filter on refresh, replacing a set with prefix zero followed
by a new peer, and removing all filters with prefix zero. IPv6 cases check
single UDP forwarding and /64, /127, and /128 filters, plus prefix-zero reset.
The runner encodes FILTER fields in RFC order: reserved byte, prefix length,
remote peer port, and address. RFC 6887 defines prefix zero as removing all
prior filters and a refresh with additional FILTER options as adding those
peers to the set.

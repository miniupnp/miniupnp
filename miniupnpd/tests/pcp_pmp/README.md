# PCP and NAT-PMP test harness

This directory contains a YAML-driven test corpus for miniupnpd's PCP and
NAT-PMP packet handling, plus the RFC text used by its case references. The
Docker environment runs miniupnpd with PCP and NAT-PMP enabled and UPnP
disabled.

This guide covers scripts, tools, configuration, and reports. See
[protocol analysis](ANALYSIS.md) for RFC coverage, implementation gaps, and
limits on what the tests establish.

## Scripts and tools

| File | Purpose |
|---|---|
| [`testpcp_natpmp_docker.sh`](testpcp_natpmp_docker.sh) | Build and run an isolated Docker fixture, invoke the Python runner, and clean up. |
| [`testpcp_natpmp.py`](testpcp_natpmp.py) | Execute YAML cases against a daemon, or check the harness with `--self-test`. |
| [`pcp-natpmp-cases.yaml`](pcp-natpmp-cases.yaml) | Define protocol requests, operations, profiles, and expected outcomes. |
| [`tools/compare_pcaps.py`](tools/compare_pcaps.py) | Decode and compare two packet captures. |
| [`tools/compare_branches.py`](tools/compare_branches.py) | Run identical cases against two committed daemon versions and report regressions. |
| [`../common/traffic_agent.py`](../common/traffic_agent.py) | Configure the WAN fixture and run the [shared traffic agent](../common/traffic_agent.md). |

Run the commands below from the repository root.

## Check the harness itself

```sh
python3 miniupnpd/tests/pcp_pmp/testpcp_natpmp.py --self-test
```

This checks variable resolution, bounded captures, response validation,
response ordering and duplicate rejection, port bounds, and TCP/UDP integration
with the shared traffic agent. It uses simulated replies and loopback sockets;
no daemon, Docker, PyYAML, or YAML corpus is required. It writes no status,
results, or packet captures, and returns a nonzero exit status on failure.
Protocol cases and their expectations remain in `pcp-natpmp-cases.yaml`.

## Run in Docker

From the repository root:

```sh
./miniupnpd/tests/pcp_pmp/testpcp_natpmp_docker.sh
```

The script builds a local image, starts an isolated dual-stack router, runs
the IPv4 PCP/NAT-PMP and IPv6 PCP cases, then removes the container and network.
Docker must be available to the current user. The container uses `NET_ADMIN`
to set up its temporary nftables rules. Each run writes `status.md` in this
directory with per-section PASS, XFAIL, FAIL, and SKIP tables for both address
families.

Status totals and section tables omit cases excluded by protocol, address
family or case selection. Sections with no remaining cases are hidden, so an
IPv6 report does not include NAT-PMP behavior. Other skips, including blocked
prerequisites, remain visible and counted. JSON results retain all cases for
complete branch comparisons; the CI summary hides rows filtered out on both
versions while retaining every regression.

Environment variables:

- `PCP_TEST_KEEP_CONTAINER=1`: retain the containers and networks for inspection.
- `PCP_TEST_IMAGE`: override the image name (default: `miniupnpd-pcp-test:local`).
- `PCP_TEST_CONTAINER`: override the router container name.
- `PCP_TEST_NETWORK`: override the LAN network name.
- `PCP_TEST_CAPTURE=0`: disable packet capture (enabled by default).
- `PCP_TEST_CAPTURE_DIR`: choose the host capture root (default: `.tmp/packet-captures/`).
- `PCP_TEST_RESULTS_DIR`: choose the directory for `status.md` and IPv4/IPv6 JSON results
  (default: this script's directory).
- `PCP_TEST_WAN_PEER=1`: enable the optional [WAN fixture](#run-with-wan-traffic).
- `DOCKER`: choose the Docker executable (default: `docker`).

The wrapper passes command-line arguments to the Python runner. Common options
include `--case NAME`, `--profile NAME`, `--no-mutating`, and `--capture-name NAME`.

```sh
PCP_TEST_CAPTURE=0 PCP_TEST_RESULTS_DIR="$PWD/.tmp/pcp-results" \
  ./miniupnpd/tests/pcp_pmp/testpcp_natpmp_docker.sh
```

## Run against an existing daemon

Install PyYAML (for example, the `python3-yaml` package), then run:

```sh
python3 miniupnpd/tests/pcp_pmp/testpcp_natpmp.py --host 192.0.2.1
```

These packets reach a real daemon, so use a disposable test instance.
Mapping lifecycle operations run by default.

Target and case arguments:

- `--host ADDRESS`: server address (default: `127.0.0.1`).
- `--port PORT`: server UDP port (default: `5351`).
- `--family ipv4|ipv6`: address family (default: `ipv4`).
- `--protocol pcp|natpmp|both`: protocols to run (default: `both`).
- `--case NAME`: select a YAML case; repeat to select several cases.
  Prerequisites are selected automatically.
- `--profile NAME`: server fixture profile (default: `baseline`);
  see [profile selection](#select-a-server-profile).
- `--mutating`: include mapping create, renew, and delete cases (default).
- `--no-mutating`: skip mapping changes.
- `--allow-empty-selection`: write SKIP results when the selection excludes the
  chosen profile, family, or protocol.
- `--peer-url URL`: WAN traffic-agent URL for cases requiring that fixture.
- `--self-test`: check the harness without contacting a daemon.

Report arguments:

- `--status-file PATH`: Markdown report path (default: `status.md` beside the runner).
- `--append-status`: append to the report instead of replacing it.
- `--results-file PATH`: request JSON results; with captures, the default is
  `results-FAMILY.json` in the run folder.

## Capture packets

The Docker harness captures each selected case with `tcpdump`. Direct Python
runs enable captures with `--capture-dir DIR`.

Capture arguments:

- `--capture-dir DIR`: capture root; create a timestamped subfolder for this run.
- `--capture-name NAME`: override the folder label. The default is the case name
  when exactly one case is selected, otherwise `all`. Requires `--capture-dir`
  for direct Python runs; the Docker wrapper supplies the capture directory.
  Names must start with a letter or digit and contain only letters, digits,
  underscores, hyphens, or dots.
- `--capture-interface IFACE`: interface to capture (default: `any`).
- `--tcpdump PATH`: tcpdump executable (default: `tcpdump`).
- `--capture-timeout SECONDS`: wait for tcpdump to stop after each case
  (default: `1.0`).

Folder names use local time with fractional seconds:
`YYYY-MM-DD_HH-MM-SS.fraction_LABEL`, for example
`2026-10-31_15-30-00.123456_before`.

```sh
# A named run, with both address families in the same folder:
./miniupnpd/tests/pcp_pmp/testpcp_natpmp_docker.sh --capture-name before
# A folder labeled announce-v2:
./miniupnpd/tests/pcp_pmp/testpcp_natpmp_docker.sh --case announce-v2
```

Each direct invocation creates its own timestamped subfolder. The Docker
wrapper shares one timestamp between its IPv4 and IPv6 invocations. Per-case
filenames include the address family and protocol. Capturing requires
`tcpdump` and permission to open a packet socket. The runner prints the capture
folder and includes it in the status report.

## Compare before and after captures

Select two per-case captures and write their decoded wire fields to Markdown:

```sh
python3 miniupnpd/tests/pcp_pmp/tools/compare_pcaps.py \
  .tmp/packet-captures/BEFORE_RUN/ipv4-pcp-filter-on-map-deletion.pcap \
  .tmp/packet-captures/AFTER_RUN/ipv4-pcp-filter-on-map-deletion.pcap \
  --output comparison.md
```

The report includes a packet overview with frame numbers, UTC times and UDP
endpoints, followed by before/after field tables. It decodes PCP common headers,
IPv4 and IPv6 headers (including source and destination addresses, IPv4 options,
and supported IPv6 extension headers), UDP ports,
v1/v2 MAP and PEER bodies, option framing and padding, THIRD_PARTY, FILTER and
PORT_SET payloads, and NAT-PMP public-address and TCP/UDP mapping messages.
Result codes are shown with names. Nonces, reserved bytes, option padding and
truncated fields are retained. Raw payload hex dumps are omitted. Unknown
options keep their code and payload lengths.

Arguments:

- `before`: first pcap or pcapng file (required).
- `after`: second pcap or pcapng file (required).
- `--output PATH` / `-o PATH`: write Markdown to a file (default: stdout).
- `--changes-only`: omit identical fields.
- `--port PORT`: UDP server port (default: `5351`; use `5350` for notifications).

Classic pcap decoding uses only Python's standard library;
pcapng input additionally requires `tcpdump` for conversion. Ethernet/VLAN,
Linux cooked v1/v2, raw IP and BSD loopback captures are supported with IPv4
and IPv6. IP fragments are reported as decoding notes rather than reassembled.

For packet-alignment and interpretation limits, see
[capture analysis](ANALYSIS.md#interpreting-packet-comparisons).

Run the offline decoder checks with:

```sh
python3 miniupnpd/tests/pcp_pmp/tools/test_compare_pcaps.py
```

## Compare master with a pull request in CI

The workflow [`.github/workflows/pcp-natpmp.yml`](../../../.github/workflows/pcp-natpmp.yml)
runs on pull requests targeting master when daemon or harness files change.
It builds the master commit recorded in the PR event and the actual PR head
separately, then runs both with the PR's harness and YAML corpus. The harness
is copied onto master even when master does not contain it. This keeps the
requests and expectations identical while comparing the two daemon versions.

The job summary shows master/candidate counts, regressions, improvements and
per-case statuses. The downloadable artifact contains a commit/corpus manifest,
both run logs and status reports, and JSON results. The workflow does not
capture packets. Its summary includes commands to create local worktrees at
the tested commits and rerun with `--capture` for packet details.

Existing master failures do not fail the job. The check fails if a master PASS
stops passing, an executed case becomes skipped, or an XFAIL becomes FAIL.
Cases newly exercised after a dependency starts passing are listed as new
coverage; a newly exposed failure is not an established regression. Missing
reports, corpus mismatches and build/startup errors fail the
check as infrastructure errors. Both address families must write complete
results, including SKIPs for cases that do not support that family.

The workflow can also be started manually with an optional case name, explicit
server profile, and optional WAN peer. The default remains baseline without
WAN traffic or packet capture.
For a manual run, the selected branch is compared with master. Artifacts are
retained for 14 days. With local capture enabled, missing captures also fail
the comparison, and relative report links resolve inside the output directory.

The same comparison can be run locally with two git checkouts and Docker.
Add `--capture` to collect pcaps, tcpdump logs and decoded before/after
Markdown field tables:

```sh
python3 miniupnpd/tests/pcp_pmp/tools/compare_branches.py \
  --master-source /path/to/master-checkout \
  --candidate-source /path/to/pr-checkout \
  --output .tmp/master-pr-comparison --capture
```

Arguments:

- `--master-source DIR`: master git checkout (required).
- `--candidate-source DIR`: candidate git checkout (required).
- `--output DIR`: new artifact directory (required); an existing directory is rejected.
- `--case NAME`: select a YAML case; repeat to select several cases.
- `--profile NAME`: server fixture profile (default: `baseline`).
- `--wan-peer`: enable WAN TCP/UDP traffic checks (disabled by default).
- `--capture`: collect pcaps, tcpdump logs, and decoded comparisons (disabled by default).

With `--capture`, captures use separate timestamped `master` and `candidate`
folders. Raw payload hex dumps are omitted from the field tables.
Daemon sources come from the committed HEAD of each checkout; uncommitted
daemon edits are excluded. The harness comes from this invocation's
`pcp_pmp/` directory and its sibling `common/` directory. Python with tarfile's
`data` extraction filter is required (Python 3.12 or newer supports it).

Exit statuses:

- `0`: no regressions.
- `1`: regressions found.
- `2`: incomplete comparison or infrastructure error.

Each branch-comparison run includes `results-ipv4.json` and `results-ipv6.json`
beside each daemon's status report, even without packet capture. Regular
Docker capture runs keep JSON results inside the capture folder unless
`PCP_TEST_RESULTS_DIR` is specified. For direct runner invocations without captures, use
`--results-file PATH` to request JSON results. These include the corpus SHA-256,
address family, and each case's status and detail.

Run the offline comparison-policy and report-completeness checks with:

```sh
python3 miniupnpd/tests/pcp_pmp/tools/test_compare_branches.py
```

## Corpus and expected failures

Corpus structure:

- [`pcp-natpmp-cases.yaml`](pcp-natpmp-cases.yaml): protocol requests, operations,
  and expected outcomes.
- Protocol sections: document the scope of each group of cases.
- Case definitions: provide the request, expected result, and short description.
- RFC citations and coverage notes: YAML comments beside the relevant cases
  explain assertions, fixture requirements, and coverage limits, referencing
  the plain-text specifications in [`rfcs/`](rfcs/).

Expected failures:

- `XFAIL`: a known implementation gap, explained in the case definition.
- Expected failures document protocol behavior that miniupnpd does not yet
  implement; they are not harness execution failures.
- Once miniupnpd implements the expected behavior, the same case should report
  `PASS` without changing its expected result.

Dependencies:

- `depends_on: [protocol/case-name]`: declare prerequisites in a YAML case.
- Each prerequisite must appear earlier in the corpus and support the dependent
  case's address families.
- Only `PASS` satisfies a dependency.
- A prerequisite reporting `FAIL`, `XFAIL`, or `SKIP` causes the dependent case
  to report `SKIP` with an explanation, without sending packets.
- `--case NAME`: selecting a dependent case also selects its prerequisites.
- The RFC 7652 nonce and sequence tests depend on the authentication support probe.

## Select a server profile

Pass `--profile NAME` to the Python runner, Docker wrapper, or branch-comparison
tool. The default is `baseline`.

| Profile | Fixture to provide |
|---|---|
| `baseline` | A daemon that leaves PORT_SET unprocessed and grants one MAP port. |
| `port-set` | An allocator configured to grant the complete sets used by the corpus. |
| `port-set-limited` | An allocator configured for two ports per new set and four ports per client. |

Selecting a profile changes the cases and expectations; it does not enable a
daemon feature or configure allocator quotas. Read the
[full fixture contracts and interpretation limits](ANALYSIS.md#rfc-7753-port_set-coverage)
before choosing an allocator profile.

## Run with WAN traffic

For physical forwarding checks, enable the optional WAN actor:

```sh
PCP_TEST_CAPTURE=0 PCP_TEST_WAN_PEER=1 \
  ./miniupnpd/tests/pcp_pmp/testpcp_natpmp_docker.sh --profile port-set
```

This adds a second isolated dual-stack Docker network, routes actor traffic
through the disposable gateway, and starts temporary LAN listeners. New
inbound traffic remains blocked by default; established replies are allowed.
Every probe uses a fresh WAN source port so old conntrack entries cannot make
a deleted mapping appear usable. Both endpoints must confirm delivery, and
blocked probes require that the LAN listener receives nothing. The fixture
uses Docker's routed IPv6 bridge mode, which requires a Docker version that
supports `com.docker.network.bridge.gateway_mode_ipv6=routed`.

The ordinary single-port WAN preflight cases can be run even before PORT_SET
is implemented to verify both address families and the fixture's blocking path:

```sh
PCP_TEST_CAPTURE=0 PCP_TEST_WAN_PEER=1 \
  ./miniupnpd/tests/pcp_pmp/testpcp_natpmp_docker.sh --profile port-set \
  --case port-set-wan-fixture-udp --case port-set-wan-fixture-tcp
```

For a direct runner targeting an appropriately configured test server:

- `--profile port-set` or `--profile port-set-limited`: select the allocator fixture.
- `--peer-url http://ACTOR:18080`: connect to its WAN traffic agent.

`../common/traffic_agent.py` runs the [shared traffic agent](../common/traffic_agent.md).
Its arguments are:

- `--source4 ADDRESS`: IPv4 probe source (default: `0.0.0.0`).
- `--source6 ADDRESS`: IPv6 probe source (default: `::`).
- `--port PORT`: HTTP control port (default: `18080`).
- `--host ADDRESS`: HTTP listen address (default: `127.0.0.1`; Docker uses `0.0.0.0`).
- `--route6 PREFIX` and `--gateway6 ADDRESS`: optional IPv6 route; supply both.
  The outgoing interface is selected using `--source4`.

Configure its source addresses and routing for that isolated topology.
The Docker wrapper sets this up automatically.
Only one instance of the fixed-subnet Docker fixture can run on a host at once.

Master/PR comparison and local packet diagnostics support the same profiles:

```sh
python3 miniupnpd/tests/pcp_pmp/tools/compare_branches.py \
  --master-source /path/to/master --candidate-source /path/to/pr \
  --output .tmp/port-set-details --profile port-set --wan-peer --capture
```

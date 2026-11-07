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
| [`run-docker.sh`](run-docker.sh) | Build and run an isolated Docker fixture, invoke the Python runner, and clean up. |
| [`run_pcp_wire_cases.py`](run_pcp_wire_cases.py) | Execute YAML cases against a daemon, or check the harness with `--self-test`. |
| [`pcp-wire-cases.yaml`](pcp-wire-cases.yaml) | Define protocol requests, operations, profiles, and expected outcomes. |
| [`tools/compare_pcap_wire_fields.py`](tools/compare_pcap_wire_fields.py) | Decode and compare two packet captures. |
| [`tools/compare_daemon_branches.py`](tools/compare_daemon_branches.py) | Run identical cases against two committed daemon versions and report regressions. |
| [`../common/traffic_agent.py`](../common/traffic_agent.py) | Configure the WAN fixture and run the [shared traffic agent](../common/traffic_agent.md). |
| [`../common/lib_test.py`](../common/lib_test.py) | Code both PCP runners share: sending requests and checking responses, LAN/WAN probes, the lease file, packet capture, the status report. |
| [`../common/pcp_packet_encoding.py`](../common/pcp_packet_encoding.py) | PCP / NAT-PMP names, request encoding and response decoding (no I/O). |

Run the commands below from the repository root.

## Check the harness itself

```sh
sh miniupnpd/tests/common/run_self_tests.sh                         # every self-test of the harness
python3 miniupnpd/tests/pcp_wire/run_pcp_wire_cases.py --self-test  # this runner's corpus only
```

`common/run_self_tests.sh` is the one list of the self-tests: the unit tests of `common/` and of
`tools/`, the `--self-test` of both runners and of the traffic agent, and `sh -n` of the driver
scripts. The GitHub workflows run it, and so do `pcp_e2e/run-docker.sh` and `run-freebsd.sh`
before their cases (`PCP_TEST_SELF_TEST=0` skips it). No daemon or Docker is needed; PyYAML is.

The runner itself is the command line and the run loop: it reads `pcp-wire-cases.yaml`, selects
the cases of the invocation, runs them, and writes the results and the status report. What a case
does (the step engine, the lifecycle, daemon-restart and PA cases, the corpus checks and the case
selection, captures, the report) is in `../common/lib_test.py`, tested by `../common/test_lib_test.py`
with simulated replies and loopback sockets. Its `--self-test` reads, expands and checks the corpus
(case shapes, profiles, dependencies) and returns a nonzero exit status on a problem.

### Writing packets in the corpus

Requests are written as named PCP / NAT-PMP packets; `../common/pcp_corpus_expander.py` expands them
into the low-level `kind:` form the runner builds bytes from (a request that
still has `kind:` is used as is, for raw or unusual packets).

```yaml
request:
  pcp: MAP                  # or PEER, AUTHENTICATION
  lifetime: 300
  protocol: UDP             # UDP | TCP | number
  internal_port: 47202
  external_port: 48201
  nonce: '271828182845904523536028'
  options: [PREFER_FAILURE, {PORT_SET: '0001c73900'}]
expect:
  opcode: MAP_RESPONSE
  result: [CANNOT_PROVIDE_EXTERNAL]
```

- `pcp:` defaults to version 2, `client: source`, `external_address: '::'`.
- `header: ANNOUNCE | <number>` sends only the common header; `natpmp: PUBLIC_ADDRESS |
  MAP_UDP | MAP_TCP` defaults to version 0.
- Option names: `THIRD_PARTY`, `PREFER_FAILURE`, `FILTER`, `NONCE`, `PORT_SET`;
  other options use `{code: N, data_hex: ...}` (`data_repeat: N` repeats the data N times).
- Result names depend on the case or step `protocol` (PCP or NAT-PMP).
- `port_set: 4` is shorthand for a PORT_SET option whose first port is the
  request's `internal_port` (`port_set: {size: 4, parity: true}` sets parity);
  `{PORT_SET: {size: 4, first: 51001}}` spells it out and a hex string is still accepted.
- `external_port` defaults to 0; set it to `null` to omit the field.
- NAT-PMP packets: `natpmp: MAP_UDP | MAP_TCP | PUBLIC_ADDRESS | <name>_RESPONSE | <number>` with
  `private_port`, `public_port`, `lifetime`; `reserved` defaults to 0 (`null` omits it) and
  `truncate_to: N` sends only the first N bytes, which replaces raw hex for short datagrams.
  `verify: natpmp-mapping` derives the usual private/external port and lifetime checks.

Sequence steps (`protocol_sequence`) have more shorthands, all expanded by `../common/pcp_corpus_expander.py`:

```yaml
defs:
  steps:                               # reusable steps
    map-not-authorized-echo:
      protocol: pcp
      expect: {version: 2, opcode: MAP_RESPONSE, result: [NOT_AUTHORIZED], length: 72}
      request: {pcp: MAP}
request:
  kind: protocol_sequence
  steps:
  - protocol: pcp
XX
    expect: {version: 2, opcode: MAP_RESPONSE, result: [SUCCESS], length: 72}
    verify: port-set-mapping           # derived captures + asserts
    assert: {external: {nonzero: true}}   # overrides; null removes a derived assert
  - use: map-not-authorized-echo       # template; keys here are deep-merged over it
    request: {protocol: UDP, lifetime: 300, nonce: ffeeddccbbaa998877665544, port_set: 1}
    each:                              # one step per entry
    - request: {internal_port: 51002}
    - request: {internal_port: 51003}
  cleanup: auto                        # delete every distinct successful MAP
```

- `verify: mapping` captures the standard MAP response fields and asserts the
  internal port, nonce, protocol and lifetime (0 for a delete, otherwise 1..600)
  from the request; `port-set-mapping` adds the PORT_SET option fields. Entries
  under `assert:` or `captures:` replace the derived entry of the same name.
- `cleanup: auto` sends a lifetime-0 MAP for each distinct (nonce, protocol,
  internal port) the steps created successfully, in no particular order.
- A top-level `defs.packets.<name>` mapping defines a reusable packet; a request
  with `use: <name>` starts from it and its own keys override the template.

## Run in Docker

From the repository root:

```sh
./miniupnpd/tests/pcp_wire/run-docker.sh
```

The script builds the shared tools image if it is missing, compiles the daemon of this tree if no
build of the same source exists (`e2e_build_daemon`, `.tmp/tests/daemon`), starts an isolated dual-stack router, runs
the IPv4 PCP/NAT-PMP and IPv6 PCP cases, then removes the container and network.
Docker must be available to the current user. The container uses `NET_ADMIN`
to set up its temporary nftables rules. Each run updates the Linux column of
`status.md` in this directory (see [Platforms and the combined status
report](#platforms-and-the-combined-status-report)) with per-section PASS,
XFAIL, FAIL, and SKIP tables for both address families.

Status totals and section tables omit cases excluded by protocol, address
family or case selection. Sections with no remaining cases are hidden, so an
IPv6 report does not include NAT-PMP behavior. Other skips, including blocked
prerequisites, remain visible and counted. JSON results retain all cases for
complete branch comparisons; the CI summary hides rows filtered out on both
versions while retaining every regression.

Environment variables:

- `PCP_TEST_KEEP_CONTAINER=1`: retain the containers and networks for inspection.
- `PCP_TEST_CONTAINER`: override the router container name.
- `PCP_TEST_NETWORK`: override the LAN network name.
- `PCP_TEST_SLOT=N` (1-128): use this address set (LAN and WAN). By default a run takes the first
  free one and holds it with `flock` in `/tmp/pcp-e2e-slots`, so runs can share Docker.
- `PCP_TEST_CAPTURE=0`: disable packet capture (enabled by default).
- `PCP_TEST_CAPTURE_DIR`: choose the host capture root (default: `.tmp/packet-captures/`).
- `PCP_TEST_RESTART_CASES=0`: skip the `daemon-restart` cases (they run on the host and need PyYAML).
- `PCP_TEST_RESULTS_DIR`: choose the directory for `status.md` and IPv4/IPv6 JSON results
  (default: this script's directory).
- `PCP_TEST_DATA_DIR`: choose the directory for `status-data.json` (default: `.tmp/tests/pcp_wire` in the repository)
- `PCP_TEST_WAN_PEER=1`: enable the optional [WAN fixture](#run-with-wan-traffic).
- `DOCKER`: choose the Docker executable (default: `docker`).

The wrapper passes command-line arguments to the Python runner. Common options
include `--case NAME`, `--profile NAME`, `--no-mutating`, and `--capture-name NAME`.

```sh
PCP_TEST_CAPTURE=0 PCP_TEST_RESULTS_DIR="$PWD/.tmp/pcp-results" \
  ./miniupnpd/tests/pcp_wire/run-docker.sh
```

## Run against an existing daemon

Install PyYAML (for example, the `python3-yaml` package), then run:

```sh
python3 miniupnpd/tests/pcp_wire/run_pcp_wire_cases.py --host 192.0.2.1
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
- `--platform NAME`: the platform column this run fills in `status.md` (default: `linux`).
- `--fixture COMMAND`: platform fixture for cases that need `daemon-restart`
  (see below); `--fixture-only` runs just those cases.
- `--results-file PATH`: request JSON results; with captures, the default is
  `results-FAMILY.json` in the run folder.

## Platforms and the combined status report

`status.md` holds one status column per platform, so a row reads, for example,
`PASS | FAIL` for Linux and FreeBSD. Each run fills in only its own platform's
column (`--platform`, default `linux`) and replaces only the cases and address
family it exercised; the raw per-platform results live in `status-data.json` (kept in `.tmp/tests/pcp_wire/` of the repository, outside the test directory; set `PCP_TEST_DATA_DIR` to change that, or pass `--status-data-file` to the runner). The Docker wrapper fills the `linux` column. The FreeBSD wrapper
fills the `freebsd` column:

```sh
./miniupnpd/tests/pcp_wire/run-freebsd.sh
```

It boots a throwaway FreeBSD VM under QEMU (KVM when available) and runs
`freebsd/ci.sh` inside it: build miniupnpd with pf on an `epair(4)` router
topology (a WAN and two LANs, default route out of the WAN), run the whole YAML
suite from a client jail on LAN1, then the cases that restart the daemon. The
client is a vnet jail because the daemon decides which LAN a request came from by
routing to the sender; for the router's own address that route is `lo0`, so a
runner on the router itself is ignored over IPv6. Requires `qemu-system-x86_64`,
`qemu-img`, `xz`, `curl`, `ssh` and `xorriso`/`genisoimage`/`mkisofs` on the host;
the header of the script lists its environment variables. The first run builds a
cached VM image with the build tools, Python and PyYAML. Results, captures and
logs go to `.tmp/ci/out/freebsd/announce/`, and the merged `status.md` is updated.

Features a platform's daemon cannot offer are declared per run with
`--unsupported FEATURE` and tagged in the YAML with `requires`; those cases are
reported as SKIP. The FreeBSD run passes `--unsupported pcp-peer`: PCP PEER is
only built with the netfilter backend.

### Cases that restart the daemon

Some behavior, such as the unsolicited multicast ANNOUNCE at startup, cannot be
observed by a client talking to a running daemon. YAML cases with
`requires: [daemon-restart]` and `request: {kind: daemon_restart}` run only when
`--fixture COMMAND` is given. The runner calls
`COMMAND daemon-restart DIRECTORY FAMILY`; the fixture must cold-start the
daemon while recording its outgoing packets and leave one classic pcap per
interface in `DIRECTORY`: `lan-N.pcap` for each LAN and `wan-N.pcap` for each
external interface. The case's `unsolicited_announce` expectation is then
checked by the runner. The test builds define `PCP_ANNOUNCE_COUNT=5`
(production sends ten restart ANNOUNCEs, about 127 s) so the capture finishes in
seconds; `startup-announce-retransmission` checks the repeat timing. Fixtures: `fixtures/docker.sh` (Linux) and
`fixtures/freebsd.sh` (the VM).

### Mapping Update cases

Cases with `requires: [wan-renumber]` (`request: {kind: wan_renumber}`, `expect:
{kind: mapping_update}`) cover RFC 6887 §14.2. The runner starts a router through
the fixture, creates the `mapping`, has the fixture change the router's external
address, and collects the unsolicited MAP responses for that mapping for five
seconds. It then checks the `mapping_update` expectation: count, gap timing,
Epoch Time, result code, the new external address, and echoed or omitted options.
With `refresh_after_ms`, the client refreshes the mapping that long after the first
update, and the reply to the refresh is not counted.

The fixture contract is `FIXTURE supports wan-renumber` (exit 0), then
`wan-renumber-start DIRECTORY FAMILY` (prints the router's LAN address),
`wan-renumber-change DIRECTORY` and `wan-renumber-stop DIRECTORY` (leaves the
daemon log and the LAN/WAN captures in `DIRECTORY`). `fixtures/docker.sh` provides
it: it moves the WAN address from .1 to .3 of the WAN /24. The Docker driver
runs these cases on the host, with the daemon-restart cases. `fixtures/freebsd.sh`
does not provide it yet, so they are `SKIP` on FreeBSD.

The cases carry a `known_failure`, because miniupnpd does not implement Mapping
Update. With this fixture (`enable_upnp=no`), the Linux daemon does not notice the
address change at all: it opens its interface watcher only together with the UPnP
sockets.

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
./miniupnpd/tests/pcp_wire/run-docker.sh --capture-name before
# A folder labeled announce-v2:
./miniupnpd/tests/pcp_wire/run-docker.sh --case announce-v2
```

Each direct invocation creates its own timestamped subfolder. The Docker
wrapper shares one timestamp between its IPv4 and IPv6 invocations. Per-case
filenames include the address family and protocol. Capturing requires
`tcpdump` and permission to open a packet socket. The runner prints the capture
folder and includes it in the status report.

## Compare before and after captures

Select two per-case captures and write their decoded wire fields to Markdown:

```sh
python3 miniupnpd/tests/pcp_wire/tools/compare_pcap_wire_fields.py \
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
python3 miniupnpd/tests/pcp_wire/tools/test_compare_pcap_wire_fields.py
```

## Compare master with a pull request in CI

The `wire-linux` job of [`.github/workflows/regression-testing.yml`](../../../.github/workflows/regression-testing.yml)
runs on pull requests targeting master when daemon or harness files change, at the same time
as the workflow's other jobs (`self-test`, `wire-freebsd`, `end2end-linux`).
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
python3 miniupnpd/tests/pcp_wire/tools/compare_daemon_branches.py \
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
`pcp_wire/` directory and its sibling `common/` directory. Python with tarfile's
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
python3 miniupnpd/tests/pcp_wire/tools/test_compare_daemon_branches.py
```

## Corpus and expected failures

Corpus structure:

- [`pcp-wire-cases.yaml`](pcp-wire-cases.yaml): protocol requests, operations,
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
  ./miniupnpd/tests/pcp_wire/run-docker.sh --profile port-set
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
  ./miniupnpd/tests/pcp_wire/run-docker.sh --profile port-set \
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
python3 miniupnpd/tests/pcp_wire/tools/compare_daemon_branches.py \
  --master-source /path/to/master --candidate-source /path/to/pr \
  --output .tmp/port-set-details --profile port-set --wan-peer --capture
```

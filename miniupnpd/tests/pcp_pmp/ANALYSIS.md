# PCP and NAT-PMP protocol analysis

This document describes protocol coverage, implementation gaps, fixture
contracts, and the limits of the evidence produced by the test corpus.
For commands, configuration, report formats, and tool usage, see the
[harness guide](README.md). Requests and expected outcomes are defined in
[`pcp-natpmp-cases.yaml`](pcp-natpmp-cases.yaml); RFC references are stored in
[`rfcs/`](rfcs/).

## Interpreting packet comparisons

Messages are aligned by protocol, direction, opcode and occurrence, not by
transaction identity. Prefer two captures of the same case and inspect request
fields and frame numbers when retries, missing responses, or other traffic are
present. A missing response in the capture does not establish a server discard.
These tables describe bytes on the wire; they do not assign PASS/FAIL or prove
that firewall rules enforce a mapping or filter.

## RFC 6886 coverage

NAT-PMP cases cover incomplete UDP/TCP requests, response-bit discard, unknown
opcode payload echo, refusal response fields, ignored reserved bits, identical
retries, retries with changed port suggestions, port conflicts, short leases,
idempotent deletion, ignored suggested ports on deletion, TCP/UDP coexistence,
and nondecreasing epoch values. Bulk UDP deletion and automatic expiry depend on
successful changed-suggestion retry tests, because they use that behavior to
distinguish an existing mapping from a newly allocated one. Their assertions
cover control-plane mapping behavior; they do not prove packet forwarding.

The following RFC requirements still need additional isolated fixtures:

- Two LAN clients: companion-port reservation across clients, source-address
  ownership, and deletion isolation (sections 3.3 and 3.4).
- A real WAN peer and traffic endpoints: unsolicited inbound traffic, TCP-only
  and UDP-only rules, bidirectional translation, and return source ports
  (sections 3.3 and 3.9).
- Controlled restart/address changes and a multicast listener on UDP 5350:
  announcements, retransmission timing, epoch reset, and recovery (sections
  3.2.1, 3.6, and 3.7). The current epoch case checks ordering only.
- Static mappings, constrained permissions, and allocation exhaustion:
  protected deletion, partial bulk deletion, and resource errors.
- Alternative daemon modes: WAN-side request rejection, forwarding-only/NAT
  disabled operation, and administratively disabled NAT-PMP (sections 3.3,
  3.8, and 5).

Client backoff behavior in section 3.1 requires a NAT-PMP client test rather
than assertions about the server. The runner currently sends sequential probes.

## RFC 6887 coverage

The additional RFC 6887 section exercises PCP v2 common-header and MAP/PEER
truncation boundaries, misalignment and oversized lengths, replicated client
address mismatches, ANNOUNCE lifetime/option handling, malformed option lengths,
optional option padding and omission, FILTER prefix validation, forbidden option
combinations, reserved response bytes, error payload copying, and error lifetime.
MAP lifecycle probes cover TCP as well as UDP, changed/zero suggestions on renewal,
idempotent deletion, wrong-nonce refresh/deletion, error rollback, and reserved
external PCP ports. PEER probes cover reserved fields and nonce ownership.

These tests intentionally distinguish control-plane assertions from forwarding:
accepting a FILTER option does not establish that its restrictions are enforced.
The no-state-change probes attempt a new nonce after a rejected create, exposing
leftover ownership; they do not inspect every firewall object or timer.

Further RFC 6887 coverage requires additional isolated fixtures:

- Two clients and explicit THIRD_PARTY-enabled/disabled profiles: authorization,
  source ownership, cross-client conflicts, and third-party address validation
  (sections 8.2, 11.3, 13.1, and 18).
- WAN traffic endpoints: actual TCP/UDP forwarding, FILTER enforcement and
  updates, protocol isolation, reserved-port protection, and PEER five-tuple
  behavior (sections 11–13). Header-only acceptance is insufficient evidence.
- Static/implicit mappings and active traffic: MAP versus PEER deletion rights,
  minimum idle lifetimes, and static mapping coexistence (sections 11, 12, 15).
- Controlled restart/address changes plus UDP 5350 multicast listeners: epoch
  reset/rate, unsolicited ANNOUNCE, mapping updates, and recovery (sections 8.5,
  14, and 16). The existing epoch checks only assert nondecreasing values.
- Resource/quota configuration and restricted permissions: short-lived errors,
  allocation exhaustion, EXCESSIVE_REMOTE_PEERS, and rollback of partial updates.
- NAT64/multiple external addresses and complete IPv6 mapping lifecycles.
  IPv6 wire-format checks currently do not prove firewall or translation behavior.

Legacy PCP v1 cases are compatibility tests, not RFC 6887 v2 compliance tests.
RFC 7652 authentication tests remain separate and depend on the support probe.
PREFER_FAILURE rate limiting is optional (section 13.2); a load test could measure
it, but lack of throttling alone is not a mandatory-protocol conformance failure.
Client retransmission/backoff and response-source rejection need client tests;
this corpus primarily exercises the server.

## RFC 7753 PORT_SET coverage

The corpus contains 121 PORT_SET cases, each enabled for both IPv4 and IPv6,
with TCP and UDP variants. Coverage notes beside the relevant cases in
[`pcp-natpmp-cases.yaml`](pcp-natpmp-cases.yaml) describe server requirements,
fixture contracts, and limits.

Three explicit profiles keep a server's optional-option fallback separate from
an allocator that processes PORT_SET:

| Profile | Required fixture behavior |
|---|---|
| `baseline` (default) | Treat option 130 as unprocessed and grant one MAP port. |
| `port-set` | Process PORT_SET; grant complete sets through 16 ports when in range and resources are free; allow the tested high ports and the permission boundary at 1024. |
| `port-set-limited` | Process PORT_SET; cap each new set at two ports and each client at four ports, with global resources available. |

Allocator fixtures must honor 120- and 300-second renewals. Expiry cases use
the granted lifetime, allowing up to 120 seconds for a short request, rather
than assuming the server will grant a two-second lease. The profiles are
explicit test-setup contracts, not capability probes or requirements that
every RFC 7753 server always grant a particular size. An absent PORT_SET
response option does not establish lack of support (section 4.3).

When an implementation intentionally starts processing PORT_SET, select the
matching allocator profile for its master/PR comparison. The baseline profile
is an explicit unprocessed-option contract and should not classify that
intentional profile change as a protocol regression.

The current daemon does not implement option 130. Its default baseline cases
test single-port fallback and option framing. Selecting an allocator profile
against that daemon intentionally produces failures; no response-based
capability inference or automatic skipping hides them. A conforming server
may choose a one-port grant; failing our configured multi-port fixture contract
alone is not a general RFC-conformance verdict.

The allocator cases cover processed-option errors and rollback, single/multi-
port response fields, port bounds, reserved bits, optional parity hints,
nonce ownership, idempotent retries, renewal and whole-set deletion/expiry,
partial grants, quota exhaustion/recovery, and overlapping entities. Overlap
cases collect multiple Mapping Updates in either order and reject duplicate or
extra replies. Ownership and neighboring-port probes distinguish a real set
from a server merely echoing an ignored option.

### WAN forwarding coverage

WAN cases check each granted member, adjacent/ungranted ports, TCP/UDP
isolation, renewal, rejection preservation, deletion and expiry. Partial-grant
traffic checks also cover the unallocated tail of the requested range. Cases
requiring the WAN fixture remain visible as SKIP when it is not supplied.

`port-set-limited` requires a server/configuration implementing its quota
contract; the harness cannot enable an allocator or quota policy that the
server does not implement. Full allocator and WAN assertions should be run
against that implementation before claiming it passes RFC 7753 coverage.
Client-side allocation strategies, stateless translation profiles and restart/
failover scenarios are separate fixtures; see the coverage comments in the corpus.

For WAN fixture setup and commands, see [Run with WAN traffic](README.md#run-with-wan-traffic).

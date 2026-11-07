# upnp_wire: coverage and limits

What the UPnP suites check, how a result is read, and what is still open. The results themselves are in
`status.md`.

## How a result is read

- **FAIL**: a gap between the specification and the daemon. The corpus has a `# spec gap:` comment with what
  the run saw. A FAIL is not always a defect to fix: many are tolerant parsing, or a wrong error code.
- **XFAIL**: a feature the daemon does not implement. `GetOutboundPinholeTimeout` is one (a stub in
  `upnpsoap.c`); it is optional.
- **SKIP**: a check only built with `configure --strict`, on a build without it. The `igd1-strict` and
  `igd2-strict` runs execute these. A case that needs a fixture the run lacks skips too.

A case name is `<doc>-<section>-<level>-<what>`. The level is the strength of the requirement on the device:
`must`, `should`, `may`, or `impl` when the spec requires nothing and the case checks miniupnpd itself. A
hostile input ends with a liveness step, so a crash or a hang is a FAIL.

## Coverage

Each cited spec was read section by section against the corpus when it had 156 cases. That review listed 985
testable-looking device requirements (DeviceProtection left out): 29% covered, 16% partly and 55% not. Of 711
testable MUSTs, 33% were fully covered. These are estimates: the same rule can count under two specs, and
"covered" means a case checks it, not that it passes. The corpus has grown since; the figures were not redone.

The cases added since then cover HTTP framing, SOAP structure, the second-client rules, the description
and SCPD details, GENA errors and value sweeps of every argument.

## Findings worth a maintainer's look

- `DeletePortMappingRange` with `NewManage=0` deletes the mappings of another client, in secure mode.
- A mapping added with `NewEnabled=0` forwards traffic, and reads back as enabled.
- `SystemUpdateID` does not change, and a lease above 604800 is accepted.
- HTTP: a chunked body is not decoded, and `Content-Length` is not validated.
- SOAP: `mustUnderstand` is ignored, the body structure is not checked, and an action runs on any service.
- `UpdatePinhole` answers 501 on FreeBSD pf.

No hostile input stopped the daemon on any build, and no path traversal served a file.

## PCP interplay

`pcp-then-upnp-same-port` and `pcp-then-upnp-addany` (upnp_e2e) expect a port held by PCP to be refused to
UPnP. No spec requires this for two mechanisms in one box: RFC 6970 describes a PCP client inside an IGD. The
expectations are a project policy, and they follow the cross-protocol protection work.

## Not covered

- **DeviceProtection:** not built (`ENABLE_DP_SERVICE`), and optional in IGD2.
- **Proposed cases not added yet:** alive and byebye
  details, and the event timing rules.
- **Fixture limits:** link and WAN state changes (events on change, `PhysicalLinkStatus` Down, 701, 702, 703),
  multi-homing, subscription expiry (the daemon keeps at least 1800 s), and the idle HTTP timeout.
- **FreeBSD:** the `upnp_wire` lease-file cases skip, as the file is inside the VM.

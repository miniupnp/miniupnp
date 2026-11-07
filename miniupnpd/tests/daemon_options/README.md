# daemon_options: miniupnpd under different configurations

The protocol suites (`pcp_wire`, `pcp_e2e`) test the daemon in one fixed configuration, with a few
profiles. This suite tests **changing** options: the same PCP, NAT-PMP or UPnP request sent to
daemons that run with different `miniupnpd.conf` lines.

| File | What it is |
|---|---|
| `daemon-options-cases.yaml` | the cases; each declares its daemon configuration (`config:`) |
| `run_daemon_options_cases.py` | the runner: one run of one configuration, side and address family |
| `run-docker.sh` | the Linux (Docker) driver: a fresh daemon per configuration |
| `status.md` | the results (`lib_test.write_status`, a `linux` column) |

## Running

```sh
miniupnpd/tests/daemon_options/run-docker.sh                 # every case
miniupnpd/tests/daemon_options/run-docker.sh --case NAME     # some cases (repeatable)
python3 miniupnpd/tests/daemon_options/run_daemon_options_cases.py --self-test
```

The driver runs `common/run_self_tests.sh` first (`PCP_TEST_SELF_TEST=0` skips it), compiles the
daemon in the tools image (`e2e_tools_image`, with OpenSSL; `e2e_build_daemon`) and writes:

- `status.md` beside the runner;
- the raw results behind it in `<repo>/.tmp/tests/daemon_options/status-data.json`;
- each daemon's log and configuration file in `<repo>/.tmp/daemon-options/<run>/`.

`DAEMON_OPTIONS_KEEP=1` keeps the containers and networks. The fixture is `common/compose.yaml` without
its traffic agents, on a slot of `e2e_address_plan` (`common/e2e_lib.sh`): `PCP_TEST_SLOT=N`, by default
the first free one, so it runs beside the other suites.

## How a run works

1. `run_daemon_options_cases.py --list-runs` prints the runs: `SIDE FAMILY CONFIG-LINE...`, one
   line per configuration, side and family that has cases, the configurations in corpus order.
2. For each configuration, the driver starts a fresh router container on a LAN and a WAN bridge
   (`PCP_TEST_REAL_WAN=1`), with the configuration lines in `PCP_TEST_EXTRA_CONF` and
   `PCP_TEST_CONF_REPLACE=1`. It is ready when its log says it listens (NAT-PMP/PCP or HTTP).
3. For each side and family of that configuration, it runs the runner in a container: from the
   LAN client (`.2` of the slot's LAN) to the router's LAN address, or from a host on the
   WAN link (`.2` of its WAN) to the router's WAN address. The runner selects the
   cases whose `config:` is exactly the `--config` lines and whose `from:` is `--side`, runs them
   and merges their results into `status.md`; the cases of other runs keep their results.

## Cases

A case is a case of the `pcp_wire` corpus (the same expander, request and expect kinds, and step
engine: `run_case`), plus:

- `config: [key=value, ...]`: the daemon's configuration lines, in order. `--self-test` checks
  each key against the option table of `miniupnpd/options.c`. Each line replaces the fixture's
  default line of the same option (see below). `allow` / `deny` lines may be listed too; they
  replace all the default ones, and `--list-runs` and `--config` carry them with `+` for blanks.
- `from: lan | wan` (default `lan`).
- request kind `upnp`: one SOAP `AddPortMapping` or `DeletePortMapping` to port 5000 (IPv4 only),
  with `expect: {kind: upnp, result: [...]}`, of `SUCCESS`, `UPNP_<errorCode>`, `NO_LISTENER`
  (the TCP connection is refused) or `NO_REPLY` (closed or timed out without an HTTP response).
  Its config has to set `http_port=5000`, also when UPnP is off. A mapping it makes is deleted.
  `internal_client: neighbour` asks for the next address on the client's LAN instead of its own.

- request kind `option_steps`: a list of steps (`natpmp_address`, `natpmp_map`, `pcp_map`,
  `upnp_add`, `upnp_get`, `http_get`, `soap`, `router`, `sleep`, `ssdp`), with `expect: {kind: steps}`.
  A `router` step asks the driver for `ruleset`, `log`, `cat:PATH`, `restart`, `firewall-flush` or
  `wan-probe:PORT`. `firewall-flush` removes the rules behind the daemon's back, as a reload does.
  With `expect: {kind: daemon_exits}` the daemon must refuse to start; a `router` log step checks why.
- `@WAN4@`, `@LAN4@`, `@LAN6@` in a config line are the addresses of the slot; `key=@OFF@` leaves the
  default line of that option out.

The fixture adds a STUN server on the WAN (`stun_server.py`), a second LAN host, and a build with
`--igd2 --vendorcfg --https`.

A case states the correct behaviour. A broken feature is a FAIL, kept for a later fix in a
separate branch; this branch does not change the daemon. `known_failure:` (an XFAIL) is only for
a feature that is not implemented.

## Configuration lines and the fixture's defaults

`common/docker/entrypoint.sh` writes a default `miniupnpd.conf` (`enable_upnp=no`,
`enable_pcp_pmp=yes`, `secure_mode=yes`, ...) and appends `PCP_TEST_EXTRA_CONF`. An appended line
does **not** override an earlier one for miniupnpd's flags (checked 2026-11-03, `miniupnpd.c`):

- `enable_upnp` only clears the flag (anything but `yes`): `enable_upnp=yes` after
  `enable_upnp=no` leaves UPnP off;
- `enable_natpmp` / `enable_pcp_pmp` only set it (`yes` or a number): `enable_pcp_pmp=no` after
  `enable_pcp_pmp=yes` leaves PCP and NAT-PMP on;
- `secure_mode` only clears it: `secure_mode=yes` after `secure_mode=no` leaves it off.

So the driver sets `PCP_TEST_CONF_REPLACE=1`: each `key=value` line of `PCP_TEST_EXTRA_CONF` then
replaces the default line of the same option, where `enable_natpmp` / `enable_pcp_pmp` and
`port` / `http_port` count as one option. Without it (the default) the entrypoint appends, as
before.

## Coverage

`run_daemon_options_cases.py --self-test` prints which options of `options.c` the cases vary.

- `enable_pcp_pmp`, `enable_natpmp`, `enable_upnp` on and off: a protocol that is off gives no
  reply, the others still answer. `enable_natpmp` and `enable_pcp_pmp` are one option
  (`options.c`: both NAT-PMP and PCP); there is no switch for one of the two alone.
- WAN side: PCP and NAT-PMP to `router-wan:5351` and UPnP to `router-wan:5000` get no reply.
- `max_lifetime`, `min_lifetime`: the exact PCP lifetime granted under each value, the startup
  limits 120 and 86400, and NAT-PMP not being capped.
- `allow` / `deny` lines by port, by client address and without a match, for PCP, NAT-PMP and
  UPnP.
- `secure_mode` on and off for a UPnP mapping to another LAN address.
- `pcp_allow_thirdparty` on and off, with `secure_mode` both ways, and from the WAN side.
  `thirdparty-traffic-reaches-neighbour` maps for the second LAN host and fetches from it over the
  WAN (`wan-probe`).

Not covered yet:

- FreeBSD runs need a tree with the `feat/pcp-peer-filter` daemon. `run-freebsd.sh` runs the suite
  inside a throwaway VM (`freebsd/run-suite.sh`, epair and vnet jails) and copies the results out.
- Forwarding-only / no-NAT mode: miniupnpd has no such option (`options.c`).

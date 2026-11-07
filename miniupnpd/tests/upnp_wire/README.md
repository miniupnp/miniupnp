# upnp_wire: the UPnP IGD protocol suite

The cases in `upnp-wire-cases.yaml` check miniupnpd's UPnP IGD side as a LAN control point sees it:
SSDP discovery, the HTTP server, the device and service descriptions, SOAP control of WANIPConnection,
WANCommonInterfaceConfig, Layer3Forwarding and WANIPv6FirewallControl, GENA eventing, and the UPnP
lease file. Each case cites the section of a spec it checks (`ref:`; the documents are listed with their
hashes in [specs/README.md](specs/README.md)). A case is named `<doc>-<section>-<level>-<what>` from
its `ref:` (`uda11-1.3.3-must-missing-mx`), and the cases of a section are in spec order. The level is the
strength of the requirement on the device: `must`, `should`, `may`, or `impl` when the spec requires
nothing and the case checks miniupnpd's own behaviour. A result that differs from the spec is one of three
things:

- a spec gap: a FAIL, with a `# spec gap:` comment in the corpus naming the cause;
- a feature miniupnpd does not implement: an XFAIL, with a `known_failure` note;
- a check miniupnpd only compiles with `UPNP_STRICT` (configure `--strict`), a SKIP (`requires: [strict]`)
  on `igd1` and `igd2`; the `igd1-strict` and `igd2-strict` runs build with it and run those cases.

## Running

    sh miniupnpd/tests/upnp_wire/run-docker.sh            # every build: igd1, igd2, igd1-strict, igd2-strict
    sh miniupnpd/tests/upnp_wire/run-docker.sh igd2 --case uda11-4.1.3-must-renew

`run-docker.sh` compiles one daemon per build in the shared tools image (`e2e_build_daemon`,
`.tmp/tests/daemon`): `igd1` is the default build, `igd2` adds `--igd2`, and both have `--ipv6 --leasefile`. For each
build it starts the daemon in UPnP mode (`PCP_TEST_ENABLE_UPNP=yes`: `enable_upnp=yes`, `http_port=5000`, the uuid
of the corpus, `notify_interval=30`) on a LAN network (of a fixture slot: `UPNP_WIRE_SLOT`, by default the first free one), and runs
`run_upnp_wire_cases.py` in a LAN client container once per address family. The results are merged into
[status.md](status.md), one column per platform and build (`linux-igd1`, `linux-igd2`). The raw results,
the runner and daemon logs and the daemon's state directory of each run go to `.tmp/tests/upnp_wire/` in
the repository (`status-data.json`, `runs/<time>/<build>/`).

The runner runs once per build and family in a LAN container, with `e2e_run_family` of
`common/e2e_lib.sh`, and the driver merges its rows into the report with `e2e_write_report`. A case that
restarts the daemon (`kind: restart`, or `ssdp-listen` with `restart: true`) asks the driver for it
through `router_call restart` (`--router-call-dir`); the driver's `restart_daemon` restarts the router
container. The runner reads the daemon's `lease_file` from the state directory the driver shares (`--lease-file`).

The runner can also be pointed at another daemon: `--router`, `--client-address`, `--family`, `--build`,
`--interface` (the IPv6 multicast scope). Without `--router-call-dir` / `--lease-file` the cases that need
them are skipped.

## The corpus

A case has `name`, `ref`, `description`, optionally `builds` and `families` (default: all), `requires`
(`restart`, `lease-file`, `strict`), `known_failure` (the case is an XFAIL when it fails: the daemon
does not implement the feature), `steps` and `cleanup`. The step kinds and the rules of `expect` are described at
the top of the corpus; the code is the UPnP block of `common/lib_test.py`. A value `{igd1: .., igd2: ..}`
or `{ipv4: .., ipv6: ..}` is chosen for the build and family of the run.

`python3 run_upnp_wire_cases.py --self-test` checks the corpus (unique names, every ref cites a spec of the
corpus's `specs` list and a section, known builds, families and step kinds) and the status report; it is
part of `common/run_self_tests.sh`.

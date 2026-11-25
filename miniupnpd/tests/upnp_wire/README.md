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
  on `igd2`; the `igd2-strict` run builds with it and runs those cases.

A `-strict` run (`igd2-strict`, `igd1-strict`) has only the `requires: [strict]` cases and the cases marked `strict_path: true`, whose
requests take a path `UPNP_STRICT` changes. Every other case gives the same result in both builds, so it runs
on `igd2` (or `igd1`) only, and the `-strict` columns list only the strict-build cases.

## Running

    sh miniupnpd/tests/upnp_wire/run-docker.sh            # both builds: igd2, then igd2-strict
    sh miniupnpd/tests/upnp_wire/run-docker.sh --base --case uda11-4.1.3-must-renew   # igd2 only (--strict: igd2-strict only)
    sh miniupnpd/tests/upnp_wire/run-docker.sh --igd1     # the IGDv1 builds instead: igd1, then igd1-strict

The IGDv1 builds (`igd1`, `igd1-strict`) run only with `--igd1`, on Docker.

`run-docker.sh` compiles one daemon per build in the shared tools image (`e2e_build_daemon`,
`.tmp/tests/daemon`): `igd1` is the default build, `igd2` adds `--igd2`, and both have `--ipv6 --leasefile`. For each
build it starts the daemon in UPnP mode (`PCP_TEST_ENABLE_UPNP=yes`: `enable_upnp=yes`, `http_port=5000`, the uuid
of the corpus, `notify_interval=10`) on a LAN network (of a fixture slot: `UPNP_WIRE_SLOT`, by default the first free one), and runs
`run_upnp_wire_cases.py` in a LAN client container once per address family. The results are merged into
[status.md](status.md), one column per platform and build (`linux-igd2`, `linux-igd2-strict`). The raw results,
the runner and daemon logs and the daemon's state directory of each run go to `.tmp/tests/upnp_wire/` in
the repository (`status-data.json`, `runs/<time>/<build>/`).

The runner runs once per build and family in a LAN container, with `e2e_run_families` of
`common/e2e_lib.sh`, and the driver merges its rows into the report with `e2e_write_report`. A case that
restarts the daemon (`kind: restart`, or `ssdp-listen` with `restart: true`; `requires: [restart]`) asks
the driver for it through `router_call restart` (`--router-call-dir`); the driver's `restart_daemon`
restarts the router container. A restart would break the case the other family runs at that moment, so
these cases run first, one family after the other (`--restart-cases only`); then the other cases of IPv4
and IPv6 run at once, in two containers (`--restart-cases skip`). The runner reads the daemon's `lease_file` from the state directory the driver shares (`--lease-file`).

The runner can also be pointed at another daemon: `--router`, `--client-address`, `--family`, `--build`,
`--interface` (the IPv6 multicast scope). Without `--router-call-dir` / `--lease-file` the cases that need
them are skipped.

## On FreeBSD

    sh miniupnpd/tests/upnp_wire/run-freebsd.sh [--base|--strict] [--slot N] [--case NAME]...

`run-freebsd.sh` runs the suite on the FreeBSD pf router of `pcp_e2e/run-freebsd.sh` (its QEMU VM, slots,
`--reuse`, `up`, `down`) in the same two phases as `run-docker.sh`, and fills the `freebsd-igd2` and
`freebsd-igd2-strict` columns of [status.md](status.md). That driver sources `freebsd-hooks.sh`
(`PCP_E2E_SUITE_HOOKS`), whose functions replace its PCP ones: this suite's settings, `enter_phase`,
which builds the daemon again with `--strict` in the VM and starts it from a clean state for the
igd2-strict phase, `restart_daemon` in the VM, and `run_families`, which runs `e2e_run_families` as the
Docker driver does. The cases of the lease file SKIP, as the file is in the VM.

## On OpenBSD

    sh miniupnpd/tests/upnp_wire/run-openbsd.sh [--base|--strict] [--slot N] [--case NAME]...

`run-openbsd.sh` is `run-freebsd.sh` with the OpenBSD pf router of `pcp_e2e/run-openbsd.sh` (the same
`pf-router.sh`, slots and options; `PCP_TEST_OPENBSD_VERSION` picks the release, default 8.0). It fills
the `openbsd-igd2` and `openbsd-igd2-strict` columns of [status.md](status.md).

## The corpus

A case has `name`, `ref`, `description`, optionally `builds` and `families` (default: all), `requires`
(`restart`, `lease-file`, `strict`), `strict_path` (the case also runs on the `-strict` builds), `known_failure` (the case is an XFAIL when it fails: the daemon
does not implement the feature), `steps` and `cleanup`. The step kinds and the rules of `expect` are described at
the top of the corpus; the code is the UPnP block of `common/lib_test.py`. A value `{igd1: .., igd2: ..}`
or `{ipv4: .., ipv6: ..}` is chosen for the build and family of the run.

`python3 run_upnp_wire_cases.py --self-test` checks the corpus (unique names, every ref cites a spec of the
corpus's `specs` list and a section, known builds, families and step kinds) and the status report; it is
part of `common/run_self_tests.sh`.

## Master against a pull request

The `upnp-wire-linux` job of `regression-testing.yml` runs `../common/tools/compare_daemon_branches.py
--suite upnp-wire`: both daemons, every build, with the pull request's harness. [`compare.py`](compare.py)
tells it how to run this suite. The corpus has FAILs (spec gaps), so only a case that passed with master's
daemon and does not now fails the job.

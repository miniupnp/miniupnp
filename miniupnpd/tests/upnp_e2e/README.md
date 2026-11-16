# upnp_e2e: the UPnP IGD end-to-end suite

The cases in `upnp-e2e-cases.yaml` make port mappings and IPv6 pinholes with SOAP and check them with real
traffic from WAN peers through the router: the lifecycle of UDP and TCP mappings, port translation, lease
expiry, NewRemoteHost and NewEnabled, AddAnyPortMapping and DeletePortMappingRange (IGDv2), pinholes with a
wildcard and a specific RemoteHost, UpdatePinhole, DeletePinhole and pinhole expiry (IGDv2, IPv6), UPnP and
PCP mappings of one daemon, a mapping across a daemon restart, and what a WAN peer reaches of
the UPnP side (SSDP, HTTP, SOAP on the router's WAN address).

The protocol details (faults, descriptions, eventing) are the subject of [../upnp_wire](../upnp_wire);
the UPnP section of [../pcp_e2e](../pcp_e2e) stays as the check of the firewall rule code UPnP shares with
PCP.

## Running

    sh miniupnpd/tests/upnp_e2e/run-docker.sh
    UPNP_E2E_BUILDS=igd2 sh miniupnpd/tests/upnp_e2e/run-docker.sh --case upnp-e2e-pinhole-remote-host

The topology is that of `pcp_e2e/run-docker.sh` (`common/compose.yaml`, on a fixture slot: `UPNP_E2E_SLOT`,
by default the first free one, so it runs beside the other suites): a LAN with the runner, the router
(miniupnpd in UPnP mode, `PCP_TEST_ENABLE_UPNP=yes`, with PCP on), and a WAN with three traffic agents
(allowed-peer, denied-peer, third-peer). The driver compiles the `igd1` and `igd2` daemons in the
shared tools image (`e2e_build_daemon`) and runs each case of each build and address family in its own runner container.
The results go into [status.md](status.md), one column per platform and build (`linux-igd1`,
`linux-igd2`); the raw results and the logs (runner, daemon, ruleset and lease file after each request)
into `.tmp/tests/upnp_e2e/` of the repository.

## On FreeBSD

    sh miniupnpd/tests/upnp_e2e/run-freebsd.sh [--slot N] [--case NAME]...

`run-freebsd.sh` runs the suite on the FreeBSD pf router of `pcp_e2e/run-freebsd.sh` (its QEMU VM, slots,
`--reuse`, `up`, `down`), with a daemon built with `--igd2`, and fills the `freebsd-igd2` column of
[status.md](status.md). That driver sources `freebsd-hooks.sh` (`PCP_E2E_SUITE_HOOKS`), whose functions
replace its PCP ones; it defines only the settings of this suite and `restart_daemon`, the restart of
the daemon in the VM.

The request and traffic keys of the corpus are those of the pcp_e2e corpus (`lib_test.CaseRun`), with the
UPnP request kinds listed at the top of the corpus. A case with `requires: [restart]` asks the driver
for a restart of the daemon after its first request (`router_call restart`, answered by the driver's
`restart_daemon`), as a `kind: restart` step of upnp_wire does. An
`exposure:` case sends a payload from a WAN peer to the router's WAN address and passes when the traffic
agent's probe ends with an error (no answer, no connection).

`python3 run_upnp_e2e_cases.py --self-test` checks the corpus of each build with `validate_corpus` and
the status report; it is part of `common/run_self_tests.sh`.

The driver runs the cases with the functions of `common/e2e_lib.sh` (`e2e_case_rows`, `e2e_start_runner`,
`e2e_record_result`, `e2e_write_report`), with `E2E_RUNNER` set to this suite's runner and
`E2E_RUNNER_ARGS` to its build.

## Master against a pull request

The `upnp-e2e-linux` job of `regression-testing.yml` runs `../common/tools/compare_daemon_branches.py
--suite upnp-e2e`: both daemons, every build, with the pull request's harness. [`compare.py`](compare.py)
tells it how to run this suite. The corpus has FAILs (spec gaps), so only a case that passed with master's
daemon and does not now fails the job.

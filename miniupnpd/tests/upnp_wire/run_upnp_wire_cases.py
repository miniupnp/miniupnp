#!/usr/bin/env python3
"""The UPnP IGD protocol suite: SSDP, HTTP, description, SOAP and GENA cases (upnp-wire-cases.yaml) run
from a LAN client against a running miniupnpd (enable_upnp=yes, http_port=5000, the corpus's uuid).

Each case cites the spec section it checks (ref:) and runs on the builds (igd1, igd2) and address
families it lists. run-docker.sh builds the daemon, runs this file in a LAN container for each build and
family, and merges the results into status.md (--write-status)."""

import argparse
import os
import re
import socket
import subprocess
import sys

# python3 -I leaves the directory of the script off sys.path: add common/ beside it
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "common"))

from lib_test import (  # noqa: E402
    LeaseSource,
    UPNP_HTTP_PORT,
    add_corpus_arguments,
    add_status_arguments,
    case_builds,
    case_families,
    check_report_columns,
    fill_placeholders,
    flatten_cases,
    host_literal,
    load_yaml,
    print_build_runs,
    resolve_variant,
    run_cases,
    run_driver_suite,
    run_protocol_sequence,
    select_build_cases,
    status_sections,
    write_driver_status,
    write_results_tsv,
)

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "upnp-wire-cases.yaml")
SUITE, TITLE = "upnp_wire", "UPnP wire"


# The LAN of a run without a fixture; the corpus names its addresses with @LAN4@, @LAN4_RE@ and @LAN6@
DEFAULT_LAN4, DEFAULT_LAN6 = "172.28.61", "fd42:61::"


def read_corpus(path=CORPUS, lan4=DEFAULT_LAN4, lan6=DEFAULT_LAN6):
    return fill_placeholders(load_yaml(path), {"@LAN4_RE@": re.escape(lan4), "@LAN4@": lan4, "@LAN6@": lan6})


def load(args):
    args.platform = args.platform or f"linux-{args.build}{'-strict' if args.strict else ''}"
    return read_corpus(args.cases, args.lan4, args.lan6)


def case_refs(case, builds):
    """The refs of a case on each of its builds (a ref may be {igd1: .., igd2: ..})."""
    return sorted({resolve_variant(case.get("ref", ""), tuple(builds), build) for build in case_builds(case, builds)})


def report_sections(corpus):
    """The sections of the report: every case is UPnP, and its description cites its refs."""
    builds = set(corpus["builds"])
    return status_sections(corpus, lambda _case: "upnp",
                           lambda case: f"{case.get('description', '')} ({'; '.join(case_refs(case, builds))})")


CASE_NAME = re.compile(r"[a-z0-9]+-\d+(\.\d+)*-(must|should|may|impl)-[a-z0-9-]+")


def validate(corpus):
    """The corpus shape: unique names, a ref whose spec id is in `specs`, valid builds, families and steps."""
    specs = set(corpus.get("specs", []))
    builds = set(corpus.get("builds", {}))
    cases = flatten_cases(corpus)
    names = [case.get("name") for case in cases]
    assert cases and all(names) and len(names) == len(set(names)), "case names must be present and unique"
    for case in cases:
        where = case["name"]
        assert CASE_NAME.fullmatch(where), f"{where}: not <doc>-<section>-<level>-<what>"
        assert set(case_builds(case, builds)) <= builds, f"{where}: unknown build"
        for ref in case_refs(case, builds):
            assert isinstance(ref, str) and ref.split(" ", 1)[0] in specs, (
                f"{where}: ref {ref!r} cites no spec of the corpus's specs list")
            assert " §" in ref, f"{where}: ref {ref!r} names no section"
        case_families(case)
        assert case.get("steps"), f"{where}: no steps"
        for step in case["steps"] + case.get("cleanup", []):
            assert step.get("kind") in ("ssdp", "ssdp-listen", "http", "soap", "subscribe", "notify-wait",
                                        "restart", "upnp-lease", "wait"), f"{where}: unknown step kind {step.get('kind')}"
        assert set(case.get("requires", [])) <= {"restart", "lease-file", "strict", "second-client"}, f"{where}: unknown requires"
    return len(cases)


def build_variables(corpus, args):
    build = corpus["builds"][args.build]
    uuid = corpus["uuid"]
    variables = {"router": args.router, "client": args.client_address, "family": args.family, "build": args.build,
                 "http_port": UPNP_HTTP_PORT, "uuid": uuid, "udn": f"uuid:{uuid}", "services": build["services"],
                 "router_call_dir": args.router_call_dir,
                 "location": f"http://{host_literal(args.router)}:{UPNP_HTTP_PORT}/rootDesc.xml"}
    variables.update(build.get("variables", {}))
    if args.second_client:
        variables["client2"] = args.second_client
    if args.interface:
        variables["ifindex"] = socket.if_nametoindex(args.interface)
    return variables


def run_case(case, variables, lease):
    resources = []
    try:
        run_protocol_sequence(None, None, {"name": case["name"], "variables": dict(variables, _resources=resources),
                                           "request": {"steps": case["steps"], "cleanup": case.get("cleanup", [])}},
                              lease=lease)
    finally:
        for resource in resources:
            resource.close()


def selected_cases(corpus, args):
    """The cases of this build and family (resolved for them), in corpus order."""
    builds = tuple(corpus["builds"])

    def resolve(case):
        resolved = resolve_variant(resolve_variant(case, ("ipv4", "ipv6"), args.family), builds, args.build)
        return dict(resolved, protocol="upnp")
    return select_build_cases(corpus, args, resolve)


def missing_requirement(args):
    def reason(case, _outcomes):
        if "second-client" in case.get("requires", []) and not args.second_client:
            return "requires a second LAN address (--second-client)"
        if "strict" in case.get("requires", []) and not args.strict:
            return "requires a build with UPNP_STRICT (configure --strict)"
        if "restart" in case.get("requires", []) and not args.router_call_dir:
            return "requires the driver's daemon restart (--router-call-dir)"
        if "lease-file" in case.get("requires", []) and not args.lease_file:
            return "requires the daemon's lease file (--lease-file)"
        return None
    return reason


def write_report(corpus, results_path, args):
    write_driver_status(results_path, args, TITLE, SUITE, report_sections(corpus))


def self_test(corpus):
    count = validate(corpus)
    print_build_runs(corpus, count)
    bad = {"specs": ["UDA-1.1"], "builds": {"igd1": {}}, "sections": [{"name": "S", "cases": [
        {"name": "igd9-1-must-x", "ref": "IGD9 §1", "steps": [{"kind": "http"}]}]}]}
    try:
        validate(bad)
        raise AssertionError("a ref to a spec outside `specs` must be rejected")
    except AssertionError as error:
        assert "cites no spec" in str(error), error
    bad["sections"][0]["cases"][0]["name"] = "x"
    try:
        validate(bad)
        raise AssertionError("a case name without doc, section and level must be rejected")
    except AssertionError as error:
        assert "not <doc>" in str(error), error
    check_report_columns(lambda path, args: write_report(corpus, path, args), flatten_cases(corpus)[0], "upnp",
                         ("linux-igd1", "linux-igd2"))
    moved = str(read_corpus(lan4="172.28.9", lan6="2001:db8:1:9::"))
    assert "@LAN" not in moved and DEFAULT_LAN4 not in moved and DEFAULT_LAN6 not in moved, "a corpus address is not filled"
    assert re.escape("172.28.9").replace("\\", "\\\\") in moved, "the addresses in regular expressions are not filled"
    print("PASS the addresses of a fixture slot fill the corpus")


def run_selected(corpus, args, cases):
    variables = build_variables(corpus, args)
    lease = LeaseSource(files=args.lease_file)
    if args.second_client:
        prefix = "/64" if ":" in args.second_client else "/24"
        subprocess.run(["ip", "address", "add", args.second_client + prefix, "dev", args.interface,
                        # deprecated: only a step that binds it uses it, not the default source of the runner
                        *(["nodad", "preferred_lft", "0"] if ":" in args.second_client else [])], check=True)
    outcomes = run_cases(cases, lambda case: run_case(case, variables, lease), skip=missing_requirement(args),
                         failures=(Exception,), timestamps=True)
    if args.results:
        write_results_tsv(args.results, args.family, cases, outcomes)
    return outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_corpus_arguments(parser, CORPUS, "print the cases of --build and --family")
    parser.add_argument("--router", default="172.28.61.1", help="the daemon's LAN address of --family")
    parser.add_argument("--client-address", default="172.28.61.2", help="this client's LAN address of --family")
    parser.add_argument("--second-client", help="a second LAN address of --interface, added by this runner")
    parser.add_argument("--interface", help="the LAN interface (the IPv6 multicast scope)")
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    parser.add_argument("--build", default="igd1", help="the daemon build: igd1 or igd2")
    parser.add_argument("--strict", action="store_true", help="the daemon was built with configure --strict")
    parser.add_argument("--lan4", default=DEFAULT_LAN4, help="the first three octets of the LAN of this fixture")
    parser.add_argument("--lan6", default=DEFAULT_LAN6, help='the LAN /64 of this fixture, ending in "::"')
    parser.add_argument("--case", action="append")
    parser.add_argument("--router-call-dir", help="the directory the driver watches, for a daemon restart")
    parser.add_argument("--lease-file", help="the daemon's lease_file, shared by the driver")
    parser.add_argument("--results", help="write the outcomes of the run to this file, for --write-status")
    add_status_arguments(parser, os.path.dirname(os.path.abspath(__file__)), SUITE, platform=None)
    return run_driver_suite(parser, load, write_report, self_test, selected_cases, validate, run_selected,
                            empty_case_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())

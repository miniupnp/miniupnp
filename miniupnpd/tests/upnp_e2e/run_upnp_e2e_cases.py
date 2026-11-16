#!/usr/bin/env python3
"""The UPnP IGD end-to-end suite: port mappings and IPv6 pinholes made with SOAP (upnp-e2e-cases.yaml),
checked with real traffic from the WAN peers of the pcp_e2e topology, the UPnP / PCP interplay, a mapping
across a daemon restart, and what a WAN peer reaches of the daemon's UPnP side.

run-docker.sh runs this file once per case, build (igd1, igd2) and address family in a LAN container,
then merges the results into status.md (--write-status)."""

import argparse
import os
import sys

# python3 -I leaves the directory of the script off sys.path: add common/ beside it
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "common"))

import pcp_corpus_expander  # noqa: E402
from lib_test import (  # noqa: E402
    CaseRun,
    add_e2e_arguments,
    add_corpus_arguments,
    add_status_arguments,
    case_builds,
    case_for_family,
    case_protocol,
    check_report_columns,
    check_wan_exposure,
    e2e_socket,
    flatten_cases,
    load_yaml,
    msearch_message,
    prepare_e2e_run,
    print_build_runs,
    resolve_family,
    resolve_variant,
    run_cases,
    run_driver_suite,
    select_build_cases,
    status_sections,
    validate_corpus,
    write_driver_status,
)

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "upnp-e2e-cases.yaml")
SUITE, TITLE = "upnp_e2e", "UPnP end-to-end"


def load(args):
    args.platform = args.platform or f"linux-{args.build}"
    return pcp_corpus_expander.expand_e2e_corpus(load_yaml(args.cases))


def protocol_of(case):
    return "upnp" if "exposure" in case else case_protocol(case)


def for_build(case, corpus, build):
    """The case on a build: its {igd1, igd2} values chosen, its UPnP port mapping requests sent to the
    build's WANIPConnection version."""
    case = resolve_variant(case, tuple(corpus["builds"]), build)
    service = corpus["builds"][build]["wanipc"]
    for request in case.get("requests", [case["request"]] if "request" in case else []):
        if request.get("protocol_family") == "UPnP" and "Pinhole" not in request["action"]:
            request.setdefault("service", service)
    return case


def validate(corpus):
    """Every build's resolution of the corpus passes validate_corpus (the exposure cases are checked here)."""
    builds = set(corpus["builds"])
    for build in sorted(builds):
        sections = []
        for section in corpus["sections"]:
            cases = []
            for case in section["cases"]:
                assert set(case_builds(case, builds)) <= builds, f"{case['name']}: unknown build"
                if build not in case_builds(case, builds):
                    continue
                if "exposure" in case:
                    for item in case["exposure"]:
                        assert item.get("protocol") in ("tcp", "udp") and isinstance(item.get("port"), int), (
                            f"{case['name']}: invalid exposure check")
                    continue
                cases.append(for_build(case, corpus, build))
            if cases:
                sections.append(dict(section, cases=cases))
        validate_corpus({"sections": sections})
    return len(flatten_cases(corpus))


def selected_cases(corpus, args):
    def resolve(case):
        by_family = (resolve_family(case, args.family) if "exposure" in case
                     else case_for_family(case, args.family))
        return dict(for_build(by_family, corpus, args.build), protocol=protocol_of(case))
    return select_build_cases(corpus, args, resolve)


def run_exposure(case, args, agents):
    for item in case["exposure"]:
        payload = item.get("payload", "")
        if item.get("payload") == "msearch":
            payload = msearch_message("ssdp:all", family=args.family).decode()
        host = args.peer_addresses.get(item.get("host", "router-wan"), item.get("host"))
        check_wan_exposure(agents[item.get("from", "allowed-peer")], item["protocol"], host, item["port"], payload)


def write_report(corpus, results_path, args):
    write_driver_status(results_path, args, TITLE, SUITE, status_sections(corpus, protocol_of))


def self_test(corpus):
    count = validate(corpus)
    print_build_runs(corpus, count)
    first = flatten_cases(corpus)[0]
    check_report_columns(lambda path, args: write_report(corpus, path, args), first, protocol_of(first),
                         ("linux-igd1", "linux-igd2"))


def run_selected(_corpus, args, cases):
    agents = prepare_e2e_run(args)
    with e2e_socket(args) as pcp_sock:

        def run(case):
            if "exposure" in case:
                run_exposure(case, args, agents)
            else:
                CaseRun(case, args, agents, pcp_sock).run()
        return run_cases(cases, run, failures=(Exception,), timestamps=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_corpus_arguments(parser, CORPUS, "print section and case of the cases of --build and --family")
    add_e2e_arguments(parser)
    parser.add_argument("--build", default="igd1")
    add_status_arguments(parser, os.path.dirname(os.path.abspath(__file__)), SUITE, platform=None)
    return run_driver_suite(parser, load, write_report, self_test, selected_cases, validate, run_selected)


if __name__ == "__main__":
    raise SystemExit(main())

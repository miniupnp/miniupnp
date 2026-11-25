#!/usr/bin/env python3
"""Execute YAML PCP mapping scenarios and verify real forwarding behavior."""

import argparse
import contextlib
import os
import subprocess
import sys
import tempfile

# python3 -I leaves the directory of the script off sys.path: add common/ beside it
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "common"))

import pcp_corpus_expander  # noqa: E402
from lib_test import (  # noqa: E402
    CaseRun,
    CorpusError,
    add_corpus_arguments,
    add_e2e_arguments,
    add_status_arguments,
    case_families,
    case_for_family,
    case_protocol,
    case_traffic,
    check_report_columns,
    e2e_socket,
    flatten_cases,
    load_yaml,
    prepare_e2e_run,
    run_driver_suite,
    run_e2e_cases,
    select_family_cases,
    status_sections,
    validate_corpus,
    write_driver_status,
)

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcp-e2e-cases.yaml")
SUITE, TITLE = "pcp_e2e", "PCP end-to-end"


def write_report(corpus, results_path, args):
    write_driver_status(results_path, args, TITLE, SUITE, status_sections(corpus))


def check_sections_kept(corpus):
    """The sections a run did not run (UPnP) keep their results, and the raw data stays out of the report's
    directory."""
    protocols = {case["name"]: case_protocol(case) for case in flatten_cases(corpus)}
    assert {"pcp", "natpmp", "upnp"} <= set(protocols.values()), protocols.values()
    assert [section["title"] for section in status_sections(corpus)] == [section["name"] for section in corpus["sections"]]
    first = {section["name"]: section["cases"][0]["name"] for section in corpus["sections"]}
    with tempfile.TemporaryDirectory() as directory:
        results = os.path.join(directory, "results.tsv")
        args = argparse.Namespace(status_file=os.path.join(directory, "status.md"), run_info=[],
                                  status_data_file=os.path.join(directory, "x", "status-data.json"))
        for platform, rows in (("freebsd", (("UPnP", "FAIL"),)), ("linux", (("PMP", "PASS"),))):
            with open(results, "w", encoding="utf-8") as handle:
                for section, status in rows:
                    handle.write("\t".join(("ipv4", section, first[section], status, "boom | x", "")) + "\n")
            write_report(corpus, results, argparse.Namespace(**vars(args), platform=platform))
        with open(args.status_file, encoding="utf-8") as handle:
            text = handle.read()
        assert f"| {first['UPnP']} | upnp | ipv4 | — | FAIL | freebsd: boom \\| x |" in text, text
        assert f"| {first['PMP']} | natpmp | ipv4 | PASS | — |" in text, text
        assert not os.path.exists(os.path.join(directory, "status-data.json"))
    print("PASS status report (a run keeps the sections it did not run)")


def self_test(corpus):
    count = validate_corpus(corpus)
    family_runs = sum(len(case_families(case)) for case in flatten_cases(corpus))
    print(f"PASS YAML sections ({count} logical cases, {family_runs} family runs)")
    first = flatten_cases(corpus)[0]
    check_report_columns(lambda path, args: write_report(corpus, path, args), first, case_protocol(first))
    check_sections_kept(corpus)


def load(args):
    return pcp_corpus_expander.expand_e2e_corpus(load_yaml(args.cases))


def selected_cases(corpus, args):
    if not args.enable_upnp:
        corpus["sections"] = [section for section in corpus["sections"] if section.get("requires") != "upnp"]
    return select_family_cases(corpus, args,
                               lambda case: dict(case_for_family(case, args.family), protocol=case_protocol(case)))


def nat66_flag(corpus):
    nat66 = {section["name"]: section.get("nat66", False) for section in corpus["sections"]}
    return lambda case: nat66[case["section"]]


def nat66_options(args, cases, nat66):
    """The options of the IPv6 cases of a NAT66 section: the client is the LAN ULA (--nat66-client, which
    the runner adds to --interface), the router its ULA (--nat66-router). None when no such case runs."""
    if args.family != "ipv6" or not args.nat66_client or not any(nat66(case) for case in cases):
        return None
    subprocess.run(["ip", "-6", "address", "replace", args.nat66_client + "/64", "dev", args.interface, "nodad"],
                   check=True)
    return argparse.Namespace(**dict(vars(args), client_address=args.nat66_client, router=args.nat66_router))


def run_selected(corpus, args, cases):
    agents = prepare_e2e_run(args)
    needed = {traffic["from"] for case in cases for traffic in case_traffic(case)}
    if needed - agents.keys():
        raise CorpusError("missing agents for: " + ", ".join(sorted(needed - agents.keys())))
    nat66 = nat66_flag(corpus)
    nat66_args = nat66_options(args, cases, nat66)
    with e2e_socket(args) as pcp_sock, \
            (e2e_socket(nat66_args) if nat66_args else contextlib.nullcontext()) as nat66_sock:

        def run(case):
            if nat66_args and nat66(case):
                CaseRun(case, nat66_args, agents, nat66_sock).run()
            else:
                CaseRun(case, args, agents, pcp_sock).run()
        return run_e2e_cases(args, cases, run, nat66)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_corpus_arguments(parser, CORPUS, "print section, case and nat66 flag of every case that runs on --family, then exit",
                         "validate YAML cases and PCP/NAT-PMP encoding without a daemon")
    add_e2e_arguments(parser)
    parser.add_argument("--enable-upnp", action="store_true",
                        help="also run sections marked requires: upnp (the daemon must have enable_upnp=yes)")
    parser.add_argument("--nat66-client", help="the client address of the IPv6 cases of a NAT66 section")
    parser.add_argument("--nat66-router", help="the router address of the IPv6 cases of a NAT66 section")
    parser.add_argument("--interface", default="eth0", help="the LAN interface, for --nat66-client")
    add_status_arguments(parser, os.path.dirname(os.path.abspath(__file__)), SUITE)
    return run_driver_suite(parser, load, write_report, self_test, selected_cases, validate_corpus, run_selected,
                            nat66_flag, empty_case_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Small UDP smoke-test harness for the miniupnpd PCP and NAT-PMP server.

Run against a configured, running miniupnpd instance. Mapping lifecycle cases run by default; use a disposable test gateway.
Pass --no-mutating to skip mapping changes.
"""

import argparse
import os
import sys

# python3 -I leaves the directory of the script off sys.path: add common/ beside it
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "common"))

from lib_test import (  # noqa: E402
    CorpusError,
    add_status_arguments,
    add_target_arguments,
    capture_name,
    lease_ports,
    packet_capture,
    prepare_capture_directory,
    print_summary,
    read_checked_corpus,
    run_case,
    run_on_socket,
    select_cases,
    unselected_reason,
    validate_cases,
    write_results,
    write_suite_report,
)


CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcp-wire-cases.yaml")


def self_test():
    """The corpus of this runner reads, expands and checks (case shapes, profiles, dependencies). The
    code it runs is tested in ../common/test_lib_test.py; no daemon is needed."""
    try:
        sections, cases, profiles, _earlier_cases = read_checked_corpus(CORPUS, validate_cases)
    except (CorpusError, ValueError) as error:
        print(f"FAIL corpus {CORPUS}: {error}")
        return 1
    print(f"PASS corpus: {len(sections)} sections, {len(cases)} cases, profiles {', '.join(profiles)}")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true",
                        help="check runner mechanics using simulated replies and loopback sockets; no daemon needed")
    add_target_arguments(parser, "server address (default: 127.0.0.1)")
    parser.add_argument("--protocol", choices=("pcp", "natpmp", "both"), default="both")
    parser.add_argument("--profile", default="baseline",
                        help="explicit server fixture profile from YAML (default: baseline)")
    parser.add_argument("--peer-url", help="WAN traffic actor URL for cases requiring the wan-peer fixture")
    parser.add_argument("--fixture", metavar="COMMAND",
                        help="platform fixture command for cases requiring daemon-restart or wan-renumber; it "
                             "is run as COMMAND daemon-restart DIRECTORY FAMILY and must restart the daemon "
                             "while recording lan-N.pcap and wan-N.pcap into DIRECTORY; COMMAND supports "
                             "wan-renumber exits 0 when it also provides wan-renumber-start/-change/-stop")
    parser.add_argument("--unsupported", action="append", default=[], metavar="FEATURE",
                        help="feature this platform's daemon lacks (for example pcp-peer, which needs the "
                             "netfilter backend); cases requiring it are reported as SKIP. May be repeated")
    parser.add_argument("--scale", action="store_true",
                        help="also run the cases requiring scale (thousands of mappings; tens of minutes)")
    parser.add_argument("--second-client", metavar="ADDRESS",
                        help="a second LAN address of this host (same family as --family); the steps with "
                             "'from: second-client' of the cases requiring second-client are sent from it")
    parser.add_argument("--fixture-only", action="store_true",
                        help="run only the cases that need a fixture this invocation provides")
    parser.add_argument("--state-file", metavar="PATH", action="append",
                        help="a lease file of the daemon (lease_file, and again for lease_file6), shared with this "
                             "runner; the lifecycle steps "
                             "with a 'state' check then verify the mapping is added to it and removed again")
    parser.add_argument("--phase", choices=("create", "verify"),
                        help="run one phase of the cases that require lease-restart: the driver restarts the daemon "
                             "between create and verify")
    parser.add_argument("--state-command", metavar="COMMAND",
                        help="a command which prints the daemon's lease files, instead of --state-file, "
                             "for a daemon in a VM (only the lease_file steps use it)")
    parser.add_argument("--snapshot-dir", metavar="DIR",
                        help="where the create phase keeps the lease-file lines the verify phase compares")
    parser.add_argument("--list-lease-ports", action="store_true",
                        help="print the internal ports the selected lease-restart cases look at, and exit")
    parser.add_argument("--allow-empty-selection", action="store_true",
                        help="write SKIP results if selection excludes this profile/family/protocol")
    parser.add_argument("--mutating", action="store_true", default=True,
                        help="include mapping create/renew/delete cases (default; use a test gateway)")
    parser.add_argument("--no-mutating", dest="mutating", action="store_false",
                        help="skip mapping create/renew/delete cases")
    add_status_arguments(parser, os.path.dirname(os.path.abspath(__file__)), "pcp_wire")
    parser.add_argument("--results-file",
                        help="JSON results path (default with captures: results-FAMILY.json in the run folder)")
    parser.add_argument("--capture-dir",
                        help="capture root; save each run in a timestamped subdirectory")
    parser.add_argument("--capture-name", type=capture_name,
                        help="run folder label (default: the single --case name, otherwise all)")
    parser.add_argument("--capture-interface", default="any",
                        help="interface passed to tcpdump (default: any)")
    parser.add_argument("--tcpdump", default="tcpdump",
                        help="tcpdump executable (default: tcpdump)")
    parser.add_argument("--capture-timeout", type=float, default=1.0,
                        help="seconds to wait for tcpdump to stop after each case")
    return parser


def load_selection(parser, args):
    """Read and check the YAML corpus and pick the cases of this invocation.
    Returns (corpus_path, sections, cases, profiles, selected); a wrong corpus or selection ends the
    program through parser.error."""
    if args.capture_name and not args.capture_dir:
        parser.error("--capture-name requires --capture-dir")

    corpus_path = CORPUS
    try:
        sections, cases, profiles, earlier_cases = read_checked_corpus(CORPUS, validate_cases)
        if args.profile not in profiles:
            parser.error("unknown server profile; choose " + ", ".join(profiles))
        if args.family == "ipv6":
            if args.protocol == "natpmp":
                parser.error("NAT-PMP uses IPv4; select --protocol pcp for IPv6")
            args.protocol = "pcp"
        selected = select_cases(args, cases, profiles, earlier_cases)
    except CorpusError as error:
        parser.error(str(error))
    return corpus_path, sections, cases, profiles, selected


def print_lease_ports(selected):
    for case in selected:
        if case["request"]["kind"] == "lease_restart":
            print(" ".join(str(port) for port in lease_ports(case)))


def run_selected(args, selected):
    """Run the selected cases against the daemon. Returns {(protocol, name): (status, detail)}."""
    return run_on_socket(args, selected,
                         lambda sock, address, case: run_case(sock, address, case, args.mutating, args.peer_url, args),
                         around=lambda case: packet_capture(args, case))


def status_run(args):
    """What this run was, for its line in the status report."""
    return {"target": f"{args.host}:{args.port}", "protocol": args.protocol,
            "profile": getattr(args, "profile", "baseline"), "lifecycle": "on" if args.mutating else "off"}


def fill_unselected(outcomes, cases, args, profiles, selected):
    """Every case of the corpus has an outcome in the report: the ones not run are SKIPs with a reason."""
    selected_ids = {(case["protocol"], case["name"]) for case in selected}
    for case in cases:
        identity = (case["protocol"], case["name"])
        if identity not in outcomes:
            outcomes[identity] = ("SKIP", unselected_reason(case, args, profiles, selected_ids))


def write_reports(args, sections, cases, outcomes, corpus_path):
    """The status report and, when asked, the results file. Returns 2 when a file that was asked for
    cannot be written, else None."""
    try:
        extra = [f"- Capture directory ({args.platform}, last run): `{args.capture_dir}`"] if args.capture_dir else []
        write_suite_report(args, "PCP/NAT-PMP", "pcp_wire", args.family, sections, outcomes, run=status_run(args),
                           extra_lines=extra,
                           keep_if_skipped=("requires daemon-restart fixture", "requires wan-renumber fixture",
                                            "requires lease-restart driver", "requires --scale",
                                            "requires second-client address"))
    except OSError as error:
        # the report is written beside the runner by default, which is not always writable (a read-only
        # checkout); it is an error only for a run that was asked to record its results or captures
        print(f"Unable to write status report {args.status_file}: {error}", file=sys.stderr)
        if args.results_file or args.capture_dir:
            return 2
    results_file = args.results_file
    if not results_file and args.capture_dir:
        results_file = os.path.join(args.capture_dir, f"results-{args.family}.json")
    if results_file:
        try:
            write_results(results_file, args, cases, outcomes, corpus_path)
        except OSError as error:
            print(f"Unable to write results {results_file}: {error}", file=sys.stderr)
            return 2
    return None


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    corpus_path, sections, cases, profiles, selected = load_selection(parser, args)
    if args.list_lease_ports:
        print_lease_ports(selected)
        return 0
    prepare_capture_directory(args)
    try:
        outcomes = run_selected(args, selected)
    except KeyboardInterrupt:
        # an interrupted run writes no report: the cases it did not reach would replace earlier results
        print("Interrupted: no status report or results written.", file=sys.stderr)
        return 130
    fill_unselected(outcomes, cases, args, profiles, selected)
    status = write_reports(args, sections, cases, outcomes, corpus_path)
    if status is not None:
        return status
    if any(outcome == "XFAIL" for outcome, _detail in outcomes.values()):
        print("Expected failures: see the known_failure notes of their YAML cases.")
    return print_summary(outcomes)

if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Daemon options tests of miniupnpd: the same PCP, NAT-PMP and UPnP requests under different
daemon configurations.

Every case of daemon-options-cases.yaml declares the configuration its daemon runs with (config:)
and the side it sends from (from: lan or wan). The driver (run-docker.sh) starts a fresh daemon
per configuration, then runs this runner once per side and address family with --config, --side
and --family; the runner runs the cases of that run and merges their results into status.md.
"""

import argparse
import os
import sys
import tempfile

# python3 -I leaves the directory of the script off sys.path: add common/ beside it
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "common"))

from lib_test import (  # noqa: E402
    CorpusError,
    add_status_arguments,
    add_target_arguments,
    case_config,
    check_case_names,
    cases_of_run,
    config_label,
    config_line,
    config_runs,
    config_word,
    daemon_option_names,
    option_coverage_line,
    option_status_sections,
    permission_line_kinds,
    print_summary,
    read_checked_corpus,
    run_on_socket,
    run_option_case,
    select_cases,
    validate_option_cases,
    write_suite_report,
)


HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "daemon-options-cases.yaml")
# the option table of the daemon, in the source tree (run-docker.sh mounts it in the runner)
OPTIONS_C = os.path.join(HERE, os.pardir, os.pardir, "options.c")
OPTIONS_C = OPTIONS_C if os.path.exists(OPTIONS_C) else None
TITLE = "Daemon options"
SUITE = "daemon_options"


def read_corpus():
    """(sections, cases, profiles, earlier_cases) of daemon-options-cases.yaml, expanded and checked;
    the config keys are checked against options.c when it is there. Needs PyYAML."""
    option_names = daemon_option_names(OPTIONS_C) if OPTIONS_C else None
    return read_checked_corpus(CORPUS, lambda cases, profiles: validate_option_cases(cases, profiles, option_names))


def selection(args, cases, profiles, earlier_cases):
    """The cases of this run: its configuration and side, the selected names and family."""
    check_case_names(args.case, cases)
    run = [case for case in cases_of_run(cases, args.config, args.side)
           if not args.case or case["name"] in args.case]
    return select_cases(argparse.Namespace(**dict(vars(args), case=None)), run, profiles, earlier_cases)


def run_selected(args, selected):
    return run_on_socket(args, selected,
                         lambda sock, address, case: run_option_case(sock, address, case, args.router_call_dir,
                                                                     args.daemon_down),
                         failures=(Exception,))


def write_report(args, sections, outcomes):
    write_suite_report(args, TITLE, SUITE, args.family, option_status_sections(sections), outcomes)


def self_test():
    """The corpus reads, expands and checks (config keys against options.c), every configuration has
    runs, the selection of a run and the report work; no daemon is needed. Then an INFO line (never a
    failure): the options of options.c that a case config varies, and the ones none does. The lib_test code is tested
    in ../common/test_lib_test.py."""
    if not OPTIONS_C:
        print("FAIL options.c not found: the config keys cannot be checked")
        return 1
    try:
        sections, cases, profiles, earlier_cases = read_corpus()
    except (CorpusError, ValueError) as error:
        print(f"FAIL corpus {CORPUS}: {error}")
        return 1
    runs = config_runs(cases)
    configs = {config for config, _side, _family in runs}
    print(f"PASS corpus: {len(sections)} sections, {len(cases)} cases, {len(configs)} configurations, "
          f"{len(runs)} runs; config keys known to options.c")

    # each case is in exactly one run per family, and a run selects only its own cases
    args = build_parser().parse_args(["--side", "wan", "--family", "ipv4"])
    seen = {}
    for config, side, family in runs:
        args.config, args.side, args.family = list(config), side, family
        for case in selection(args, cases, profiles, earlier_cases):
            assert case_config(case) == config and case.get("from", "lan") == side and family in case["families"]
            seen.setdefault((case["name"], family), 0)
            seen[(case["name"], family)] += 1
    expected = {(case["name"], family) for case in cases for family in case["families"]}
    assert set(seen) == expected and set(seen.values()) == {1}, "a case is not in exactly one run per family"
    print("PASS selection: every case is in exactly one run per family")

    # the report: a run of one configuration keeps the results of the others; the config shows
    # (the last case stands in for a second configuration while the corpus has one)
    first = cases[0]
    second = next((case for case in cases if case_config(case) != case_config(first)), cases[-1])
    with tempfile.TemporaryDirectory() as directory:
        args.status_file = os.path.join(directory, "status.md")
        args.status_data_file = os.path.join(directory, "data", "status-data.json")
        args.family = first["families"][0]
        write_report(args, sections, {(first["protocol"], first["name"]): ("PASS", "")})
        args.family = second["families"][0]
        write_report(args, sections, {(second["protocol"], second["name"]): ("FAIL", "boom")})
        with open(args.status_file, encoding="utf-8") as handle:
            text = handle.read()
    assert f"| {first['name']} | {first['protocol']} | {first['families'][0]} | PASS |" in text, text
    assert f"| {second['name']} | {second['protocol']} | {second['families'][0]} | FAIL | boom |" in text, text
    assert f"[{config_label(case_config(first))}; from" in text, text
    print("PASS status report (a run keeps the results of the other configurations)")

    # informational: which options of options.c a case config varies (README.md, Coverage)
    try:
        print(option_coverage_line(cases, sorted(daemon_option_names(OPTIONS_C)), permission_line_kinds(OPTIONS_C)))
    except (OSError, CorpusError) as error:
        print(f"INFO options: coverage not computed ({error})")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true",
                        help="check the corpus (config keys against options.c), the selection and the report; "
                             "no daemon needed")
    parser.add_argument("--list-runs", action="store_true",
                        help="print the runs a driver makes, one per line: SIDE FAMILY CONFIG-LINE..., the "
                             "configurations in corpus order (a configuration without lines prints none)")
    add_target_arguments(parser, "the router address to send to: its LAN address, or its WAN address with --side wan")
    parser.add_argument("--side", choices=("lan", "wan"), default="lan",
                        help="where this run sends from; it runs the cases with this from:")
    parser.add_argument("--config", action="append", default=[], metavar="KEY=VALUE",
                        help="a configuration line of the running daemon, in order; may be repeated. The run "
                             "has the cases whose config: is exactly these lines")
    parser.add_argument("--router-call-dir", help="the directory the driver watches for router commands")
    parser.add_argument("--daemon-down", action="store_true", help="the daemon of this configuration did not start")
    add_status_arguments(parser, HERE, SUITE)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    args.config = [config_line(word) for word in args.config]
    try:
        sections, cases, profiles, earlier_cases = read_corpus()
        if args.list_runs:
            listed = [case for case in cases if (not args.case or case["name"] in args.case)
                      and case.get("platform", args.platform) == args.platform]
            for config, side, family in config_runs(listed):
                print(" ".join((side, family) + tuple(config_word(line) for line in config)))
            return 0
        selected = selection(args, cases, profiles, earlier_cases)
    except CorpusError as error:
        parser.error(str(error))
    if not selected:
        print(f"No cases for {config_label(args.config)} from {args.side} on {args.family}.")
        return 0
    try:
        outcomes = run_selected(args, selected)
    except KeyboardInterrupt:
        print("Interrupted: no status report written.", file=sys.stderr)
        return 130
    try:
        write_report(args, sections, outcomes)
    except OSError as error:
        print(f"Unable to write status report {args.status_file}: {error}", file=sys.stderr)
        return 2
    return print_summary(outcomes)


if __name__ == "__main__":
    sys.exit(main())

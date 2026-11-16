"""What compare_daemon_branches.py and the suites share: a suite tells the tool how to run it and read
its results in a compare.py of its own (miniupnpd/tests/SUITE/compare.py), which imports this module.

A suite's compare.py defines:
  SUITE       the name --suite selects
  TITLE       the report title (the platform is added)
  CORPUS      the YAML corpus, relative to the suite's directory
  PLATFORMS   the platforms --platform can run it on
  run(label, tree, output, args) -> (outcomes, corpus_sha256)
              run the suite's driver in `tree` (a prepared copy of a daemon version), keep its log
              and results under output/label, and return its outcomes keyed (family, group, case),
              each {'status': PASS|FAIL|XFAIL|SKIP, 'detail': text}
and may define:
  add_arguments(parser)               options of its own
  check(parser, args)                 reject option combinations
  report_header(args) -> lines        lines under the commits in summary.md
  reproduce(commits, args) -> lines   how to repeat the comparison locally
  NOTES                               a sentence for the end of the report's notes
  LINK_COLUMN, case_link(output, key, before, after) -> markdown   a column of per-case links"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMMON))

from lib_test import is_filtered_skip  # noqa: E402,F401  (the suites' compare.py use it too)

TESTS = Path('miniupnpd/tests')
STATUSES = {'PASS', 'FAIL', 'XFAIL', 'SKIP'}


def cell(value):
    """A Markdown table cell."""
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\n', ' ')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_driver(label, tree, folder, command, env):
    """Run a driver in `tree` with its output in folder/run.log; return its exit code."""
    folder.mkdir(parents=True, exist_ok=True)
    print(f'Running {label}; log: {folder / "run.log"}', flush=True)
    with (folder / 'run.log').open('w') as log:
        return subprocess.run(command, cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT).returncode


def check_exit(outcomes, exit_code):
    """A driver exits 1 when a case failed and 0 otherwise."""
    failures = sum(result['status'] == 'FAIL' for result in outcomes.values())
    if exit_code != (1 if failures else 0):
        raise ValueError(f'harness exit {exit_code} disagrees with {failures} reported failures')


def read_status_results(path, platform, corpus_digest):
    """The results of one platform in a status-data.json (lib_test.write_status_report), keyed
    (family, protocol, case)."""
    data = json.loads(Path(path).read_text())
    outcomes = {}
    for family, cases in data['platforms'][platform]['results'].items():
        for key, (status, detail) in cases.items():
            protocol, name = key.split('/', 1)
            if status not in STATUSES:
                raise ValueError(f'invalid result: {key}')
            outcomes[(family, protocol, name)] = {'status': status, 'detail': detail}
    if not any(not is_filtered_skip(item['status'], item['detail']) for item in outcomes.values()):
        raise ValueError(f'no cases executed in {path}')
    return outcomes, corpus_digest


def read_build_results(path, corpus_digest):
    """The results of every platform in a status-data.json, for a driver whose one run fills several
    columns (a column per daemon build: linux-igd1, linux-igd2): keyed ('PLATFORM FAMILY', protocol, case)."""
    platforms = json.loads(Path(path).read_text())['platforms']
    outcomes = {}
    for platform in platforms:
        found, _ = read_status_results(path, platform, corpus_digest)
        outcomes.update({(f'{platform} {family}', protocol, name): result
                         for (family, protocol, name), result in found.items()})
    if not outcomes:
        raise ValueError(f'no results in {path}')
    return outcomes, corpus_digest


def run_build_driver(suite_dir, label, tree, output, args, driver, corpus, env_prefix):
    """run() of a suite whose driver runs every daemon build in one go (the UPnP suites): `driver` in
    suite_dir, its report and status data put under output/label through its {env_prefix}_STATUS_FILE and
    {env_prefix}_STATUS_DATA_FILE. The corpus has FAILs (spec gaps), so the comparison decides; the exit
    code must only agree with them."""
    folder = output / label
    directory = TESTS / Path(suite_dir).name
    env = dict(os.environ, PCP_TEST_SELF_TEST='0', **{f'{env_prefix}_STATUS_FILE': str(folder / 'status.md'),
                                                      f'{env_prefix}_STATUS_DATA_FILE': str(folder / 'status-data.json')})
    command = [f'./{directory / driver}']
    for name in args.case:
        command += ['--case', name]
    exit_code = run_driver(f'{label} ({args.platform})', tree, folder, command, env)
    data = folder / 'status-data.json'
    if not data.is_file():
        raise ValueError(f'{label}: the driver wrote no results (exit {exit_code}); see {folder / "run.log"}')
    outcomes, corpus_digest = read_build_results(data, digest(tree / directory / corpus))
    check_exit(outcomes, exit_code)
    return outcomes, corpus_digest

#!/usr/bin/env python3
"""Run the same test suite on master's daemon and a candidate's, and report the regressions.

Both daemons run with the candidate's harness. --suite picks the suite: each suite directory with a
compare.py (miniupnpd/tests/SUITE/compare.py, see suite_compare.py) is one, and says how it runs on
which --platform. --results MASTER CANDIDATE: run nothing, compare the status-data.json of two runs
which ended (a suite run in the FreeBSD VM of the workflow). --suite NAME --help lists the options of
that suite."""

import argparse
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]     # common/
sys.path.insert(0, str(Path(__file__).resolve().parent))

from suite_compare import TESTS, cell, digest, is_filtered_skip, read_status_results  # noqa: E402

UNTRACKED = shutil.ignore_patterns('__pycache__', 'status.md', 'status-data.json')
# the options of the tool, not of a suite (the manifest lists a suite's options apart)
GENERIC_OPTIONS = {'master_source', 'candidate_source', 'output', 'suite', 'platform', 'results', 'case'}


def load_suites(tests=HERE.parent):
    """The suites, by name: the compare.py of each directory of `tests`."""
    suites = {}
    for path in sorted(tests.glob('*/compare.py')):
        spec = importlib.util.spec_from_file_location(f'suite_compare_{path.parent.name}', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if module.SUITE in suites:
            raise ValueError(f'two suites are named {module.SUITE}: {path}')
        module.DIR = path.parent.name
        suites[module.SUITE] = module
    return suites


def command_output(command):
    return subprocess.check_output(command, text=True).strip()


def prepare_tree(source, destination, harness_source=HERE.parent):
    """Build committed daemon sources with exactly this invocation's harness (all of miniupnpd/tests).
    The tree is made a git repository, as run-freebsd.sh copies it with git ls-files."""
    archive = subprocess.check_output(['git', '-C', str(source), 'archive', 'HEAD'])
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
        tree.extractall(destination, filter='data')
    tests = destination / TESTS
    if tests.exists():
        shutil.rmtree(tests)
    shutil.copytree(harness_source, tests, ignore=UNTRACKED)
    git = ['git', '-C', str(destination), '-c', 'user.name=pcp-compare', '-c', 'user.email=pcp-compare@invalid',
           '-c', 'commit.gpgsign=false']
    subprocess.run(git + ['init', '-q'], check=True)
    subprocess.run(git + ['add', '-A', '-f'], check=True)
    subprocess.run(git + ['commit', '-q', '-m', 'tree under comparison'], check=True)
    return command_output(['git', '-C', str(source), 'rev-parse', 'HEAD'])


def transition(before, after):
    if before == after:
        return 'unchanged'
    if before == 'PASS' or (before != 'SKIP' and after == 'SKIP') or (before == 'XFAIL' and after == 'FAIL'):
        return 'regression'
    if after == 'PASS':
        return 'improvement'
    if before == 'SKIP':
        return 'new coverage'
    return 'changed'


def compare_results(before, after):
    if before.keys() != after.keys():
        raise ValueError('master and candidate results contain different case identities')
    return [(key, transition(before[key]['status'], after[key]['status'])) for key in before]


def make_report(output, commits, runs, errors, title, suite=None, args=None):
    """summary.md; the exit code: 0 no regression, 1 regressions, 2 an incomplete comparison. The suite
    adds its header lines and how to reproduce the comparison (not for --results), its notes and a
    column of per-case links."""
    ran = suite is not None and args is not None and not args.results
    header = suite.report_header(args) if ran and hasattr(suite, 'report_header') else []
    reproduce = suite.reproduce(commits, args) if ran and hasattr(suite, 'reproduce') else []
    lines = [f'# {title}: master versus pull request', '',
             f"- Master commit: `{commits.get('master', 'unavailable')}`",
             f"- Candidate commit: `{commits.get('candidate', 'unavailable')}`", '',
             *header,
             'Both daemon builds use the same candidate test harness and YAML corpus. '
             'The candidate is the PR head, without a synthetic merge with master.', '']
    if errors:
        lines += ['## Infrastructure errors', '']
        lines += [f'- {cell(label)}: {cell(error)}' for label, error in errors]
        lines += ['', 'The comparison is incomplete and must not be treated as passing.', '', *reproduce]
        (output / 'summary.md').write_text('\n'.join(lines))
        return 2
    before, before_digest = runs['master']
    after, after_digest = runs['candidate']
    if before_digest != after_digest:
        raise ValueError('master and candidate used different corpus hashes')
    transitions = compare_results(before, after)
    counts = Counter(kind for _, kind in transitions)
    regressions = [key for key, kind in transitions if kind == 'regression']
    print(f'Regressions: {len(regressions)}', flush=True)
    for key in regressions:
        print(f"REGRESSION {key[0]} {key[1]}/{key[2]}: {before[key]['status']} -> {after[key]['status']}: "
              f"{after[key]['detail']}", flush=True)
    lines += [f'- Corpus SHA-256: `{before_digest}`', '',
              '| Run | PASS | FAIL | XFAIL | SKIP |', '|:--|--:|--:|--:|--:|']
    for label, results in (('Master', before), ('Candidate', after)):
        totals = Counter(item['status'] for item in results.values()
                         if not is_filtered_skip(item['status'], item['detail']))
        lines.append(f"| {label} | {totals['PASS']} | {totals['FAIL']} | {totals['XFAIL']} | {totals['SKIP']} |")
    notes = getattr(suite, 'NOTES', '')
    lines += ['', f"Regressions: **{counts['regression']}**. Improvements: **{counts['improvement']}**.", '',
              'Totals omit cases excluded by protocol, address family or case filters. '
              'Other skips remain counted.', '',
              'Existing master failures do not fail this comparison. A previously passing case that '
              'stops passing, a previously executed case that becomes skipped, or an expected failure '
              'that becomes an unexpected failure is a regression. Failures exposed by newly satisfied '
              'dependencies are shown as new coverage, not established regressions.', '',
              'Download the workflow artifact for the run logs, status tables and JSON results.' +
              (' ' + notes if notes else ''), '', *reproduce]
    if regressions:
        lines += ['## Regressions', '', '| Family | Protocol / case | Master | Candidate | Candidate detail |',
                  '|:--|:--|:--|:--|:--|']
        lines += ['| ' + ' | '.join((cell(key[0]), cell(f'{key[1]}/{key[2]}'), before[key]['status'],
                                     after[key]['status'], cell(after[key]['detail']))) + ' |'
                  for key in regressions]
        lines.append('')
    link = getattr(suite, 'case_link', None)
    column = f" {suite.LINK_COLUMN} |" if link else ''
    lines += ['## Case results', '', '| Family | Protocol / case | Master | Candidate | Change |' + column,
              '|:--|:--|:--|:--|:--|' + (':--|' if link else '')]
    for key, kind in transitions:
        a, b = before[key], after[key]
        if is_filtered_skip(a['status'], a['detail']) and is_filtered_skip(b['status'], b['detail']):
            continue
        cells = [cell(key[0]), cell(f'{key[1]}/{key[2]}'), a['status'], b['status'], kind]
        if link:
            cells.append(link(output, key, a, b))
        lines.append('| ' + ' | '.join(cells) + ' |')
    lines.append('')
    (output / 'summary.md').write_text('\n'.join(lines))
    return 1 if counts['regression'] else 0


def parse_args(suites, argv=None):
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument('--suite', choices=tuple(suites))
    chosen = suites.get(pre.parse_known_args(argv)[0].suite)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master-source', type=Path, required=True, help='master git checkout')
    parser.add_argument('--candidate-source', type=Path, required=True, help='PR head git checkout')
    parser.add_argument('--output', type=Path, required=True, help='new artifact directory')
    parser.add_argument('--suite', choices=tuple(suites), required=True,
                        help='the suite to compare (the compare.py of its directory)')
    parser.add_argument('--platform', choices=sorted({p for module in suites.values() for p in module.PLATFORMS}),
                        default='linux', help='where the suite runs, or which platform of --results to read')
    parser.add_argument('--results', nargs=2, type=Path, metavar=('MASTER', 'CANDIDATE'),
                        help='run nothing: compare the status-data.json of two ended runs of --platform')
    parser.add_argument('--case', action='append', default=[], help='select one YAML case; repeatable')
    if chosen is not None and hasattr(chosen, 'add_arguments'):
        chosen.add_arguments(parser.add_argument_group(f'{chosen.SUITE} options'))
    args = parser.parse_args(argv)
    suite = suites[args.suite]
    if args.results and args.case:
        parser.error('--results compares whole runs which ended: no --case')
    if not args.results and args.platform not in suite.PLATFORMS:
        parser.error(f'the {suite.SUITE} suite runs on {", ".join(suite.PLATFORMS)}, not {args.platform}')
    if hasattr(suite, 'check'):
        suite.check(parser, args)
    if args.output.exists():
        parser.error('--output must be a new directory to avoid reusing stale results')
    return suite, args


def main(argv=None):
    suite, args = parse_args(load_suites(), argv)
    output = args.output.resolve()
    output.mkdir(parents=True)
    commits, runs, errors = {}, {}, []
    with tempfile.TemporaryDirectory(prefix='pcp-branch-comparison-') as temporary:
        harness_snapshot = Path(temporary) / 'tests'
        shutil.copytree(HERE.parent, harness_snapshot, ignore=UNTRACKED)
        corpus_digest = digest(harness_snapshot / suite.DIR / suite.CORPUS)
        for index, (label, source) in enumerate((('master', args.master_source), ('candidate', args.candidate_source))):
            try:
                if args.results:
                    commits[label] = command_output(['git', '-C', str(source), 'rev-parse', 'HEAD'])
                    runs[label] = read_status_results(args.results[index] / 'status-data.json', args.platform,
                                                      corpus_digest)
                    continue
                tree = Path(temporary) / label
                commits[label] = prepare_tree(source.resolve(), tree, harness_snapshot)
                runs[label] = suite.run(label, tree, output, args)
                if runs[label][1] != corpus_digest:
                    raise ValueError('run did not use the selected candidate corpus')
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                errors.append((label, str(error)))
    options = {name: value for name, value in vars(args).items() if name not in GENERIC_OPTIONS}
    manifest = {'version': 2, 'suite': args.suite, 'platform': args.platform, 'commits': commits,
                'corpus_sha256': corpus_digest, 'cases': args.case, 'options': options, 'errors': errors}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2, default=str) + '\n')
    title = f'{suite.TITLE} ({args.platform})'
    try:
        code = make_report(output, commits, runs, errors, title, suite, args)
    except (OSError, ValueError, KeyError) as error:
        code = make_report(output, commits, runs, [('comparison', str(error))], title, suite, args)
    print(f'Comparison report: {output / "summary.md"}', flush=True)
    return code


if __name__ == '__main__':
    sys.exit(main())

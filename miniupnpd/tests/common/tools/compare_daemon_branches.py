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
import os
import re
import shlex
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


def change_table(heading, keys, before, after):
    """The cases of one kind of change, as a markdown table under `heading`; nothing without cases."""
    if not keys:
        return []
    return [heading, '', '| Family | Protocol / case | Master | Candidate | Candidate detail |',
            '|:--|:--|:--|:--|:--|',
            *('| ' + ' | '.join((cell(key[0]), cell(f'{key[1]}/{key[2]}'), before[key]['status'],
                                 after[key]['status'], cell(after[key]['detail']))) + ' |' for key in keys), '']


# the UPnP documents linked from https://openconnectivity.org/developer/specifications/upnp-resources/upnp/
# (its IGD v2 page and its archive of device architectures), by the prefix of a case's ref; refs of other
# documents (WANIPC1, IGD1, SOAP11 ...) stay text
SPEC_PDFS = {
    'UDA-1.0': 'http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf',
    'UDA-1.1': 'https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf',
    'IGD2': 'http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v2-Device.pdf',
    'WANIPC2': 'http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf',
    '6FC1': 'http://upnp.org/specs/gw/UPnP-gw-WANIPv6FirewallControl-v1-Service.pdf',
    'L3F1': 'http://upnp.org/specs/gw/UPnP-gw-Layer3Forwarding-v1-Service.pdf',
    'WANCIC1': 'http://upnp.org/specs/gw/UPnP-gw-WANCommonInterfaceConfig-v1-Service.pdf',
}


def case_index(corpus):
    """name: (line, refs) of each case of a corpus, read as text: the line of its '- name:', and the
    'ref:' under it if any, a string or a map by build ({igd1: "...", igd2: "..."})."""
    index, name = {}, None
    for number, line in enumerate(corpus.read_text().splitlines(), 1):
        found = re.match(r'\s*- name: *"?([^"\s]+)"?\s*$', line)
        if found:
            name = found[1]
            index.setdefault(name, (number, ()))
            continue
        found = re.match(r'\s+ref: *(".*"|\{.*\})', line)
        if found and name in index and not index[name][1]:
            index[name] = (index[name][0], tuple(re.findall(r'"([^"]*)"', found[1])))
    return index


def spec_cell(ref):
    """The ref of a case, linked to its RFC section or to the UPnP document of its prefix."""
    found = re.match(r'(\S+) §(\S+)', ref)
    if not found:
        return cell(ref)
    rfc = re.fullmatch(r'RFC(\d+)', found[1])
    if rfc:
        return f'[{cell(ref)}](https://www.rfc-editor.org/rfc/rfc{rfc[1]}#section-{found[2]})'
    if found[1] in SPEC_PDFS:
        return f'[{cell(ref)}]({SPEC_PDFS[found[1]]})'
    return cell(ref)


def case_sources(commits, suite):
    """For the review: a function giving the case cell (linked to the case's line in the corpus at the
    candidate commit, in CI) and the spec cell of a case name."""
    corpus = HERE.parent / suite.DIR / suite.CORPUS if hasattr(suite, 'DIR') else None    # suite may be None
    index = case_index(corpus) if corpus and corpus.exists() else {}
    server, repository = os.environ.get('GITHUB_SERVER_URL'), os.environ.get('GITHUB_REPOSITORY')
    blob = (f'{server}/{repository}/blob/{commits["candidate"]}/{TESTS}/{suite.DIR}/{suite.CORPUS}'
            if index and server and repository and 'candidate' in commits else None)

    def source(text, name):
        line, refs = index.get(name, (None, ()))
        shown = f'[{cell(text)}]({blob}#L{line})' if blob and line else cell(text)
        return shown, ', '.join(spec_cell(ref) for ref in refs)
    return source


def grouped_table(label, keys, before, after, open_box, source, mark=''):
    """As change_table, in a <details> box, one row per case and outcome: the families it holds for share
    a cell. `source` gives the case and spec cells; `mark` goes before the box's summary and each case
    (the red mark the review puts on the way down to a regression)."""
    if not keys:
        return []
    rows = {}
    for key in keys:
        row = (key[1], key[2], before[key]['status'], after[key]['status'], after[key]['detail'])
        rows.setdefault(row, []).append(key[0])
    cases = len({row[:2] for row in rows})
    return ['<details open>' if open_box else '<details>',
            f'<summary>{mark}{label}: {cases} case{"s" if cases != 1 else ""}</summary>', '',
            '| Protocol / case | Spec | Master | Candidate | Detail | Families |', '|:--|:--|:--|:--|:--|:--|',
            *('| ' + mark + ' | '.join((*source(f'{protocol}/{name}', name), master, candidate, cell(detail),
                                 cell(', '.join(families)))) + ' |'
              for (protocol, name, master, candidate, detail), families in rows.items()), '', '</details>', '']


def review_reproduce(commits, suite, args, keys):
    """A <details> box with the commands which compare the changed cases again, on a machine with this
    harness; nothing for a platform the suite does not run on (the FreeBSD wire run reads --results)."""
    if not keys or suite is None or args is None or args.platform not in suite.PLATFORMS:
        return []
    cases = ''.join(' --case ' + shlex.quote(name) for name in sorted({key[2] for key in keys}))
    return ['<details>', '<summary>Reproduce locally</summary>', '', '```sh',
            'git worktree add --detach .tmp/compare-master ' + shlex.quote(commits.get('master', 'MASTER_COMMIT')),
            'git worktree add --detach .tmp/compare-candidate ' + shlex.quote(commits.get('candidate', 'PR_COMMIT')),
            f'python3 miniupnpd/tests/common/tools/compare_daemon_branches.py --suite {shlex.quote(suite.SUITE)} '
            f'--platform {shlex.quote(args.platform)} \\',
            '  --master-source .tmp/compare-master --candidate-source .tmp/compare-candidate \\',
            '  --output .tmp/compare-output' + cases, '```', '', '</details>', '']


def make_report(output, commits, runs, errors, title, suite=None, args=None):
    """summary.md, and review.md: the counts and the changed cases alone, for the review the workflow
    posts on the pull request: the counts on its first line (unchanged leaves out the cases a filter
    skipped), then a <details> box per kind of change and one to reproduce them. The exit code: 0 no regression,
    1 regressions, 2 an incomplete comparison. The suite adds its header lines and how to reproduce the
    comparison (not for --results), its notes and a column of per-case links."""
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
        (output / 'review.md').write_text('\n'.join(
            ['Incomplete comparison.', '',
             *(f'- {cell(label)}: {cell(error)}' for label, error in errors), '']))
        return 2
    before, before_digest = runs['master']
    after, after_digest = runs['candidate']
    if before_digest != after_digest:
        raise ValueError('master and candidate used different corpus hashes')
    transitions = compare_results(before, after)
    counts = Counter(kind for _, kind in transitions)
    regressions = [key for key, kind in transitions if kind == 'regression']
    improvements = [key for key, kind in transitions if kind == 'improvement']
    new_coverage = [key for key, kind in transitions if kind == 'new coverage']
    other = [key for key, kind in transitions if kind == 'changed']
    print(f'Regressions: {len(regressions)}. Improvements: {len(improvements)}.', flush=True)
    for label, keys in (('REGRESSION', regressions), ('IMPROVEMENT', improvements)):
        for key in keys:
            print(f"{label} {key[0]} {key[1]}/{key[2]}: {before[key]['status']} -> {after[key]['status']}: "
                  f"{after[key]['detail']}", flush=True)
    lines += [f'- Corpus SHA-256: `{before_digest}`', '',
              '| Run | PASS | FAIL | XFAIL | SKIP |', '|:--|--:|--:|--:|--:|']
    for label, results in (('Master', before), ('Candidate', after)):
        totals = Counter(item['status'] for item in results.values()
                         if not is_filtered_skip(item['status'], item['detail']))
        lines.append(f"| {label} | {totals['PASS']} | {totals['FAIL']} | {totals['XFAIL']} | {totals['SKIP']} |")
    notes = getattr(suite, 'NOTES', '')
    counted = f"Regressions: **{counts['regression']}**. Improvements: **{counts['improvement']}**."
    lines += ['', counted, '',
              'Totals omit cases excluded by protocol, address family or case filters. '
              'Other skips remain counted.', '',
              'Existing master failures do not fail this comparison. A previously passing case that '
              'stops passing, a previously executed case that becomes skipped, or an expected failure '
              'that becomes an unexpected failure is a regression. Failures exposed by newly satisfied '
              'dependencies are shown as new coverage, not established regressions.', '',
              'Download the workflow artifact for the run logs, status tables and JSON results.' +
              (' ' + notes if notes else ''), '', *reproduce]
    lines += change_table('## Regressions', regressions, before, after)
    lines += change_table('## Improvements', improvements, before, after)
    unchanged = sum(1 for key, kind in transitions if kind == 'unchanged'
                    and not is_filtered_skip(after[key]['status'], after[key]['detail']))
    source = case_sources(commits, suite)
    (output / 'review.md').write_text('\n'.join(
        [f'Regressions: {len(regressions)}. Improvements: {len(improvements)}. New coverage: {len(new_coverage)}. '
         f'Other changes: {len(other)}. Unchanged: {unchanged}.', '',
         *grouped_table('Regressions', regressions, before, after, True, source, '🔴 '),
         *grouped_table('Improvements', improvements, before, after, False, source),
         *grouped_table('New coverage', new_coverage, before, after, False, source),
         *grouped_table('Other changes', other, before, after, False, source),
         *review_reproduce(commits, suite, args, regressions + improvements + new_coverage + other)]))
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

#!/usr/bin/env python3
"""Run the same PCP test corpus on master's daemon and a candidate's, and report the regressions.

--suite wire (default): the request / response suite (pcp_wire) on Docker.
--suite end2end: the forwarding suite (pcp_e2e), --platform linux (run-docker.sh) or freebsd
(run-freebsd.sh, a FreeBSD pf router in QEMU). Both daemons run with the candidate's harness.
--results MASTER CANDIDATE: run nothing, compare the status data of two runs which ended (the wire
suite in the FreeBSD VM of the workflow)."""

import argparse
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from compare_pcap_wire_fields import cell, load_capture, markdown
from lib_test import is_filtered_skip  # noqa: E402  (compare_pcap_wire_fields puts common/ on sys.path)
TESTS = Path('miniupnpd/tests')
HARNESS = TESTS / 'pcp_wire'
END2END_DRIVERS = {'linux': 'run-docker.sh', 'freebsd': 'run-freebsd.sh'}
UNTRACKED = shutil.ignore_patterns('__pycache__', 'status.md', 'status-data.json')
STATUSES = {'PASS', 'FAIL', 'XFAIL', 'SKIP'}


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


def read_results(folder, exit_code, capture_folder=None):
    """Require complete results, and complete captures when requested."""
    outcomes, digests = {}, set()
    for family in ('ipv4', 'ipv6'):
        results = json.loads((folder / f'results-{family}.json').read_text())
        if results.get('version') != 1 or results.get('family') != family:
            raise ValueError(f'invalid {family} result metadata')
        digests.add(results['corpus_sha256'])
        if not results['cases']:
            raise ValueError(f'empty {family} results')
        for result in results['cases']:
            key = (family, result['protocol'], result['name'])
            if key in outcomes or result['status'] not in STATUSES:
                raise ValueError(f'invalid or duplicate result: {key}')
            if capture_folder is not None and result['status'] != 'SKIP':
                filename = f"{family}-{result['protocol']}-{result['name'].replace('/', '_')}"
                pcap = capture_folder / (filename + '.pcap')
                if pcap.stat().st_size < 24 or not (capture_folder / (filename + '.tcpdump.log')).is_file():
                    raise ValueError(f'missing or incomplete capture for {key}')
                result['pcap'] = pcap
            outcomes[key] = result
    if len(digests) != 1:
        raise ValueError('address families used different corpora')
    if not any(result['status'] != 'SKIP' for result in outcomes.values()):
        raise ValueError('no cases executed')
    failures = sum(result['status'] == 'FAIL' for result in outcomes.values())
    if exit_code != (1 if failures else 0):
        raise ValueError(f'harness exit {exit_code} disagrees with {failures} reported failures')
    return outcomes, digests.pop()


def read_end2end_results(artifacts, log_text, exit_code, corpus_digest):
    """The cases of an end2end driver run: the rows of its results.tsv (family, section, case, result,
    note), keyed (family, section, case), and the lease-restart check of run-freebsd.sh as a case of its
    own (its PASS / FAIL restart line)."""
    tables = sorted(artifacts.glob('*/results.tsv'))
    if len(tables) != 1:
        raise ValueError(f'expected one results.tsv under {artifacts}, found {len(tables)}')
    outcomes = {}
    for line in tables[0].read_text().splitlines():
        fields = line.split('\t')
        if len(fields) < 5:
            continue
        family, section, name, status, detail = fields[:5]
        key = (family, section, name)
        if key in outcomes or status not in STATUSES:
            raise ValueError(f'invalid or duplicate result: {key}')
        outcomes[key] = {'status': status, 'detail': detail}
    for line in log_text.splitlines():
        for status in ('PASS', 'FAIL'):
            prefix = f'{status} restart: '
            if prefix in line:
                outcomes[('both', 'restart', 'lease-file')] = {'status': status, 'detail': line.split(prefix, 1)[1]}
    if not outcomes:
        raise ValueError('no cases executed')
    failures = sum(result['status'] == 'FAIL' for result in outcomes.values())
    if exit_code != (1 if failures else 0):
        raise ValueError(f'harness exit {exit_code} disagrees with {failures} reported failures')
    return outcomes, corpus_digest


def run_end2end(label, tree, output, case_names, platform):
    """One end2end driver run in `tree`, its artifacts and report under output/label."""
    folder = output / label
    folder.mkdir(parents=True)
    env = os.environ.copy()
    env.update(PCP_E2E_ARTIFACT_DIR=str(folder / 'artifacts'), E2E_STATUS_FILE=str(folder / 'status.md'),
               E2E_STATUS_DATA_FILE=str(folder / 'status-data.json'), PCP_TEST_SELF_TEST='0')
    command = [f'./miniupnpd/tests/pcp_e2e/{END2END_DRIVERS[platform]}']
    for name in case_names:
        command += ['--case', name]
    print(f'Running {label} ({platform}); log: {folder / "run.log"}', flush=True)
    with (folder / 'run.log').open('w') as log:
        result = subprocess.run(command, cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT)
    corpus = tree / TESTS / 'pcp_e2e' / 'pcp-e2e-cases.yaml'
    return read_end2end_results(folder / 'artifacts', (folder / 'run.log').read_text(), result.returncode,
                                hashlib.sha256(corpus.read_bytes()).hexdigest())


def read_status_results(path, platform, corpus_digest):
    """The results of one platform in a status-data.json, keyed (family, protocol, case)."""
    data = json.loads(path.read_text())
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


def run_one(label, tree, output, case_names, capture, profile='baseline', wan_peer=False):
    results_dir = output / label
    results_dir.mkdir(parents=True)
    capture_root = output / label / 'captures'
    env = os.environ.copy()
    env.update(PCP_TEST_CAPTURE_DIR=str(capture_root),
               PCP_TEST_CAPTURE='1' if capture else '0',
               PCP_TEST_WAN_PEER='1' if wan_peer else '0',
               PCP_TEST_RESULTS_DIR=str(results_dir),
               PCP_TEST_KEEP_CONTAINER='0')
    # Use the harness defaults for container/network isolation and its timestamp.
    for name in ('PCP_TEST_CONTAINER', 'PCP_TEST_NETWORK', 'PCP_TEST_CAPTURE_TIMESTAMP'):
        env.pop(name, None)
    command = ['./miniupnpd/tests/pcp_wire/run-docker.sh', '--profile', profile]
    if capture:
        command += ['--capture-name', label]
    for name in case_names:
        command += ['--case', name]
    print(f'Running {label}; log: {output / label / "run.log"}', flush=True)
    with (output / label / 'run.log').open('w') as log:
        result = subprocess.run(command, cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT)
    if not (results_dir / 'status.md').is_file():
        raise ValueError(f'{label}: missing status report; see run.log')
    capture_folder = None
    if capture:
        folders = [path for path in capture_root.iterdir() if path.is_dir()]
        if len(folders) != 1:
            raise ValueError(f'expected one capture run folder under {capture_root}')
        capture_folder = folders[0]
    return read_results(results_dir, result.returncode, capture_folder)


def local_capture_command(commits, cases, profile='baseline', wan_peer=False):
    return [
        '## Reproduce locally with packet details', '',
        'From a checkout containing this harness, fetch the commits above if needed and run '
        '(the worktree and output directories must be new):', '',
        '```sh',
        'git worktree add --detach .tmp/pcp-master ' + shlex.quote(commits.get('master', 'MASTER_COMMIT')),
        'git worktree add --detach .tmp/pcp-candidate ' + shlex.quote(commits.get('candidate', 'PR_COMMIT')),
        'python3 miniupnpd/tests/pcp_wire/tools/compare_daemon_branches.py \\',
        '  --master-source .tmp/pcp-master \\',
        '  --candidate-source .tmp/pcp-candidate \\',
        '  --output .tmp/pcp-local-details --capture --profile ' + shlex.quote(profile) +
        (' --wan-peer' if wan_peer else '') +
        ''.join(' --case ' + shlex.quote(name) for name in cases),
        '```', '',
        'Use --case CASE_NAME to focus on one case. Docker is required. '
        'This collects pcaps, tcpdump logs and decoded before/after field tables.', '',
    ]


def make_report(output, commits, runs, errors, cases=(), profile='baseline', wan_peer=False,
                title='PCP/NAT-PMP (wire)', reproduce=True):
    lines = [f'# {title}: master versus pull request', '',
             f"- Master commit: `{commits.get('master', 'unavailable')}`",
             f"- Candidate commit: `{commits.get('candidate', 'unavailable')}`", '',
             *([f'- Server profile: `{cell(profile)}`', ''] if reproduce else []),
             'Both daemon builds use the same candidate test harness and YAML corpus. '
             'The candidate is the PR head, without a synthetic merge with master.', '']
    if errors:
        lines += ['## Infrastructure errors', '']
        lines += [f'- {cell(label)}: {cell(error)}' for label, error in errors]
        lines += ['', 'The comparison is incomplete and must not be treated as passing.', '']
        if reproduce:
            lines += local_capture_command(commits, cases, profile, wan_peer)
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
    lines += ['', f"Regressions: **{counts['regression']}**. Improvements: **{counts['improvement']}**.", '',
              'Totals omit cases excluded by protocol, address family or case filters. '
              'Other skips remain counted.', '',
              'Existing master failures do not fail this comparison. A previously passing case that '
              'stops passing, a previously executed case that becomes skipped, or an expected failure '
              'that becomes an unexpected failure is a regression. Failures exposed by newly satisfied '
              'dependencies are shown as new coverage, not established regressions.', '',
              'Download the workflow artifact for the run logs, status tables and JSON results. '
              'Packet captures and wire-field comparisons are produced only with --capture.', '',
              *(local_capture_command(commits, cases, profile, wan_peer) if reproduce else [])]
    if regressions:
        lines += ['## Regressions', '', '| Family | Protocol / case | Master | Candidate | Candidate detail |',
                  '|:--|:--|:--|:--|:--|']
        lines += ['| ' + ' | '.join((cell(key[0]), cell(f'{key[1]}/{key[2]}'), before[key]['status'],
                                     after[key]['status'], cell(after[key]['detail']))) + ' |'
                  for key in regressions]
        lines.append('')
    lines += ['## Case results', '', '| Family | Protocol / case | Master | Candidate | Change | Wire fields |',
              '|:--|:--|:--|:--|:--|:--|']
    comparisons = output / 'comparisons'
    for key, kind in transitions:
        a, b = before[key], after[key]
        if (is_filtered_skip(a['status'], a['detail']) and
                is_filtered_skip(b['status'], b['detail'])):
            continue
        link = ''
        if 'pcap' in a and 'pcap' in b:
            comparisons.mkdir(exist_ok=True)
            filename = f"{key[0]}-{key[1]}-{key[2].replace('/', '_')}.md"
            left, ln = load_capture(a['pcap'], 5351)
            right, rn = load_capture(b['pcap'], 5351)
            # Relative capture paths make the downloaded artifact self-contained.
            report = markdown(Path('..') / a['pcap'].relative_to(output),
                              Path('..') / b['pcap'].relative_to(output),
                              left, right, (ln, rn), False)
            (comparisons / filename).write_text(report)
            link = f'[compare](comparisons/{filename})'
        lines.append('| ' + ' | '.join((cell(key[0]), cell(f'{key[1]}/{key[2]}'),
                                        a['status'], b['status'], kind, link)) + ' |')
    lines.append('')
    (output / 'summary.md').write_text('\n'.join(lines))
    return 1 if counts['regression'] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master-source', type=Path, required=True, help='master git checkout')
    parser.add_argument('--candidate-source', type=Path, required=True, help='PR head git checkout')
    parser.add_argument('--output', type=Path, required=True, help='new artifact directory')
    parser.add_argument('--suite', choices=('wire', 'end2end'), default='wire',
                        help='wire: the pcp_wire suite (default); end2end: the pcp_e2e suite')
    parser.add_argument('--platform', choices=tuple(END2END_DRIVERS), default='linux',
                        help='the router of an end2end comparison: linux (Docker) or freebsd (pf in QEMU)')
    parser.add_argument('--results', nargs=2, type=Path, metavar=('MASTER', 'CANDIDATE'),
                        help='run nothing: compare the status-data.json of two ended wire runs of --platform')
    parser.add_argument('--case', action='append', default=[], help='select one YAML case; repeatable')
    parser.add_argument('--profile', default='baseline', help='explicit YAML server fixture profile (wire)')
    parser.add_argument('--wan-peer', action='store_true', help='enable isolated WAN TCP/UDP traffic fixture (wire)')
    parser.add_argument('--capture', action='store_true',
                        help='also collect pcaps and decoded wire-field comparisons (wire; default: no capture)')
    args = parser.parse_args()
    if args.results and (args.suite != 'wire' or args.capture or args.wan_peer or args.case):
        parser.error('--results compares whole wire runs which ended')
    if args.suite == 'end2end' and (args.capture or args.wan_peer or args.profile != 'baseline'):
        parser.error('--capture, --wan-peer and --profile belong to the wire suite')
    output = args.output.resolve()
    if output.exists():
        parser.error('--output must be a new directory to avoid reusing stale results')
    output.mkdir(parents=True)
    commits, runs, errors = {}, {}, []
    with tempfile.TemporaryDirectory(prefix='pcp-branch-comparison-') as temporary:
        harness_snapshot = Path(temporary) / 'tests'
        shutil.copytree(HERE.parent, harness_snapshot, ignore=UNTRACKED)
        corpus = ('pcp_wire/pcp-wire-cases.yaml' if args.suite == 'wire' else 'pcp_e2e/pcp-e2e-cases.yaml')
        corpus_digest = hashlib.sha256((harness_snapshot / corpus).read_bytes()).hexdigest()
        for index, (label, source) in enumerate((('master', args.master_source), ('candidate', args.candidate_source))):
            try:
                if args.results:
                    commits[label] = command_output(['git', '-C', str(source), 'rev-parse', 'HEAD'])
                    runs[label] = read_status_results(args.results[index] / 'status-data.json', args.platform,
                                                      corpus_digest)
                    continue
                tree = Path(temporary) / label
                commits[label] = prepare_tree(source.resolve(), tree, harness_snapshot)
                if args.suite == 'wire':
                    runs[label] = run_one(label, tree, output, args.case, args.capture, args.profile, args.wan_peer)
                else:
                    runs[label] = run_end2end(label, tree, output, args.case, args.platform)
                if runs[label][1] != corpus_digest:
                    raise ValueError('run did not use the selected candidate corpus')
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                errors.append((label, str(error)))
    manifest = {'version': 1, 'suite': args.suite, 'platform': args.platform, 'commits': commits,
                'corpus_sha256': corpus_digest, 'cases': args.case, 'profile': args.profile,
                'capture': args.capture, 'wan_peer': args.wan_peer, 'errors': errors}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    title = 'PCP/NAT-PMP (wire)' if args.suite == 'wire' else f'PCP end-to-end ({args.platform})'
    if args.results:
        title = f'PCP/NAT-PMP (wire, {args.platform})'
    report = dict(title=title, reproduce=args.suite == 'wire' and not args.results)
    try:
        code = make_report(output, commits, runs, errors, args.case, args.profile, args.wan_peer, **report)
    except (OSError, ValueError, KeyError) as error:
        code = make_report(output, commits, runs, [('comparison', str(error))], **report)
    print(f'Comparison report: {output / "summary.md"}', flush=True)
    return code


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Run the same Docker PCP/NAT-PMP corpus on master and a candidate checkout."""

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

from compare_pcaps import cell, load_capture, markdown
from testpcp_natpmp import is_filtered_skip
HARNESS = Path('miniupnpd/tests/pcp_pmp')
STATUSES = {'PASS', 'FAIL', 'XFAIL', 'SKIP'}


def command_output(command):
    return subprocess.check_output(command, text=True).strip()


def prepare_tree(source, destination, harness_source=HERE):
    """Build committed daemon sources with exactly this invocation's harness."""
    archive = subprocess.check_output(['git', '-C', str(source), 'archive', 'HEAD'])
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
        tree.extractall(destination, filter='data')
    harness = destination / HARNESS
    if harness.exists():
        shutil.rmtree(harness)
    shutil.copytree(harness_source, harness, ignore=shutil.ignore_patterns('__pycache__', 'status.md'))
    common = destination / HARNESS.parent / 'common'
    if common.exists():
        shutil.rmtree(common)
    shutil.copytree(harness_source.parent / 'common', common,
                    ignore=shutil.ignore_patterns('__pycache__'))
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
               PCP_TEST_IMAGE=f'miniupnpd-pcp-compare-{label}:local',
               PCP_TEST_KEEP_CONTAINER='0')
    # Use the harness defaults for container/network isolation and its timestamp.
    for name in ('PCP_TEST_CONTAINER', 'PCP_TEST_NETWORK', 'PCP_TEST_CAPTURE_TIMESTAMP'):
        env.pop(name, None)
    command = ['./miniupnpd/tests/pcp_pmp/testpcp_natpmp_docker.sh', '--profile', profile]
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
        'python3 miniupnpd/tests/pcp_pmp/tools/compare_branches.py \\',
        '  --master-source .tmp/pcp-master \\',
        '  --candidate-source .tmp/pcp-candidate \\',
        '  --output .tmp/pcp-local-details --capture --profile ' + shlex.quote(profile) +
        (' --wan-peer' if wan_peer else '') +
        ''.join(' --case ' + shlex.quote(name) for name in cases),
        '```', '',
        'Use --case CASE_NAME to focus on one case. Docker is required. '
        'This collects pcaps, tcpdump logs and decoded before/after field tables.', '',
    ]


def make_report(output, commits, runs, errors, cases=(), profile='baseline', wan_peer=False):
    lines = ['# PCP/NAT-PMP: master versus pull request', '',
             f"- Master commit: `{commits.get('master', 'unavailable')}`",
             f"- Candidate commit: `{commits.get('candidate', 'unavailable')}`", '',
             f'- Server profile: `{cell(profile)}`', '',
             'Both daemon builds use the same candidate test harness and YAML corpus. '
             'The candidate is the PR head, without a synthetic merge with master.', '']
    if errors:
        lines += ['## Infrastructure errors', '']
        lines += [f'- {cell(label)}: {cell(error)}' for label, error in errors]
        lines += ['', 'The comparison is incomplete and must not be treated as passing.', '']
        lines += local_capture_command(commits, cases, profile, wan_peer)
        (output / 'summary.md').write_text('\n'.join(lines))
        return 2
    before, before_digest = runs['master']
    after, after_digest = runs['candidate']
    if before_digest != after_digest:
        raise ValueError('master and candidate used different corpus hashes')
    transitions = compare_results(before, after)
    counts = Counter(kind for _, kind in transitions)
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
              *local_capture_command(commits, cases, profile, wan_peer),
              '## Case results', '', '| Family | Protocol / case | Master | Candidate | Change | Wire fields |',
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
    parser.add_argument('--case', action='append', default=[], help='select one YAML case; repeatable')
    parser.add_argument('--profile', default='baseline', help='explicit YAML server fixture profile')
    parser.add_argument('--wan-peer', action='store_true', help='enable isolated WAN TCP/UDP traffic fixture')
    parser.add_argument('--capture', action='store_true',
                        help='also collect pcaps and decoded wire-field comparisons (default: no capture)')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error('--output must be a new directory to avoid reusing stale results')
    output.mkdir(parents=True)
    commits, runs, errors = {}, {}, []
    with tempfile.TemporaryDirectory(prefix='pcp-branch-comparison-') as temporary:
        harness_snapshot = Path(temporary) / 'harness'
        shutil.copytree(HERE, harness_snapshot, ignore=shutil.ignore_patterns('__pycache__', 'status.md'))
        shutil.copytree(HERE.parent / 'common', Path(temporary) / 'common',
                        ignore=shutil.ignore_patterns('__pycache__'))
        corpus_digest = hashlib.sha256((harness_snapshot / 'pcp-natpmp-cases.yaml').read_bytes()).hexdigest()
        for label, source in (('master', args.master_source), ('candidate', args.candidate_source)):
            try:
                tree = Path(temporary) / label
                commits[label] = prepare_tree(source.resolve(), tree, harness_snapshot)
                runs[label] = run_one(label, tree, output, args.case, args.capture, args.profile, args.wan_peer)
                if runs[label][1] != corpus_digest:
                    raise ValueError('run did not use the selected candidate corpus')
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                errors.append((label, str(error)))
    manifest = {'version': 1, 'commits': commits, 'corpus_sha256': corpus_digest,
                'cases': args.case, 'profile': args.profile, 'capture': args.capture,
                'wan_peer': args.wan_peer, 'errors': errors}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    try:
        code = make_report(output, commits, runs, errors, args.case, args.profile, args.wan_peer)
    except (OSError, ValueError, KeyError) as error:
        code = make_report(output, commits, runs, [('comparison', str(error))])
    print(f'Comparison report: {output / "summary.md"}', flush=True)
    return code


if __name__ == '__main__':
    sys.exit(main())

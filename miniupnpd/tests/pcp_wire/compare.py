"""wire: the request / response suite on Docker (run-docker.sh), for
../common/tools/compare_daemon_branches.py (the interface is in ../common/tools/suite_compare.py)."""

import json
import os
import shlex
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'common' / 'tools'))
sys.path.insert(0, str(HERE / 'tools'))

from compare_pcap_wire_fields import load_capture, markdown  # noqa: E402
from suite_compare import STATUSES, TESTS, cell, check_exit, run_driver  # noqa: E402

SUITE = 'wire'
TITLE = 'PCP/NAT-PMP wire'
CORPUS = 'pcp-wire-cases.yaml'
PLATFORMS = ('linux',)
NOTES = 'Packet captures and wire-field comparisons are produced only with --capture.'
LINK_COLUMN = 'Wire fields'
DRIVER = TESTS / HERE.name / 'run-docker.sh'


def add_arguments(parser):
    parser.add_argument('--profile', default='baseline', help='explicit YAML server fixture profile')
    parser.add_argument('--wan-peer', action='store_true', help='enable isolated WAN TCP/UDP traffic fixture')
    parser.add_argument('--capture', action='store_true',
                        help='also collect pcaps and decoded wire-field comparisons (default: no capture)')


def check(parser, args):
    if args.results and (args.capture or args.wan_peer or args.profile != 'baseline'):
        parser.error('--results compares whole runs which ended: no --capture, --wan-peer or --profile')


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
    check_exit(outcomes, exit_code)
    return outcomes, digests.pop()


def run(label, tree, output, args):
    results_dir = output / label
    capture_root = results_dir / 'captures'
    env = dict(os.environ, PCP_TEST_CAPTURE_DIR=str(capture_root), PCP_TEST_CAPTURE='1' if args.capture else '0',
               PCP_TEST_WAN_PEER='1' if args.wan_peer else '0', PCP_TEST_RESULTS_DIR=str(results_dir),
               PCP_TEST_KEEP_CONTAINER='0')
    # Use the harness defaults for container/network isolation and its timestamp.
    for name in ('PCP_TEST_CONTAINER', 'PCP_TEST_NETWORK', 'PCP_TEST_CAPTURE_TIMESTAMP'):
        env.pop(name, None)
    command = [f'./{DRIVER}', '--profile', args.profile]
    if args.capture:
        command += ['--capture-name', label]
    for name in args.case:
        command += ['--case', name]
    exit_code = run_driver(label, tree, results_dir, command, env)
    if not (results_dir / 'status.md').is_file():
        raise ValueError(f'{label}: missing status report; see run.log')
    capture_folder = None
    if args.capture:
        folders = [path for path in capture_root.iterdir() if path.is_dir()]
        if len(folders) != 1:
            raise ValueError(f'expected one capture run folder under {capture_root}')
        capture_folder = folders[0]
    return read_results(results_dir, exit_code, capture_folder)


def report_header(args):
    return [f'- Server profile: `{cell(args.profile)}`', '']


def reproduce(commits, args):
    return [
        '## Reproduce locally with packet details', '',
        'From a checkout containing this harness, fetch the commits above if needed and run '
        '(the worktree and output directories must be new):', '',
        '```sh',
        'git worktree add --detach .tmp/pcp-master ' + shlex.quote(commits.get('master', 'MASTER_COMMIT')),
        'git worktree add --detach .tmp/pcp-candidate ' + shlex.quote(commits.get('candidate', 'PR_COMMIT')),
        'python3 miniupnpd/tests/common/tools/compare_daemon_branches.py --suite wire \\',
        '  --master-source .tmp/pcp-master \\',
        '  --candidate-source .tmp/pcp-candidate \\',
        '  --output .tmp/pcp-local-details --capture --profile ' + shlex.quote(args.profile) +
        (' --wan-peer' if args.wan_peer else '') +
        ''.join(' --case ' + shlex.quote(name) for name in args.case),
        '```', '',
        'Use --case CASE_NAME to focus on one case. Docker is required. '
        'This collects pcaps, tcpdump logs and decoded before/after field tables.', '',
    ]


def case_link(output, key, before, after):
    """The decoded wire fields of a case captured in both runs, side by side."""
    if 'pcap' not in before or 'pcap' not in after:
        return ''
    comparisons = output / 'comparisons'
    comparisons.mkdir(exist_ok=True)
    filename = f"{key[0]}-{key[1]}-{key[2].replace('/', '_')}.md"
    left, ln = load_capture(before['pcap'], 5351)
    right, rn = load_capture(after['pcap'], 5351)
    # Relative capture paths make the downloaded artifact self-contained.
    report = markdown(Path('..') / before['pcap'].relative_to(output), Path('..') / after['pcap'].relative_to(output),
                      left, right, (ln, rn), False)
    (comparisons / filename).write_text(report)
    return f'[compare](comparisons/{filename})'

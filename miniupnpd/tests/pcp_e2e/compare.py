"""end2end: the forwarding suite, on Docker (run-docker.sh) or with a FreeBSD pf router in QEMU
(run-freebsd.sh), for ../common/tools/compare_daemon_branches.py (the interface is in
../common/tools/suite_compare.py)."""

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'common' / 'tools'))

from suite_compare import STATUSES, TESTS, check_exit, digest, run_driver  # noqa: E402

SUITE = 'end2end'
TITLE = 'PCP end-to-end'
CORPUS = 'pcp-e2e-cases.yaml'
DRIVERS = {'linux': 'run-docker.sh', 'freebsd': 'run-freebsd.sh'}
PLATFORMS = tuple(DRIVERS)


def read_results(artifacts, log_text, exit_code, corpus_digest):
    """The cases of a driver run: the rows of its results.tsv (family, section, case, result, note), keyed
    (family, section, case), and the lease-restart check of run-freebsd.sh as a case of its own (its
    PASS / FAIL restart line)."""
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
    check_exit(outcomes, exit_code)
    return outcomes, corpus_digest


def run(label, tree, output, args):
    folder = output / label
    env = dict(os.environ, PCP_E2E_ARTIFACT_DIR=str(folder / 'artifacts'), E2E_STATUS_FILE=str(folder / 'status.md'),
               E2E_STATUS_DATA_FILE=str(folder / 'status-data.json'), PCP_TEST_SELF_TEST='0')
    command = [f'./{TESTS / HERE.name / DRIVERS[args.platform]}']
    for name in args.case:
        command += ['--case', name]
    exit_code = run_driver(f'{label} ({args.platform})', tree, folder, command, env)
    return read_results(folder / 'artifacts', (folder / 'run.log').read_text(), exit_code,
                        digest(tree / TESTS / HERE.name / CORPUS))

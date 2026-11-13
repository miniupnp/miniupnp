"""daemon_options: the daemon configurations, on Docker (run-docker.sh) or in a FreeBSD VM with pf
(run-freebsd.sh), for ../common/tools/compare_daemon_branches.py (the interface is in
../common/tools/suite_compare.py)."""

import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'common' / 'tools'))

from suite_compare import TESTS, digest, read_status_results, run_driver  # noqa: E402

SUITE = 'daemon_options'
TITLE = 'Daemon options'
CORPUS = 'daemon-options-cases.yaml'
DRIVERS = {'linux': 'run-docker.sh', 'freebsd': 'run-freebsd.sh'}
PLATFORMS = tuple(DRIVERS)
# where a driver leaves its results and daemon logs in the tree it ran in
RESULTS = Path('.tmp/tests/daemon_options')
LOGS = {'linux': Path('.tmp/daemon-options'), 'freebsd': Path('.tmp/ci/out/freebsd/daemon_options')}


def run(label, tree, output, args):
    """A driver that fails without a FAIL among its results (a build, a fixture) is an error."""
    folder = output / label
    suite = TESTS / HERE.name
    command = [f'./{suite / DRIVERS[args.platform]}']
    for name in args.case:
        command += ['--case', name]
    exit_code = run_driver(f'{label} ({args.platform})', tree, folder, command, dict(os.environ, PCP_TEST_SELF_TEST='0'))
    data = tree / RESULTS / 'status-data.json'
    if not data.is_file():
        raise ValueError(f'{label}: the driver wrote no results (exit {exit_code}); see {folder / "run.log"}')
    shutil.copy2(data, folder / 'status-data.json')
    shutil.copy2(tree / suite / 'status.md', folder / 'status.md')
    if (tree / LOGS[args.platform]).is_dir():
        shutil.copytree(tree / LOGS[args.platform], folder / 'daemon-logs')
    outcomes, corpus_digest = read_status_results(folder / 'status-data.json', args.platform,
                                                  digest(tree / suite / CORPUS))
    if exit_code != 0 and not any(item['status'] == 'FAIL' for item in outcomes.values()):
        raise ValueError(f'{label}: the driver failed (exit {exit_code}) with no failed case; '
                         f'see {folder / "run.log"}')
    return outcomes, corpus_digest

"""upnp-e2e: the UPnP IGD end-to-end suite on Docker (run-docker.sh), every build (igd1,
igd2), for ../common/tools/compare_daemon_branches.py (the interface is in
../common/tools/suite_compare.py)."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'common' / 'tools'))

from suite_compare import run_build_driver  # noqa: E402

SUITE = 'upnp-e2e'
TITLE = 'UPnP end-to-end'
CORPUS = 'upnp-e2e-cases.yaml'
PLATFORMS = ('linux',)


def run(label, tree, output, args):
    return run_build_driver(HERE, label, tree, output, args, 'run-docker.sh', CORPUS, 'UPNP_E2E')

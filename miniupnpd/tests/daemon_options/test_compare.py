#!/usr/bin/env python3
"""Offline checks of compare.py: it runs the suite's driver in the tree and reads the status data the
driver leaves there."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import compare  # noqa: E402
from suite_compare import TESTS  # noqa: E402  (compare.py put common/tools on the path)


def tree(root, script):
    suite = root / TESTS / HERE.name
    suite.mkdir(parents=True)
    (suite / compare.CORPUS).write_text('version: 1\n')
    driver = suite / compare.DRIVERS['linux']
    driver.write_text('#!/bin/sh\n' + script)
    driver.chmod(0o755)
    return root


def results(status, exit_code):
    data = json.dumps({'version': 1, 'platforms': {'linux': {'results': {'ipv4': {'pcp/a': [status, 'why']}}}}})
    return (f"mkdir -p {compare.RESULTS} {compare.LOGS['linux']}/run\n"
            f"echo '{data}' > {compare.RESULTS}/status-data.json\n"
            f"echo report > {TESTS / HERE.name}/status.md\n"
            f"echo log > {compare.LOGS['linux']}/run/miniupnpd.log\nexit {exit_code}\n")


class DaemonOptionsComparisonTests(unittest.TestCase):
    def run_options(self, root, script):
        with contextlib.redirect_stdout(io.StringIO()):
            return compare.run('master', tree(root / 'tree', script), root / 'out',
                               Namespace(platform='linux', case=[]))

    def test_results_status_and_logs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outcomes, digest = self.run_options(root, results('FAIL', 1))
            self.assertEqual(outcomes[('ipv4', 'pcp', 'a')], {'status': 'FAIL', 'detail': 'why'})
            self.assertEqual(len(digest), 64)
            self.assertEqual((root / 'out/master/status.md').read_text(), 'report\n')
            self.assertTrue((root / 'out/master/daemon-logs/run/miniupnpd.log').is_file())

    def test_a_driver_without_results_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'wrote no results'):
                self.run_options(Path(temporary), 'echo FAIL: build\nexit 1\n')

    def test_a_failed_driver_without_a_failed_case_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'no failed case'):
                self.run_options(Path(temporary), results('PASS', 1))


if __name__ == '__main__':
    unittest.main()

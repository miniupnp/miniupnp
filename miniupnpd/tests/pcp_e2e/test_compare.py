#!/usr/bin/env python3
"""Offline checks of compare.py: the results of an end2end driver run."""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import compare  # noqa: E402
import compare_daemon_branches as tool  # noqa: E402  (compare.py put common/tools on the path)


def artifacts(root, rows):
    run = root / 'artifacts' / 'freebsd-run'
    run.mkdir(parents=True)
    (run / 'results.tsv').write_text(''.join('\t'.join(row) + '\t.\n' for row in rows))
    return root / 'artifacts'


class End2endComparisonTests(unittest.TestCase):
    def test_results_and_the_restart_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = artifacts(Path(temporary), [('ipv4', 'MAP', 'map-a', 'PASS', 'ok'),
                                                 ('ipv6', 'NAT', 'nat-b', 'FAIL', 'timed out')])
            log = 'x\nFAIL restart: the rules changed\n'
            outcomes, digest = compare.read_results(folder, log, 1, 'sha')
            self.assertEqual(digest, 'sha')
            self.assertEqual(outcomes[('ipv6', 'NAT', 'nat-b')], {'status': 'FAIL', 'detail': 'timed out'})
            self.assertEqual(outcomes[('both', 'restart', 'lease-file')]['status'], 'FAIL')
            with self.assertRaisesRegex(ValueError, 'disagrees'):
                compare.read_results(folder, log, 0, 'sha')

    def test_a_run_without_results_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'expected one results.tsv'):
                compare.read_results(Path(temporary), '', 0, 'sha')

    def test_regression_between_two_runs(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            master = compare.read_results(artifacts(root / 'm', [('ipv4', 'MAP', 'map-a', 'PASS', '')]), '', 0, 'sha')
            candidate = compare.read_results(artifacts(root / 'c', [('ipv4', 'MAP', 'map-a', 'FAIL', 'no')]), '', 1,
                                             'sha')
            code = tool.make_report(root, {}, {'master': master, 'candidate': candidate}, [],
                                    'PCP end-to-end (linux)', compare)
            self.assertEqual(code, 1)
            summary = (root / 'summary.md').read_text()
        self.assertIn('# PCP end-to-end (linux): master versus pull request', summary)
        self.assertIn('| ipv4 | MAP/map-a | PASS | FAIL | regression |', summary)
        self.assertNotIn('git worktree add', summary)
        self.assertNotIn('Server profile', summary)


if __name__ == '__main__':
    unittest.main()

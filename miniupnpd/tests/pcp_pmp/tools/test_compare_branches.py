#!/usr/bin/env python3
"""Offline checks for regression classification and complete CI evidence."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import compare_branches as compare
from test_compare_pcaps import pcap_file, pcp, udp_packet


class BranchComparisonTests(unittest.TestCase):
    def fixture(self, root, statuses=('PASS', 'FAIL', 'SKIP')):
        folder = root
        folder.mkdir(parents=True, exist_ok=True)
        for family in ('ipv4', 'ipv6'):
            cases = []
            for i, status in enumerate(statuses):
                name = f'case-{i}'
                cases.append({'protocol': 'pcp', 'name': name, 'status': status, 'detail': ''})
                if status != 'SKIP':
                    path = folder / f'{family}-pcp-{name}.pcap'
                    path.write_bytes(pcap_file(udp_packet(pcp(response=True))))
                    path.with_suffix('.tcpdump.log').write_text('capture complete\n')
            report = {'version': 1, 'family': family, 'corpus_sha256': 'test-digest', 'cases': cases}
            (folder / f'results-{family}.json').write_text(json.dumps(report))
        return folder

    def test_transitions(self):
        for after in ('FAIL', 'XFAIL', 'SKIP'):
            self.assertEqual(compare.transition('PASS', after), 'regression')
        self.assertEqual(compare.transition('FAIL', 'FAIL'), 'unchanged')
        self.assertEqual(compare.transition('XFAIL', 'FAIL'), 'regression')
        self.assertEqual(compare.transition('FAIL', 'SKIP'), 'regression')
        self.assertEqual(compare.transition('FAIL', 'PASS'), 'improvement')
        self.assertEqual(compare.transition('XFAIL', 'PASS'), 'improvement')
        self.assertEqual(compare.transition('SKIP', 'FAIL'), 'new coverage')
        self.assertEqual(compare.transition('SKIP', 'PASS'), 'improvement')

    def test_complete_results_and_failure_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            outcomes, digest = compare.read_results(root, 1)
            self.assertEqual(len(outcomes), 6)
            self.assertEqual(digest, 'test-digest')
            with self.assertRaisesRegex(ValueError, 'disagrees'):
                compare.read_results(root, 0)

    def test_missing_reports_and_captures_are_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = self.fixture(root)
            (folder / 'results-ipv6.json').unlink()
            with self.assertRaises(OSError):
                compare.read_results(root, 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = self.fixture(root)
            (folder / 'ipv4-pcp-case-0.pcap').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'incomplete capture'):
                compare.read_results(root, 1, root)

    def test_corpus_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = self.fixture(root)
            p = folder / 'results-ipv6.json'
            value = json.loads(p.read_text())
            value['corpus_sha256'] = 'different-digest'
            p.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'different corpora'):
                compare.read_results(root, 1)

    def test_all_skipped_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root, ('SKIP',))
            with self.assertRaisesRegex(ValueError, 'no cases executed'):
                compare.read_results(root, 0)

    def test_case_identity_mismatch(self):
        with self.assertRaisesRegex(ValueError, 'different case identities'):
            compare.compare_results({'one': {'status': 'PASS'}}, {'two': {'status': 'PASS'}})

    def test_unchanged_failures_do_not_fail_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root / 'master' / 'captures')
            self.fixture(root / 'candidate' / 'captures')
            master = compare.read_results(root / 'master' / 'captures', 1, root / 'master' / 'captures')
            candidate = compare.read_results(root / 'candidate' / 'captures', 1, root / 'candidate' / 'captures')
            code = compare.make_report(root, {}, {'master': master, 'candidate': candidate}, [])
            self.assertEqual(code, 0)
            summary = (root / 'summary.md').read_text()
            self.assertIn('Regressions: **0**', summary)
            self.assertEqual(len(list((root / 'comparisons').glob('*.md'))), 4)
            self.assertNotIn(str(root), next((root / 'comparisons').glob('*.md')).read_text())

    def test_regressions_fail_and_improvements_pass(self):
        for old, new, expected in [('PASS', 'FAIL', 1), ('FAIL', 'PASS', 0)]:
            with self.subTest(old=old, new=new), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root / 'master' / 'captures', (old,))
                self.fixture(root / 'candidate' / 'captures', (new,))
                master = compare.read_results(root / 'master' / 'captures', int(old == 'FAIL'))
                candidate = compare.read_results(root / 'candidate' / 'captures', int(new == 'FAIL'))
                code = compare.make_report(root, {}, {'master': master, 'candidate': candidate}, [])
                self.assertEqual(code, expected)

    def test_infrastructure_error_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(compare.make_report(root, {}, {}, [('master', 'build failed')]), 2)
            self.assertIn('build failed', (root / 'summary.md').read_text())

    def test_results_without_packet_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label in ('master', 'candidate'):
                folder = self.fixture(root / label)
                for pattern in ('*.pcap', '*.tcpdump.log'):
                    for path in folder.glob(pattern):
                        path.unlink()
            master = compare.read_results(root / 'master', 1)
            candidate = compare.read_results(root / 'candidate', 1)
            self.assertFalse(any('pcap' in case for case in master[0].values()))
            code = compare.make_report(root, {'master': 'abc', 'candidate': 'def'},
                                       {'master': master, 'candidate': candidate}, [], ['case-0'])
            self.assertEqual(code, 0)
            self.assertFalse((root / 'comparisons').exists())
            summary = (root / 'summary.md').read_text()
            self.assertIn('git worktree add --detach .tmp/pcp-master abc', summary)
            self.assertIn('--capture --profile baseline --case case-0', summary)

    def test_no_capture_run_omits_capture_options(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def run(command, cwd, env, stdout, stderr):
                self.assertNotIn('--capture-name', command)
                self.assertEqual(env['PCP_TEST_CAPTURE'], '0')
                folder = self.fixture(Path(env['PCP_TEST_RESULTS_DIR']), ('PASS',))
                (folder / 'status.md').write_text('complete\n')
                for pattern in ('*.pcap', '*.tcpdump.log'):
                    for path in folder.glob(pattern):
                        path.unlink()
                return type('Result', (), {'returncode': 0})()

            with patch.object(compare.subprocess, 'run', side_effect=run):
                result, _ = compare.run_one('master', root, root, [], False)
            self.assertEqual(len(result), 2)
            self.assertFalse((root / 'master' / 'captures').exists())

    def test_filtered_skips_are_hidden_but_prerequisites_remain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = {
                ('ipv6', 'pcp', 'announce'): {'status': 'PASS', 'detail': ''},
                ('ipv6', 'natpmp', 'public-address'): {
                    'status': 'SKIP', 'detail': 'excluded by --protocol filter'},
                ('ipv6', 'pcp', 'ipv4-only'): {
                    'status': 'SKIP', 'detail': 'excluded by --family filter'},
                ('ipv6', 'pcp', 'unselected'): {
                    'status': 'SKIP', 'detail': 'not selected by --case'},
                ('ipv6', 'pcp', 'blocked'): {
                    'status': 'SKIP', 'detail': 'prerequisite did not pass: probe (XFAIL)'},
            }
            result = (cases, 'same-corpus')
            self.assertEqual(compare.make_report(root, {}, {'master': result, 'candidate': result}, []), 0)
            summary = (root / 'summary.md').read_text()
            self.assertIn('| Master | 1 | 0 | 0 | 1 |', summary)
            self.assertIn('pcp/blocked', summary)
            for name in ('natpmp/public-address', 'pcp/ipv4-only', 'pcp/unselected'):
                self.assertNotIn(name, summary)

    def test_a_newly_filtered_case_is_still_a_visible_regression(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = ('ipv6', 'pcp', 'previously-passing')
            before = ({key: {'status': 'PASS', 'detail': ''}}, 'same-corpus')
            after = ({key: {'status': 'SKIP', 'detail': 'excluded by --family filter'}}, 'same-corpus')
            self.assertEqual(compare.make_report(root, {}, {'master': before, 'candidate': after}, []), 1)
            summary = (root / 'summary.md').read_text()
            self.assertIn('pcp/previously-passing | PASS | SKIP | regression', summary)


if __name__ == '__main__':
    unittest.main()

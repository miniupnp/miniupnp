#!/usr/bin/env python3
"""Offline checks of the suite-independent part: regression classification, the report, the status data
of ended runs, and finding the suites. Each suite's compare.py has a test_compare.py beside it."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import compare_daemon_branches as compare
import suite_compare

SUITE = '''
SUITE = {name!r}
TITLE = 'Stand-in'
CORPUS = 'cases.yaml'
PLATFORMS = ('linux',)


def add_arguments(parser):
    parser.add_argument('--{name}-only', action='store_true')


def run(label, tree, output, args):
    return {{}}, ''
'''


def suites_dir(root, *names):
    for directory, name in names:
        (root / directory).mkdir(parents=True)
        (root / directory / 'compare.py').write_text(SUITE.format(name=name))
    return root


def report(root, master, candidate, suite=None):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        code = compare.make_report(root, {}, {'master': master, 'candidate': candidate}, [], 'Stand-in (linux)',
                                   suite)
    return code, (root / 'summary.md').read_text(), out.getvalue()


class ClassificationTests(unittest.TestCase):
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

    def test_case_identity_mismatch(self):
        with self.assertRaisesRegex(ValueError, 'different case identities'):
            compare.compare_results({'one': {'status': 'PASS'}}, {'two': {'status': 'PASS'}})


class ReportTests(unittest.TestCase):
    def test_the_report_names_each_regression_and_why(self):
        master = ({('ipv4', 'pcp', 'lost'): {'status': 'PASS', 'detail': ''},
                   ('ipv4', 'pcp', 'known'): {'status': 'FAIL', 'detail': 'old'}}, 'digest')
        candidate = ({('ipv4', 'pcp', 'lost'): {'status': 'FAIL', 'detail': 'result code 8'},
                      ('ipv4', 'pcp', 'known'): {'status': 'FAIL', 'detail': 'old'}}, 'digest')
        with tempfile.TemporaryDirectory() as temporary:
            code, summary, out = report(Path(temporary), master, candidate)
        self.assertEqual(code, 1)
        self.assertIn('Regressions: 1\nREGRESSION ipv4 pcp/lost: PASS -> FAIL: result code 8\n', out)
        self.assertNotIn('known', out)
        self.assertIn('| ipv4 | pcp/lost | PASS | FAIL | result code 8 |', summary)
        self.assertLess(summary.index('## Regressions'), summary.index('## Case results'))
        self.assertIn('| Family | Protocol / case | Master | Candidate | Change |\n', summary)

    def test_filtered_skips_are_hidden_but_prerequisites_remain(self):
        cases = {
            ('ipv6', 'pcp', 'announce'): {'status': 'PASS', 'detail': ''},
            ('ipv6', 'natpmp', 'public-address'): {'status': 'SKIP', 'detail': 'excluded by --protocol filter'},
            ('ipv6', 'pcp', 'ipv4-only'): {'status': 'SKIP', 'detail': 'excluded by --family filter'},
            ('ipv6', 'pcp', 'unselected'): {'status': 'SKIP', 'detail': 'not selected by --case'},
            ('ipv6', 'pcp', 'blocked'): {'status': 'SKIP', 'detail': 'prerequisite did not pass: probe (XFAIL)'},
        }
        with tempfile.TemporaryDirectory() as temporary:
            code, summary, _ = report(Path(temporary), (cases, 'same'), (cases, 'same'))
        self.assertEqual(code, 0)
        self.assertIn('| Master | 1 | 0 | 0 | 1 |', summary)
        self.assertIn('pcp/blocked', summary)
        for name in ('natpmp/public-address', 'pcp/ipv4-only', 'pcp/unselected'):
            self.assertNotIn(name, summary)

    def test_a_newly_filtered_case_is_still_a_visible_regression(self):
        key = ('ipv6', 'pcp', 'previously-passing')
        before = ({key: {'status': 'PASS', 'detail': ''}}, 'same')
        after = ({key: {'status': 'SKIP', 'detail': 'excluded by --family filter'}}, 'same')
        with tempfile.TemporaryDirectory() as temporary:
            code, summary, _ = report(Path(temporary), before, after)
        self.assertEqual(code, 1)
        self.assertIn('pcp/previously-passing | PASS | SKIP | regression', summary)

    def test_the_suite_adds_its_notes_and_a_link_column(self):
        suite = SimpleNamespace(NOTES='Stand-in note.', LINK_COLUMN='Detail',
                                case_link=lambda output, key, a, b: f'[{key[2]}](x)')
        result = ({('ipv4', 'pcp', 'a'): {'status': 'PASS', 'detail': ''}}, 'same')
        with tempfile.TemporaryDirectory() as temporary:
            _, summary, _ = report(Path(temporary), result, result, suite)
        self.assertIn('JSON results. Stand-in note.', summary)
        self.assertIn('| Change | Detail |', summary)
        self.assertIn('| unchanged | [a](x) |', summary)

    def test_infrastructure_error_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(compare.make_report(root, {}, {}, [('master', 'build failed')], 'Stand-in'), 2)
            self.assertIn('build failed', (root / 'summary.md').read_text())


class StatusDataTests(unittest.TestCase):
    def status_data(self, path, results):
        path.mkdir()
        (path / 'status-data.json').write_text(json.dumps(
            {'version': 1, 'platforms': {'freebsd': {'results': {'ipv4': results}}}}))
        return path / 'status-data.json'

    def test_status_data_of_ended_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = self.status_data(Path(temporary) / 'run', {'pcp/a': ['FAIL', 'boom'], 'natpmp/b': ['PASS', '']})
            outcomes, digest = suite_compare.read_status_results(data, 'freebsd', 'digest')
        self.assertEqual(digest, 'digest')
        self.assertEqual(outcomes[('ipv4', 'pcp', 'a')], {'status': 'FAIL', 'detail': 'boom'})
        self.assertEqual(outcomes[('ipv4', 'natpmp', 'b')]['status'], 'PASS')

    def test_status_data_without_a_run_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = self.status_data(Path(temporary) / 'run', {'pcp/a': ['SKIP', 'not selected by --case']})
            with self.assertRaisesRegex(ValueError, 'no cases executed'):
                suite_compare.read_status_results(data, 'freebsd', 'digest')
            with self.assertRaises(KeyError):
                suite_compare.read_status_results(data, 'linux', 'digest')


class SuiteTests(unittest.TestCase):
    def test_each_suite_directory_with_a_compare_py_is_a_suite(self):
        with tempfile.TemporaryDirectory() as temporary:
            suites = compare.load_suites(suites_dir(Path(temporary), ('first_dir', 'one'), ('second_dir', 'two')))
        self.assertEqual(sorted(suites), ['one', 'two'])
        self.assertEqual(suites['two'].DIR, 'second_dir')

    def test_two_suites_of_one_name_are_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'two suites are named one'):
                compare.load_suites(suites_dir(Path(temporary), ('a', 'one'), ('b', 'one')))

    def test_the_tree_has_suites(self):
        self.assertTrue(compare.load_suites())

    def parse(self, suites, *argv):
        with contextlib.redirect_stderr(io.StringIO()):
            return compare.parse_args(suites, ['--master-source', 'm', '--candidate-source', 'c',
                                               '--output', '/nonexistent/out', *argv])

    def test_options_belong_to_the_chosen_suite(self):
        with tempfile.TemporaryDirectory() as temporary:
            suites = compare.load_suites(suites_dir(Path(temporary), ('a', 'one'), ('b', 'two')))
            suite, args = self.parse(suites, '--suite', 'one', '--one-only')
            self.assertEqual(suite.SUITE, 'one')
            self.assertTrue(args.one_only)
            with self.assertRaises(SystemExit):
                self.parse(suites, '--suite', 'two', '--one-only')
            with self.assertRaises(SystemExit):
                self.parse(suites, '--one-only')

    def test_a_platform_the_suite_does_not_run_on(self):
        with tempfile.TemporaryDirectory() as temporary:
            suites = compare.load_suites(suites_dir(Path(temporary), ('a', 'one')))
            suites['other'] = SimpleNamespace(SUITE='other', PLATFORMS=('freebsd',))
            with self.assertRaises(SystemExit):
                self.parse(suites, '--suite', 'one', '--platform', 'freebsd')
            # an ended run is read for any platform, but whole
            _, args = self.parse(suites, '--suite', 'one', '--platform', 'freebsd', '--results', 'a', 'b')
            self.assertEqual(args.platform, 'freebsd')
            with self.assertRaises(SystemExit):
                self.parse(suites, '--suite', 'one', '--results', 'a', 'b', '--case', 'x')


if __name__ == '__main__':
    unittest.main()

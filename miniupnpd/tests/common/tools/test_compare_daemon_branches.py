#!/usr/bin/env python3
"""Offline checks of the suite-independent part: regression classification, the report, the status data
of ended runs, and finding the suites. Each suite's compare.py has a test_compare.py beside it."""

import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock
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


def review(root, master, candidate):
    """The review.md of a report, with its summary.md and output left out."""
    report(root, master, candidate)
    return (root / 'review.md').read_text()


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
        self.assertIn('Regressions: 1. Improvements: 0.\nREGRESSION ipv4 pcp/lost: PASS -> FAIL: result code 8\n',
                      out)
        self.assertNotIn('known', out)
        self.assertIn('| ipv4 | pcp/lost | PASS | FAIL | result code 8 |', summary)
        self.assertLess(summary.index('## Regressions'), summary.index('## Case results'))
        self.assertIn('| Family | Protocol / case | Master | Candidate | Change |\n', summary)

    def test_the_report_names_each_improvement(self):
        master = ({('ipv4', 'pcp', 'fixed'): {'status': 'FAIL', 'detail': 'result code 8'},
                   ('ipv4', 'pcp', 'lost'): {'status': 'PASS', 'detail': ''}}, 'digest')
        candidate = ({('ipv4', 'pcp', 'fixed'): {'status': 'PASS', 'detail': ''},
                      ('ipv4', 'pcp', 'lost'): {'status': 'FAIL', 'detail': 'timeout'}}, 'digest')
        with tempfile.TemporaryDirectory() as temporary:
            code, summary, out = report(Path(temporary), master, candidate)
        self.assertEqual(code, 1)
        self.assertIn('IMPROVEMENT ipv4 pcp/fixed: FAIL -> PASS: \n', out)
        self.assertIn('## Improvements', summary)
        self.assertLess(summary.index('## Regressions'), summary.index('## Improvements'))
        self.assertLess(summary.index('## Improvements'), summary.index('## Case results'))
        self.assertIn('| ipv4 | pcp/fixed | FAIL | PASS |  |', summary)

    def test_the_review_holds_the_counts_and_both_lists_only(self):
        unchanged = {'status': 'FAIL', 'detail': 'old'}
        master = ({('ipv4', 'pcp', 'fixed'): {'status': 'XFAIL', 'detail': 'no feature'},
                   ('ipv4', 'pcp', 'lost'): {'status': 'PASS', 'detail': ''},
                   ('ipv4', 'pcp', 'known'): unchanged,
                   ('ipv4', 'pcp', 'unblocked'): {'status': 'SKIP', 'detail': 'prerequisite did not pass'}}, 'digest')
        candidate = ({('ipv4', 'pcp', 'fixed'): {'status': 'PASS', 'detail': ''},
                      ('ipv4', 'pcp', 'lost'): {'status': 'FAIL', 'detail': 'timeout'},
                      ('ipv4', 'pcp', 'known'): unchanged,
                      ('ipv4', 'pcp', 'unblocked'): {'status': 'FAIL', 'detail': 'gap'}}, 'digest')
        with tempfile.TemporaryDirectory() as temporary:
            text = review(Path(temporary), master, candidate)
        self.assertTrue(text.startswith('Regressions: 1. Improvements: 1. New coverage: 1. Other changes: 0. '
                                        'Unchanged: 1.\n\n'
                                        '<details open>\n'
                                        '<summary>🔴 Regressions: 1 case</summary>\n\n'))
        self.assertIn('| 🔴 pcp/lost |  | PASS | FAIL | timeout | ipv4 |', text)
        self.assertIn('<details>\n<summary>Improvements: 1 case</summary>\n\n', text)
        self.assertIn('| pcp/fixed |  | XFAIL | PASS |  | ipv4 |', text)
        self.assertIn('<details>\n<summary>New coverage: 1 case</summary>\n\n', text)
        self.assertIn('| pcp/unblocked |  | SKIP | FAIL | gap | ipv4 |', text)
        self.assertNotIn('known', text)

    def test_the_review_has_one_row_per_case_and_outcome(self):
        lost = {'status': 'FAIL', 'detail': 'fault 714'}
        keys = [('igd1 ipv4', 'upnp', 'walk'), ('igd2 ipv4', 'upnp', 'walk'), ('igd2 ipv6', 'upnp', 'walk')]
        master = ({key: {'status': 'PASS', 'detail': ''} for key in keys}, 'digest')
        candidate = ({**{key: lost for key in keys[:2]}, keys[2]: {'status': 'FAIL', 'detail': 'timeout'}},
                     'digest')
        with tempfile.TemporaryDirectory() as temporary:
            text = review(Path(temporary), master, candidate)
        self.assertIn('| 🔴 upnp/walk |  | PASS | FAIL | fault 714 | igd1 ipv4, igd2 ipv4 |', text)
        self.assertIn('| 🔴 upnp/walk |  | PASS | FAIL | timeout | igd2 ipv6 |', text)

    def test_a_review_without_changes_has_the_counts_only(self):
        result = ({('ipv4', 'pcp', 'a'): {'status': 'PASS', 'detail': ''},
                   ('ipv4', 'pcp', 'b'): {'status': 'SKIP', 'detail': 'excluded by --family filter'}}, 'same')
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(review(Path(temporary), result, result),
                             'Regressions: 0. Improvements: 0. New coverage: 0. Other changes: 0. Unchanged: 1.\n')

    def test_the_review_lists_other_changes(self):
        master = ({('ipv4', 'pcp', 'known'): {'status': 'FAIL', 'detail': 'gap'}}, 'digest')
        candidate = ({('ipv4', 'pcp', 'known'): {'status': 'XFAIL', 'detail': 'no feature'}}, 'digest')
        with tempfile.TemporaryDirectory() as temporary:
            text = review(Path(temporary), master, candidate)
        self.assertIn('Other changes: 1.', text)
        self.assertIn('| pcp/known |  | FAIL | XFAIL | no feature | ipv4 |', text)

    def test_the_review_reproduces_the_changed_cases_where_the_suite_runs(self):
        master = ({('ipv4', 'upnp', 'b'): {'status': 'PASS', 'detail': ''},
                   ('ipv6', 'upnp', 'a'): {'status': 'PASS', 'detail': ''},
                   ('ipv4', 'upnp', 'same'): {'status': 'PASS', 'detail': ''}}, 'digest')
        candidate = ({('ipv4', 'upnp', 'b'): {'status': 'FAIL', 'detail': 'x'},
                      ('ipv6', 'upnp', 'a'): {'status': 'FAIL', 'detail': 'x'},
                      ('ipv4', 'upnp', 'same'): {'status': 'PASS', 'detail': ''}}, 'digest')
        suite = SimpleNamespace(SUITE='upnp-wire', PLATFORMS=('linux',))
        commits = {'master': 'aaa', 'candidate': 'bbb'}
        for platform, shown in (('linux', True), ('freebsd', False)):
            args = SimpleNamespace(platform=platform, results=None)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with contextlib.redirect_stdout(io.StringIO()):
                    compare.make_report(root, commits, {'master': master, 'candidate': candidate}, [], 'T', suite,
                                        args)
                text = (root / 'review.md').read_text()
            self.assertEqual('<summary>Reproduce locally</summary>' in text, shown)
            if shown:
                self.assertIn('git worktree add --detach .tmp/compare-candidate bbb\n', text)
                self.assertIn('--suite upnp-wire --platform linux', text)
                self.assertIn('--output .tmp/compare-output --case a --case b\n', text)

    def test_the_review_links_the_case_and_its_spec(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'x').mkdir()
            (root / 'x' / 'cases.yaml').write_text(
                'groups:\n  - name: SOAP\n    cases:\n      - name: walk\n        ref: "WANIPC2 §2.5.17"\n'
                '      - name: http\n        ref: "RFC9112 §2.2"\n      - name: old\n        ref: "WANIPC1 §2.4"\n'
                '      - name: both\n        ref: {igd1: "WANIPC1 §2.4.14", igd2: "WANIPC2 §2.5.14"}\n')
            index = compare.case_index(root / 'x' / 'cases.yaml')
            self.assertEqual(index['walk'], (4, ('WANIPC2 §2.5.17',)))
            self.assertEqual(index['SOAP'], (2, ()))
            suite = SimpleNamespace(DIR='x', CORPUS='cases.yaml')
            environment = {'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_REPOSITORY': 'o/r'}
            with unittest.mock.patch.object(compare, 'HERE', root / 'common'), \
                 unittest.mock.patch.dict(os.environ, environment):
                source = compare.case_sources({'candidate': 'bbb'}, suite)
            self.assertEqual(source('upnp/walk', 'walk'), (
                '[upnp/walk](https://github.com/o/r/blob/bbb/miniupnpd/tests/x/cases.yaml#L4)',
                '[WANIPC2 §2.5.17](http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf)'))
            self.assertEqual(source('upnp/http', 'http')[1],
                             '[RFC9112 §2.2](https://www.rfc-editor.org/rfc/rfc9112#section-2.2)')
            self.assertEqual(source('upnp/old', 'old')[1], 'WANIPC1 §2.4')
            self.assertEqual(source('upnp/both', 'both')[1], 'WANIPC1 §2.4.14, [WANIPC2 §2.5.14]'
                             '(http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf)')
            self.assertEqual(compare.spec_cell('UDA-1.1 §2.1'), '[UDA-1.1 §2.1]'
                             '(https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf)')
            self.assertEqual(source('upnp/gone', 'gone'), ('upnp/gone', ''))
            with unittest.mock.patch.object(compare, 'HERE', root / 'common'), \
                 unittest.mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(compare.case_sources({'candidate': 'bbb'}, suite)('upnp/walk', 'walk')[0],
                                 'upnp/walk')

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
            text = (root / 'review.md').read_text()
        self.assertTrue(text.startswith('Incomplete comparison.\n'))
        self.assertIn('- master: build failed', text)


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


BUILD_DATA = {'version': 1, 'platforms': {
    'linux-igd1': {'results': {'ipv4': {'upnp/a': ['PASS', ''], 'upnp/b': ['FAIL', 'gap']}}},
    'linux-igd2': {'results': {'ipv6': {'upnp/a': ['XFAIL', 'no feature']}}}}}


class BuildDriverTests(unittest.TestCase):
    """The UPnP suites: one driver run fills a column per daemon build."""

    def test_every_platform_is_read_and_keyed_by_platform_and_family(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'status-data.json'
            path.write_text(json.dumps(BUILD_DATA))
            outcomes, digest = suite_compare.read_build_results(path, 'sha')
        self.assertEqual(digest, 'sha')
        self.assertEqual(outcomes[('linux-igd1 ipv4', 'upnp', 'b')], {'status': 'FAIL', 'detail': 'gap'})
        self.assertEqual(outcomes[('linux-igd2 ipv6', 'upnp', 'a')]['status'], 'XFAIL')
        self.assertEqual(len(outcomes), 3)

    def run_build(self, root, exit_code, write=True):
        suite = root / 'tree' / suite_compare.TESTS / 'upnp_x'
        suite.mkdir(parents=True)
        (suite / 'cases.yaml').write_text('version: 1\n')
        data = json.dumps(BUILD_DATA)
        driver = suite / 'run-docker.sh'
        driver.write_text('#!/bin/sh\n' + (f"echo '{data}' > \"$UPNP_X_STATUS_DATA_FILE\"\n" if write else '')
                          + 'echo "$@"\n' + f'exit {exit_code}\n')
        driver.chmod(0o755)
        with contextlib.redirect_stdout(io.StringIO()):
            return suite_compare.run_build_driver(suite, 'master', root / 'tree', root / 'out',
                                                  SimpleNamespace(platform='linux', case=['a']),
                                                  'run-docker.sh', 'cases.yaml', 'UPNP_X')

    def test_the_driver_writes_its_status_data_under_the_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outcomes, digest = self.run_build(root, 1)
            self.assertEqual(len(digest), 64)
            self.assertIn(('linux-igd1 ipv4', 'upnp', 'b'), outcomes)
            self.assertEqual((root / 'out/master/run.log').read_text(), '--case a\n')

    def test_an_exit_code_which_disagrees_with_the_failures_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'disagrees'):
                self.run_build(Path(temporary), 0)

    def test_a_driver_without_results_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'wrote no results'):
                self.run_build(Path(temporary), 2, write=False)


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

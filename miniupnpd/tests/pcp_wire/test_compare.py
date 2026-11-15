#!/usr/bin/env python3
"""Offline checks of compare.py: complete wire results and captures, and the wire part of the report."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import compare  # noqa: E402
import compare_daemon_branches as tool  # noqa: E402  (compare.py put common/tools on the path)
import suite_compare  # noqa: E402
from test_compare_pcap_wire_fields import pcap_file, pcp, udp_packet  # noqa: E402

TITLE = 'PCP/NAT-PMP wire (linux)'


def options(**changes):
    values = dict(profile='baseline', wan_peer=False, capture=False, case=[], results=None, platform='linux')
    values.update(changes)
    return Namespace(**values)


def fixture(folder, statuses=('PASS', 'FAIL', 'SKIP')):
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


class WireResultTests(unittest.TestCase):
    def test_complete_results_and_failure_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture(Path(temporary))
            outcomes, digest = compare.read_results(root, 1)
            self.assertEqual(len(outcomes), 6)
            self.assertEqual(digest, 'test-digest')
            with self.assertRaisesRegex(ValueError, 'disagrees'):
                compare.read_results(root, 0)

    def test_missing_reports_and_captures_are_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture(Path(temporary))
            (root / 'results-ipv6.json').unlink()
            with self.assertRaises(OSError):
                compare.read_results(root, 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture(Path(temporary))
            (root / 'ipv4-pcp-case-0.pcap').write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'incomplete capture'):
                compare.read_results(root, 1, root)

    def test_corpus_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture(Path(temporary))
            path = root / 'results-ipv6.json'
            value = json.loads(path.read_text())
            value['corpus_sha256'] = 'different-digest'
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'different corpora'):
                compare.read_results(root, 1)

    def test_all_skipped_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture(Path(temporary), ('SKIP',))
            with self.assertRaisesRegex(ValueError, 'no cases executed'):
                compare.read_results(root, 0)

    def test_no_capture_run_omits_capture_options(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def run(command, cwd, env, stdout, stderr):
                self.assertNotIn('--capture-name', command)
                self.assertEqual(env['PCP_TEST_CAPTURE'], '0')
                folder = fixture(Path(env['PCP_TEST_RESULTS_DIR']), ('PASS',))
                (folder / 'status.md').write_text('complete\n')
                for pattern in ('*.pcap', '*.tcpdump.log'):
                    for path in folder.glob(pattern):
                        path.unlink()
                return type('Result', (), {'returncode': 0})()

            with patch.object(suite_compare.subprocess, 'run', side_effect=run), \
                    contextlib.redirect_stdout(io.StringIO()):
                result, _ = compare.run('master', root, root, options())
            self.assertEqual(len(result), 2)
            self.assertFalse((root / 'master' / 'captures').exists())


class WireReportTests(unittest.TestCase):
    def report(self, root, master, candidate, args=None, commits=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return tool.make_report(root, commits or {}, {'master': master, 'candidate': candidate}, [], TITLE,
                                    compare, args or options())

    def test_unchanged_failures_link_the_wire_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            master = compare.read_results(fixture(root / 'master' / 'captures'), 1, root / 'master' / 'captures')
            candidate = compare.read_results(fixture(root / 'candidate' / 'captures'), 1,
                                             root / 'candidate' / 'captures')
            self.assertEqual(self.report(root, master, candidate), 0)
            summary = (root / 'summary.md').read_text()
            self.assertIn('Regressions: **0**', summary)
            self.assertIn('| Change | Wire fields |', summary)
            self.assertEqual(len(list((root / 'comparisons').glob('*.md'))), 4)
            self.assertNotIn(str(root), next((root / 'comparisons').glob('*.md')).read_text())

    def test_regressions_fail_and_improvements_pass(self):
        for old, new, expected in [('PASS', 'FAIL', 1), ('FAIL', 'PASS', 0)]:
            with self.subTest(old=old, new=new), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                master = compare.read_results(fixture(root / 'master', (old,)), int(old == 'FAIL'))
                candidate = compare.read_results(fixture(root / 'candidate', (new,)), int(new == 'FAIL'))
                self.assertEqual(self.report(root, master, candidate), expected)

    def test_results_without_packet_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label in ('master', 'candidate'):
                folder = fixture(root / label)
                for pattern in ('*.pcap', '*.tcpdump.log'):
                    for path in folder.glob(pattern):
                        path.unlink()
            master = compare.read_results(root / 'master', 1)
            candidate = compare.read_results(root / 'candidate', 1)
            self.assertFalse(any('pcap' in case for case in master[0].values()))
            code = self.report(root, master, candidate, options(case=['case-0']), {'master': 'abc', 'candidate': 'def'})
            self.assertEqual(code, 0)
            self.assertFalse((root / 'comparisons').exists())
            summary = (root / 'summary.md').read_text()
            self.assertIn('- Server profile: `baseline`', summary)
            self.assertIn('git worktree add --detach .tmp/pcp-master abc', summary)
            self.assertIn('--capture --profile baseline --case case-0', summary)

    def test_ended_runs_have_no_reproduce_section(self):
        result = ({('ipv4', 'pcp', 'a'): {'status': 'PASS', 'detail': ''}}, 'digest')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(self.report(root, result, result, options(results=['m', 'c'])), 0)
            summary = (root / 'summary.md').read_text()
        self.assertNotIn('Server profile', summary)
        self.assertNotIn('git worktree add', summary)


class WireOptionTests(unittest.TestCase):
    def parse(self, *argv):
        return tool.parse_args(tool.load_suites(), ['--master-source', 'm', '--candidate-source', 'c',
                                                    '--output', '/nonexistent/out', *argv])

    def test_options_of_the_suite(self):
        suite, args = self.parse('--suite', 'wire', '--capture', '--profile', 'other')
        self.assertEqual(suite.SUITE, 'wire')
        self.assertTrue(args.capture)
        self.assertEqual(args.profile, 'other')

    def test_ended_runs_take_no_capture(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.parse('--suite', 'wire', '--platform', 'freebsd', '--results', 'a', 'b', '--capture')
        _, args = self.parse('--suite', 'wire', '--platform', 'freebsd', '--results', 'a', 'b')
        self.assertEqual(args.platform, 'freebsd')

    def test_the_suite_runs_on_linux_only(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.parse('--suite', 'wire', '--platform', 'freebsd')


if __name__ == '__main__':
    unittest.main()

"""Tests of lib_test (python3 test_lib_test.py)."""

import argparse
import ipaddress
import contextlib
import io
import json
import multiprocessing
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pcp_corpus_expander
import pcp_packet_encoding
import lib_test
from lib_test import (build_map_packet, upnp_soap_body, v6_address, wan_network,  # noqa: E402
                      CorpusError, build_lifecycle_request, run_daemon_restart, filter_reason, run_exchange_case, run_protocol_step,
                      select_cases, skip_reason, unselected_reason, validate_cases, with_dependencies,
                      write_status_report)
import traffic_agent
from lib_test import LanEcho


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class LanEchoTests(unittest.TestCase):
    def udp_exchange(self, port, payload):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(payload, ("127.0.0.1", port))
            return client.recvfrom(4096)[0]

    def tcp_exchange(self, port, payload):
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            client.sendall(payload)
            return client.recv(4096)

    def test_udp_echo_continues_until_closed(self):
        port = free_port(socket.SOCK_DGRAM)
        echo = LanEcho(socket.AF_INET, "127.0.0.1", port, "udp")
        try:
            self.assertEqual(self.udp_exchange(port, b"one"), b"one")
            self.assertEqual(self.udp_exchange(port, b"two"), b"two")
        finally:
            echo.close()
        self.assertEqual(echo.received, [b"one", b"two"])

    def test_tcp_echo_continues_until_closed(self):
        port = free_port(socket.SOCK_STREAM)
        echo = LanEcho(socket.AF_INET, "127.0.0.1", port, "tcp")
        try:
            self.assertEqual(self.tcp_exchange(port, b"one"), b"one")
            self.assertEqual(self.tcp_exchange(port, b"two"), b"two")
        finally:
            echo.close()

    def test_once_serves_one_exchange_and_ends(self):
        port = free_port(socket.SOCK_DGRAM)
        echo = LanEcho(socket.AF_INET, "127.0.0.1", port, "udp", once=True)
        self.assertEqual(self.udp_exchange(port, b"only"), b"only")
        echo.join(2)
        self.assertFalse(echo.thread.is_alive())
        self.assertEqual(echo.received, [b"only"])
        echo.close()

    def test_once_ends_by_itself_when_nobody_comes(self):
        port = free_port(socket.SOCK_STREAM)
        echo = LanEcho(socket.AF_INET, "127.0.0.1", port, "tcp", once=True)
        echo.join(3)
        self.assertFalse(echo.thread.is_alive())
        self.assertEqual(echo.received, [])
        echo.close()

    def test_tcp_read_bytes_waits_for_the_whole_token(self):
        port = free_port(socket.SOCK_STREAM)
        echo = LanEcho(socket.AF_INET, "127.0.0.1", port, "tcp", once=True, read_bytes=6)
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            client.sendall(b"abc")
            client.sendall(b"def")
            data = b""
            while len(data) < 6:
                data += client.recv(4096)
        echo.join(2)
        echo.close()
        self.assertEqual(data, b"abcdef")
        self.assertEqual(echo.received, [b"abcdef"])


class MappingRequestTests(unittest.TestCase):
    """pcp_mapping_request against the byte layout RFC 6887 gives (written out by hand)."""

    def test_map_request_bytes(self):
        nonce = bytes(range(12))
        expected = (bytes((2, 1, 0, 0)) + struct.pack("!I", 300) + b"\0" * 10 + b"\xff\xff" + bytes((192, 0, 2, 5))
                    + nonce + bytes((17, 0, 0, 0)) + struct.pack("!HH", 4000, 5000) + b"\0" * 16)
        built = pcp_packet_encoding.pcp_mapping_request(2, 1, 300, "192.0.2.5", 17, 4000, 5000, nonce)
        self.assertEqual(built, expected)
        self.assertEqual(len(built), pcp_packet_encoding.MAP_REQUEST_SIZE)

    def test_peer_request_and_options(self):
        nonce = b"\x42" * 12
        option = pcp_packet_encoding.pcp_option(2)
        built = pcp_packet_encoding.pcp_mapping_request(
            2, 2, 0, "2001:db8::2", 6, 1, 2, nonce, peer=(53, "2001:db8::9", 7), options=option)
        self.assertEqual(len(built), pcp_packet_encoding.PEER_REQUEST_SIZE + len(option))
        self.assertEqual(built[60:64], struct.pack("!HH", 53, 7))
        self.assertEqual(built[64:80], pcp_packet_encoding.ipv6_bytes("2001:db8::9"))
        self.assertEqual(built[80:], option)

    def test_version_one_has_no_nonce(self):
        built = pcp_packet_encoding.pcp_mapping_request(1, 1, 0, "192.0.2.5", 17, 1, 2)
        self.assertEqual(len(built), pcp_packet_encoding.MAP_REQUEST_SIZE - 12)


class WireTests(unittest.TestCase):
    def server(self, reply):
        """A UDP socket on loopback which answers every datagram with `reply` (None: stays silent)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.2)
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    data, peer = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if reply is not None:
                    sock.sendto(reply, peer)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        def close():
            stop.set()
            thread.join(timeout=1)
            sock.close()
        self.addCleanup(close)
        return sock.getsockname()

    def client(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(lib_test.TIMEOUT)
        self.addCleanup(sock.close)
        return sock

    def test_client_address_is_the_address_used_to_reach_the_server(self):
        self.assertEqual(lib_test.client_address(self.client(), ("127.0.0.1", 9)), "127.0.0.1")

    def test_exchange_returns_the_response(self):
        address = self.server(b"answer")
        self.assertEqual(lib_test.exchange(self.client(), address, b"question"), b"answer")

    def test_exchange_needs_a_timeout(self):
        sock = self.client()
        sock.settimeout(None)
        with self.assertRaisesRegex(ValueError, "needs a socket with a timeout"):
            lib_test.exchange(sock, ("127.0.0.1", 9), b"question")

    def test_parse_auth_response(self):
        response = (bytes((2, 131, 0, 7)) + b"\0" * 20 + struct.pack("!II", 9, 3)
                    + pcp_packet_encoding.pcp_option(7, b"eap"))
        self.assertEqual(lib_test.parse_auth_response(response), (7, 9, 3, {7: b"eap"}))
        with self.assertRaisesRegex(AssertionError, "short PCP AUTHENTICATION"):
            lib_test.parse_auth_response(response[:31])
        with self.assertRaisesRegex(AssertionError, "expected PCP AUTHENTICATION"):
            lib_test.parse_auth_response(bytes((2, 129)) + response[2:])

    def test_receive_within_gives_the_datagram_or_none_and_keeps_the_timeout(self):
        sock = self.client()
        sock.settimeout(7)
        address = self.server(b"here")
        sock.sendto(b"x", address)
        self.assertEqual(lib_test.receive_within(sock, 1), b"here")
        self.assertEqual(sock.gettimeout(), 7)
        self.assertIsNone(lib_test.receive_within(sock, 0.05))
        self.assertEqual(sock.gettimeout(), 7)

    def test_expect_silence_passes_when_ignored_and_fails_on_an_answer(self):
        quiet = self.client()
        lib_test.expect_silence(quiet, self.server(None), b"x")
        self.assertEqual(quiet.gettimeout(), lib_test.TIMEOUT)
        talkative = self.client()
        with self.assertRaisesRegex(AssertionError, "got 3 response bytes"):
            lib_test.expect_silence(talkative, self.server(b"abc"), b"x")
        self.assertEqual(talkative.gettimeout(), lib_test.TIMEOUT)

    def build(self, spec):
        return lib_test.build_request(self.client(), ("127.0.0.1", 5351),
                                          pcp_corpus_expander.expand_request(spec))

    def test_map_request_bytes(self):
        packet = self.build({"pcp": "MAP", "lifetime": 120, "nonce": "0102030405060708090a0b0c",
                             "protocol": "UDP", "internal_port": 41000, "external_port": 41001,
                             "client": "10.0.0.2"})
        self.assertEqual(packet[:2], bytes((2, 1)))
        self.assertEqual(packet[4:8], (120).to_bytes(4, "big"))
        self.assertEqual(packet[8:24], pcp_packet_encoding.ipv6_bytes("10.0.0.2"))
        self.assertEqual(packet[24:36], bytes(range(1, 13)))
        self.assertEqual(packet[36], 17)
        self.assertEqual(packet[40:44], (41000).to_bytes(2, "big") + (41001).to_bytes(2, "big"))
        self.assertEqual(len(packet), 60)

    def test_options_follow_the_body_and_patches_are_applied(self):
        packet = self.build({"pcp": "MAP", "lifetime": 1, "nonce": "00" * 12, "protocol": "UDP",
                             "internal_port": 1, "client": "10.0.0.2",
                             "options": ["PREFER_FAILURE", {"code": 99, "data_hex": "aabbccdd"}],
                             "patches": [{"offset": 3, "hex": "ff"}]})
        self.assertEqual(packet[60:64], bytes((2, 0, 0, 0)))
        self.assertEqual(packet[64:72], bytes((99, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd)))
        self.assertEqual(packet[3], 0xff)

    def test_natpmp_and_raw_requests(self):
        self.assertEqual(self.build({"natpmp": "MAP_UDP", "private_port": 5, "public_port": 6, "lifetime": 7}),
                         pcp_packet_encoding.natpmp_packet(1, 5, 6, 7))
        self.assertEqual(self.build({"kind": "raw", "hex": "0a0b"}), b"\x0a\x0b")

    def test_unknown_request_kind_is_refused(self):
        with self.assertRaises(ValueError):
            lib_test.build_request(self.client(), ("127.0.0.1", 5351), {"kind": "nothing"})


# kind|proto|eport|family|iaddr|iport|ifname|nonce|prefer_failure|since|expiry|eaddr|raddr|rport|label
MAP4 = "PCP-M|UDP|43333|IPv4|10.0.0.2|43333|eth0|aabbccddeeff001122334455|0|100|200|198.51.100.1|NA|NA|NA"
MAP6 = "PCP-M|UDP|43335|IPv6|2001:db8:1::2|43335|eth0|c1c2c3c4c5c6c7c8c9cacbcc|0|100|200|2001:db8:1::2|NA|NA|NA"
FILTER4 = "PCP-F|UDP|43333|IPv4|10.0.0.2|43333|NA|aabbccddeeff001122334455|NA|NA|NA|NA|198.51.100.0/24|0|NA"
PEER4 = "PCP-P|UDP|44444|IPv4|10.0.0.2|44444|eth0|b1b2b3b4b5b6b7b8b9babbbc|0|100|200|198.51.100.1|198.51.100.20|6000|NA"
PMP4 = "NAT-PMP|UDP|42222|IPv4|10.0.0.2|42222|eth0|NA|0|100|200|198.51.100.1|NA|NA|NA"
HEADER = "PCP-LEASE 3"


class LeaseLineTests(unittest.TestCase):
    def test_selector_nonce(self):
        self.assertTrue(lib_test.lease_line_matches(MAP4, {"kind": "PCP-M", "nonce": "aabbccddeeff001122334455"}))
        self.assertFalse(lib_test.lease_line_matches(MAP4, {"kind": "PCP-M", "nonce": "00" * 12}))
        self.assertFalse(lib_test.lease_line_matches("PCP-M|UDP|1|IPv4|a|43333", {"kind": "PCP-M", "nonce": "x"}))

    def test_socket_family_and_key_value_pairs(self):
        self.assertEqual(lib_test.socket_family("ipv6"), socket.AF_INET6)
        self.assertEqual(lib_test.socket_family("ipv4"), socket.AF_INET)
        self.assertEqual(lib_test.key_value_pairs(["a=b=c", "d="]), {"a": "b=c", "d": ""})

    def test_selector_matches_kind_family_and_internal_port(self):
        self.assertTrue(lib_test.lease_line_matches(MAP4, {"kind": "PCP-M"}))
        self.assertTrue(lib_test.lease_line_matches(MAP4, {"kind": "PCP-M", "family": "IPv4", "internal_port": 43333}))
        self.assertFalse(lib_test.lease_line_matches(MAP4, {"kind": "PCP-P"}))
        self.assertFalse(lib_test.lease_line_matches(MAP4, {"kind": "PCP-M", "family": "IPv6"}))
        self.assertFalse(lib_test.lease_line_matches(MAP4, {"kind": "PCP-M", "internal_port": 43334}))
        self.assertTrue(lib_test.lease_line_matches(FILTER4, {"kind": "PCP-F", "internal_port": 43333}))
        self.assertTrue(lib_test.lease_line_matches(PMP4, {"kind": "NAT-PMP", "internal_port": 42222}))

    def test_header_and_short_lines_never_match(self):
        for selector in ({"kind": "PCP-LEASE 3"}, {"kind": "PCP-M"}):
            self.assertFalse(lib_test.lease_line_matches(HEADER, selector))
        self.assertFalse(lib_test.lease_line_matches("PCP-M|UDP|1", {"kind": "PCP-M"}))

    def test_counts_and_at_least_one(self):
        lines = [HEADER, MAP4, FILTER4, FILTER4, PEER4]
        matched = lib_test.match_lease_lines(
            [{"kind": "PCP-M", "internal_port": 43333, "count": 1},
             {"kind": "PCP-F", "internal_port": 43333, "count": 2},
             {"kind": "PCP-P"}], lines)
        self.assertEqual(matched, sorted([MAP4, FILTER4, FILTER4, PEER4]))
        with self.assertRaisesRegex(AssertionError, "expected 3 line"):
            lib_test.match_lease_lines([{"kind": "PCP-F", "count": 3}], lines)
        with self.assertRaisesRegex(AssertionError, "no line of kind=NAT-PMP"):
            lib_test.match_lease_lines([{"kind": "NAT-PMP"}], lines)
        self.assertEqual(lib_test.match_lease_lines([{"kind": "NAT-PMP", "count": 0}], lines), [])

    def test_same_lines_without_tolerance(self):
        self.assertTrue(lib_test.same_lease_lines([MAP4, FILTER4], [MAP4, FILTER4], 0))
        self.assertFalse(lib_test.same_lease_lines([MAP4], [lib_test.with_lease_expiry(MAP4, 201)], 0))
        self.assertFalse(lib_test.same_lease_lines([MAP4], [MAP4, FILTER4], 0))

    def test_expiry_tolerance_is_only_for_the_expiry_field(self):
        self.assertTrue(lib_test.same_lease_lines([MAP4], [lib_test.with_lease_expiry(MAP4, 201)], 1))
        self.assertTrue(lib_test.same_lease_lines([MAP4], [lib_test.with_lease_expiry(MAP4, 199)], 1))
        self.assertFalse(lib_test.same_lease_lines([MAP4], [lib_test.with_lease_expiry(MAP4, 202)], 1))
        self.assertTrue(lib_test.same_lease_lines([PEER4], [lib_test.with_lease_expiry(PEER4, 201)], 1))
        self.assertTrue(lib_test.same_lease_lines([PMP4], [lib_test.with_lease_expiry(PMP4, 201)], 1))
        # another field which differs is never tolerated, nor is a nonce or a since time
        self.assertFalse(lib_test.same_lease_lines([MAP4], [MAP4.replace("|100|", "|101|")], 1))
        self.assertFalse(lib_test.same_lease_lines([MAP4], [MAP4.replace("aabbcc", "ffbbcc")], 1))
        self.assertFalse(lib_test.same_lease_lines([MAP4], [lib_test.with_lease_expiry(MAP4, 201).replace("eth0", "eth1")], 1))

    def test_filter_peer_lines_have_no_expiry_to_tolerate(self):
        self.assertFalse(lib_test.same_lease_lines([FILTER4], [lib_test.with_lease_expiry(FILTER4, 5)], 1))
        self.assertFalse(lib_test.same_lease_lines([MAP4], [lib_test.with_lease_expiry(MAP4, "NA")], 1))


class ResponseCheckTests(unittest.TestCase):
    def test_variables_in_requests(self):
        variables = {"port": 41000, "other": 2}
        self.assertEqual(lib_test.resolve_value("$port", variables), 41000)
        self.assertEqual(lib_test.resolve_value("plain", variables), "plain")
        self.assertEqual(lib_test.resolve_value({"add": ["$port", 5, "$other"]}, variables), 41007)
        self.assertEqual(lib_test.resolve_request(
            {"a": ["$port", {"add": ["$other", 1]}], "b": {"c": "$other"}, "d": "x"}, variables),
            {"a": [41000, 3], "b": {"c": 2}, "d": "x"})
        with self.assertRaisesRegex(AssertionError, "'missing' has not been set"):
            lib_test.resolve_value("$missing", variables)

    def test_capture_response_types(self):
        response = bytes((7, 0x12, 0x34, 0, 0, 1, 0)) + pcp_packet_encoding.ipv6_bytes("192.0.2.5") + b"\xab\xcd"
        capture = lib_test.capture_response
        self.assertEqual(capture(response, {"offset": 0, "type": "u8"}), 7)
        self.assertEqual(capture(response, {"offset": 1, "type": "u16"}), 0x1234)
        self.assertEqual(capture(response, {"offset": 3, "type": "u32"}), 256)
        self.assertEqual(capture(response, {"offset": 7, "type": "address"}), "::ffff:192.0.2.5")
        self.assertEqual(capture(response, {"offset": 23, "type": "hex", "length": 2}), "abcd")
        with self.assertRaisesRegex(AssertionError, "truncated"):
            capture(response, {"offset": 24, "type": "u16"})
        with self.assertRaisesRegex(AssertionError, "no length"):
            capture(response, {"offset": 0, "type": "hex"})
        with self.assertRaises(ValueError):
            capture(response, {"offset": 0, "type": "float", "length": 1})

    def test_step_value_rules(self):
        values = {"port": 41000, "lifetime": 120, "zero": 0}
        variables = {"expected": 41000}
        lib_test.assert_step_values(values, {
            "port": {"nonzero": True, "equals": "$expected", "not_equals": 1, "min": 41000, "max": 41000,
                     "remember": "seen"},
            "lifetime": {"min": 1, "max": 600}, "zero": {"nonzero": False}}, variables)
        self.assertEqual(variables["seen"], 41000)
        for rules, message in (({"port": {"nonzero": False}}, "unexpectedly has value"),
                               ({"port": {"equals": 1}}, "expected 1"),
                               ({"port": {"not_equals": 41000}}, "unexpectedly equals"),
                               ({"port": {"min": 41001}}, "is below"),
                               ({"port": {"max": 40999}}, "exceeds")):
            with self.subTest(rules=rules), self.assertRaisesRegex(AssertionError, message):
                lib_test.assert_step_values(values, rules, dict(variables))

    def test_echoed_request_bytes(self):
        request, response = b"0123456789", b"xx2345xxxx"
        lib_test.assert_response_echo(request, response, {"echo_request": [{"offset": 2, "length": 4}]})
        with self.assertRaisesRegex(AssertionError, "were not echoed"):
            lib_test.assert_response_echo(request, response, {"echo_request": [{"offset": 0, "length": 4}]})
        with self.assertRaisesRegex(AssertionError, "invalid request echo region"):
            lib_test.assert_response_echo(request, response, {"echo_request": [{"offset": 8, "length": 4}]})
        with self.assertRaisesRegex(AssertionError, "truncates echoed"):
            lib_test.assert_response_echo(request, b"xx23", {"echo_request": [{"offset": 2, "length": 4}]})
        lib_test.assert_response_echo(request, response, {})

    def test_pcp_header_result_and_errors(self):
        response = bytes((2, 129, 0, 7)) + b"\x00" * 20
        expect = {"version": 2, "opcode": 129}
        self.assertEqual(lib_test.check_response_header(response, {"protocol": "pcp"}, expect), 7)
        with self.assertRaisesRegex(AssertionError, "unexpected PCP response opcode 129"):
            lib_test.check_response_header(response, {"protocol": "pcp"}, {"version": 2, "opcode": 130})
        with self.assertRaisesRegex(AssertionError, "reserved byte"):
            lib_test.check_response_header(bytes((2, 129, 1, 0)), {"protocol": "pcp"}, expect)

    def test_natpmp_result_is_16_bits_at_offset_2(self):
        response = bytes((0, 129, 0, 4)) + b"\x00" * 12
        self.assertEqual(lib_test.check_response_header(response, {"protocol": "natpmp"},
                                                            {"version": 0, "opcode": 129}), 4)
        with self.assertRaisesRegex(AssertionError, "unexpected NAT-PMP response version 0"):
            lib_test.check_response_header(response, {"protocol": "natpmp"}, {"version": 1, "opcode": 129})

    def test_required_options(self):
        response = bytes(24) + pcp_packet_encoding.pcp_option(3, b"abcd") + pcp_packet_encoding.pcp_option(7, b"xy")
        lib_test.check_required_options(response, {"required_options": [
            {"code": 3, "data_hex": b"abcd".hex()}, {"code": 7, "minimum_length": 2}]})
        for required, message in (({"code": 9}, "missing"),
                                  ({"code": 3, "data_hex": "00"}, "data mismatch"),
                                  ({"code": 7, "minimum_length": 3}, "too short")):
            with self.subTest(message=message), self.assertRaisesRegex(AssertionError, message):
                lib_test.check_required_options(response, {"required_options": [required]})
        with self.assertRaisesRegex(AssertionError, "truncated response option 3"):
            lib_test.check_required_options(response[:24 + 6], {"required_options": [{"code": 3}]})

    def test_protocol_response_checks_header_length_fields_and_remembers(self):
        request = bytes(60)
        response = bytes((2, 129, 0, 0)) + (120).to_bytes(4, "big") + bytes(52)
        spec = {"expect": {"version": 2, "opcode": 129, "result": [0], "length": 60},
                "captures": {"lifetime": {"offset": 4, "type": "u32"}},
                "assert": {"lifetime": {"min": 1, "remember": "granted"}}}
        variables = {}
        lib_test.check_protocol_response(request, response, "pcp", spec, variables)
        self.assertEqual(variables["granted"], 120)
        with self.assertRaisesRegex(AssertionError, "expected 72-byte pcp response, got 60"):
            lib_test.check_protocol_response(request, response, "pcp", dict(
                spec, expect=dict(spec["expect"], length=72)), {})
        with self.assertRaisesRegex(AssertionError, "unexpected pcp result code 3"):
            lib_test.check_protocol_response(request, bytes((2, 129, 0, 3)) + bytes(56), "pcp", spec, {})
        with self.assertRaisesRegex(ValueError, "unsupported protocol"):
            lib_test.check_protocol_response(request, response, "other", spec, {})


class LeasePortsTests(unittest.TestCase):
    def test_lease_ports_of_a_case(self):
        case = {"request": {"phases": {
            "create": [{"kind": "lease_file", "lines": [{"kind": "PCP-M", "internal_port": 43333},
                                                        {"kind": "PCP-P", "internal_port": 44444}]},
                       {"protocol": "pcp"}],
            "verify": [{"kind": "lease_file", "lines": [{"kind": "PCP-M", "internal_port": 43333},
                                                        {"kind": "PCP-F"}]}]}}}
        self.assertEqual(lib_test.lease_ports(case), [43333, 44444])


# the same mappings as the daemon writes them: lease_file (IPv4) and lease_file6 (IPv6); the nonce of
# MAP4 as a little-endian host prints it (pcpserver.c: three uint32_t with %08x)
LEASE_MAP4 = "UDP:43333:10.0.0.2:43333:200:PCP MAP ddccbbaa1100ffee55443322"
LEASE_PMP4 = "UDP:42222:10.0.0.2:42222:200:NAT-PMP 42222 udp"
LEASE_MAP6 = "UDP;2001:db8:1::2;43335;;0;7;200;PCP MAP c1c2c3c4c5c6c7c8c9cacbcc"
LEASE_UPNP4 = "TCP:41000:198.51.100.7:10.0.0.2:41000:0:my:app"


class LeaseRecordTests(unittest.TestCase):
    def test_lease_file_lines(self):
        record = lib_test.lease_record(LEASE_MAP4)
        self.assertEqual(record.split("|")[:6], ["PCP-M", "UDP", "43333", "IPv4", "10.0.0.2", "43333"])
        self.assertEqual(record.split("|")[lib_test.LEASE_EXPIRY_FIELD], "200")
        self.assertEqual(len(record.split("|")), lib_test.LEASE_FIELDS)
        self.assertTrue(lib_test.lease_line_matches(record, {"kind": "PCP-M", "nonce": "aabbccddeeff001122334455"}))
        self.assertTrue(lib_test.lease_line_matches(record, {"kind": "PCP-M", "nonce": "ddccbbaa1100ffee55443322"}))
        self.assertFalse(lib_test.lease_line_matches(record, {"kind": "PCP-M", "nonce": "00" * 12}))
        self.assertTrue(lib_test.lease_line_matches(lib_test.lease_record(LEASE_PMP4),
                                                    {"kind": "NAT-PMP", "family": "IPv4", "internal_port": 42222}))

    def test_remote_host_and_upnp_lines(self):
        fields = lib_test.lease_record(LEASE_UPNP4).split("|")
        self.assertEqual((fields[0], fields[4], fields[12], fields[-1]), ("UPNP", "10.0.0.2", "198.51.100.7", "my:app"))

    def test_lease_file6_lines(self):
        record = lib_test.lease_record(LEASE_MAP6)
        self.assertTrue(lib_test.lease_line_matches(record, {"kind": "PCP-M", "family": "IPv6", "internal_port": 43335,
                                                             "nonce": "c4c3c2c1c8c7c6c5cccbcac9"}))
        self.assertEqual(record.split("|")[2], "43335")
        # the uid is not part of the record: a reload may give another
        self.assertEqual(record, lib_test.lease_record(LEASE_MAP6.replace(";7;", ";9;")))

    def test_other_lines_are_left_out(self):
        self.assertEqual(lib_test.lease_records([HEADER, MAP4, "", "UDP:1", LEASE_MAP4]),
                         [lib_test.lease_record(LEASE_MAP4)])


class LeaseFileStepTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.lease = os.path.join(self.directory.name, "miniupnpd.leases")
        self.lease6 = os.path.join(self.directory.name, "miniupnpd.leases6")
        self.source = lib_test.LeaseSource([self.lease, self.lease6], None, self.directory.name)

    def write(self, *lines, path=None):
        with open(path or self.lease, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def test_save_then_same_as_over_a_restart(self):
        variables = {"case_name": "restart-demo"}
        selectors = [{"kind": "PCP-M", "internal_port": 43333, "count": 1},
                     {"kind": "NAT-PMP", "internal_port": 42222, "count": 1}]
        self.write(LEASE_MAP4, LEASE_PMP4)
        lib_test.run_lease_file_step({"lines": selectors, "save": "before"}, variables, self.source)
        # after the restart the expiry moved by one second
        self.write(LEASE_MAP4.replace(":200:", ":201:"), LEASE_PMP4)
        lib_test.run_lease_file_step({"lines": selectors, "same_as": "before", "expiry_tolerance": 1}, variables, self.source)
        with self.assertRaisesRegex(AssertionError, "changed over the restart"):
            lib_test.run_lease_file_step({"lines": selectors, "same_as": "before"}, variables, self.source)
        self.write(LEASE_MAP4.replace(":200:", ":300:"), LEASE_PMP4)
        with self.assertRaisesRegex(AssertionError, "changed over the restart"):
            lib_test.run_lease_file_step({"lines": selectors, "same_as": "before", "expiry_tolerance": 1}, variables, self.source)

    def test_both_files_are_read(self):
        self.write(LEASE_MAP4)
        self.write(LEASE_MAP6, path=self.lease6)
        lib_test.run_lease_file_step({"lines": [{"kind": "PCP-M", "family": "IPv4", "count": 1},
                                                {"kind": "PCP-M", "family": "IPv6", "count": 1}]},
                                     {"case_name": "both"}, self.source)

    def test_a_lost_lease_file_fails_the_step(self):
        variables = {"case_name": "lost"}
        self.write(LEASE_MAP4)
        step = {"lines": [{"kind": "PCP-M", "internal_port": 43333, "count": 1}], "save": "before"}
        lib_test.run_lease_file_step(step, variables, self.source)
        os.unlink(self.lease)
        with self.assertRaisesRegex(AssertionError, "expected 1 line"):
            lib_test.run_lease_file_step({"lines": step["lines"], "same_as": "before"}, variables, self.source)

    def test_state_command_replaces_the_file(self):
        command = lib_test.LeaseSource(None, "printf '%s\\n%s\\n' " + repr(LEASE_MAP4) + " " + repr(LEASE_MAP6))
        lib_test.run_lease_file_step({"lines": [{"kind": "PCP-M", "count": 2}]}, {"case_name": "cmd"}, command)
        failing = lib_test.LeaseSource(None, "false")
        with self.assertRaisesRegex(AssertionError, "--state-command failed"):
            failing.lines()

    def test_wait_seconds_waits_for_lines_to_go(self):
        self.write(LEASE_MAP4)
        with self.assertRaises(AssertionError):
            lib_test.run_lease_file_step({"lines": [{"kind": "PCP-M", "count": 0}], "wait_seconds": 0},
                                          {"case_name": "wait"}, self.source)
        self.write("")
        lib_test.run_lease_file_step({"lines": [{"kind": "PCP-M", "count": 0}], "wait_seconds": 2},
                                      {"case_name": "wait"}, self.source)

    def test_no_state_source_is_an_error(self):
        with self.assertRaisesRegex(AssertionError, "needs --state-file or --state-command"):
            lib_test.LeaseSource().lines()


class PacketCaptureTests(unittest.TestCase):
    def fake_tcpdump(self, directory, body):
        path = os.path.join(directory, "tcpdump")
        with open(path, "w", encoding="utf-8") as script:
            script.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)
        return path

    def test_start_and_stop_write_the_log(self):
        with tempfile.TemporaryDirectory() as directory:
            tcpdump = self.fake_tcpdump(directory, "echo 'listening on lo' >&2\n"
                                                   "trap 'echo stopped >&2; exit 0' INT\nwhile :; do sleep 0.1; done\n")
            capture = lib_test.PacketCapture.start(tcpdump, "lo", "udp", directory, "case", 2)
            capture.stop()
            with open(os.path.join(directory, "case.tcpdump.log"), encoding="utf-8") as log:
                self.assertEqual(log.read(), "listening on lo\nstopped\n")

    def test_a_silent_tcpdump_does_not_hang_the_start(self):
        with tempfile.TemporaryDirectory() as directory:
            tcpdump = self.fake_tcpdump(directory, "exec sleep 30\n")
            saved, lib_test.PacketCapture.START_TIMEOUT = lib_test.PacketCapture.START_TIMEOUT, 0.2
            try:
                with self.assertRaisesRegex(SystemExit, "tcpdump failed to start for case case: no output"):
                    lib_test.PacketCapture.start(tcpdump, "lo", "udp", directory, "case", 1)
            finally:
                lib_test.PacketCapture.START_TIMEOUT = saved


class ParseOptionsTests(unittest.TestCase):
    def test_options_with_padding(self):
        data = (b"\x00" * 24 + pcp_packet_encoding.pcp_option(3, b"abcde") + pcp_packet_encoding.pcp_option(2)
                + pcp_packet_encoding.pcp_option(130, b"1234"))
        self.assertEqual(pcp_packet_encoding.parse_options(data, 24),
                         [(3, b"abcde"), (2, b""), (130, b"1234")])
        self.assertEqual(pcp_packet_encoding.parse_options(data, len(data)), [])

    def test_truncated_options_name_what_was_cut(self):
        option = pcp_packet_encoding.pcp_option(3, b"abcdef")
        with self.assertRaisesRegex(ValueError, "truncated thing header"):
            pcp_packet_encoding.parse_options(option + b"\x01\x00", 0, "thing")
        with self.assertRaisesRegex(ValueError, "truncated thing 3"):
            pcp_packet_encoding.parse_options(option[:-3], 0, "thing")
        # the padding after the last payload may be missing: only the payload has to be complete
        self.assertEqual(pcp_packet_encoding.parse_options(option[:-2], 0), [(3, b"abcdef")])


class CorpusExpanderTests(unittest.TestCase):
    def test_packet_definitions(self):
        corpus = {"defs": {"packets": {"map-udp": {
                      "pcp": "MAP", "lifetime": 300, "protocol": "UDP",
                      "internal_port": 40000, "external_port": 41000}}},
                  "sections": [{"cases": [{
                      "name": "t", "protocol": "pcp",
                      "request": {"use": "map-udp", "options": ["PREFER_FAILURE", {"PORT_SET": "0001c73900"}]},
                      "expect": {"opcode": "MAP_RESPONSE", "result": ["CANNOT_PROVIDE_EXTERNAL"]}}]}]}
        case = pcp_corpus_expander.expand_corpus(corpus)["sections"][0]["cases"][0]
        self.assertEqual(case["request"], {
            "kind": "pcp_map", "opcode": 1, "version": 2, "client": "source",
            "external_address": "::", "lifetime": 300, "protocol_number": 17,
            "internal_port": 40000, "external_port": 41000,
            "options": [{"code": 2}, {"code": 130, "data_hex": "0001c73900"}]})
        self.assertEqual(case["expect"], {"opcode": 129, "result": [11]})
        self.assertEqual(pcp_corpus_expander.expand_request({"natpmp": "MAP_TCP", "private_port": 1}),
                         {"kind": "natpmp", "version": 0, "reserved": 0, "opcode": 2, "private_port": 1})
        self.assertEqual(pcp_corpus_expander.expand_request({"natpmp": "MAP_UDP", "reserved": None})["opcode"], 1)
        self.assertNotIn("reserved", pcp_corpus_expander.expand_request({"natpmp": "MAP_UDP", "reserved": None}))
        self.assertEqual(
            pcp_corpus_expander.expand_request({"natpmp": "MAP_TCP", "private_port": 49001, "lifetime": 300,
                                     "truncate_to": 11}),
            {"kind": "raw", "hex": "00020000bf690000000001"})
        self.assertEqual(pcp_corpus_expander.expand_request({"natpmp": "MAP_UDP_RESPONSE"})["opcode"], 129)
        self.assertEqual(pcp_corpus_expander.expand_request({"header": 127})["opcode"], 127)
        with self.assertRaises(ValueError):
            pcp_corpus_expander.expand_request({"pcp": "NOPE"})

    def test_sequence_shorthands(self):
        step = {"protocol": "pcp", "request": {"pcp": "MAP", "lifetime": 300, "nonce": "ab" * 12,
                                               "protocol": "UDP", "internal_port": 51001, "port_set": 2},
                "expect": {"opcode": "MAP_RESPONSE", "result": ["SUCCESS"], "length": 72},
                "verify": "port-set-mapping", "assert": {"external": {"nonzero": True}}}
        corpus = {"defs": {"steps": {"mapped": step}},
                  "sections": [{"cases": [{"name": "t", "protocol": "pcp", "request": {
                      "kind": "protocol_sequence", "cleanup": "auto",
                      "steps": [{"use": "mapped", "each": [{"request": {"internal_port": 51001}},
                                                           {"request": {"internal_port": 51002}}]}]}}]}]}
        request = pcp_corpus_expander.expand_corpus(corpus)["sections"][0]["cases"][0]["request"]
        first, second = request["steps"]
        self.assertEqual(first["request"]["options"], [{"code": 130, "data_hex": "0002c73900"}])
        self.assertEqual(second["request"]["internal_port"], 51002)
        self.assertEqual(first["assert"]["size"], {"equals": 2})
        self.assertEqual(first["assert"]["first"], {"equals": 51001})
        self.assertEqual(first["assert"]["protocol_reserved"], {"equals": 17 << 24})
        self.assertEqual(first["assert"]["external"], {"nonzero": True})
        self.assertEqual(first["captures"]["first"], {"offset": 66, "type": "u16"})
        self.assertEqual([item["request"]["internal_port"] for item in request["cleanup"]],
                         [51001, 51002])
        self.assertEqual(request["cleanup"][0]["request"]["lifetime"], 0)
        self.assertEqual(request["cleanup"][0]["expect"]["length"], [60, 72])
        self.assertNotIn("first", request["cleanup"][0]["captures"])


class StepCheckTests(unittest.TestCase):
    def test_variables_and_captures(self):
        self.assertEqual(lib_test.resolve_request(
            {"port": {"add": ["$start", 3]}, "values": ["$start"]}, {"start": 1000}),
            {"port": 1003, "values": [1000]})
        self.assertEqual(lib_test.resolve_value({"add": ["$ttl", 0.5]}, {"ttl": 2}), 2.5)
        with self.assertRaisesRegex(AssertionError, "has not been set"):
            lib_test.resolve_value("$missing", {})
        reply = bytes.fromhex("010203040506")
        for field, expected in (({"type": "u8", "offset": 0}, 1),
                                ({"type": "u16", "offset": 1}, 0x0203),
                                ({"type": "u32", "offset": 2}, 0x03040506),
                                ({"type": "hex", "offset": 0, "length": 3}, "010203")):
            with self.subTest(field=field):
                self.assertEqual(lib_test.capture_response(reply, field), expected)
        with self.assertRaisesRegex(AssertionError, "truncated"):
            lib_test.capture_response(reply, {"type": "u16", "offset": len(reply) - 1})

    def test_response_fields(self):
        reply = struct.pack("!BBHII", 0, 128, 0, 1, 0)
        spec = {"expect": {"version": 0, "opcode": 128, "result": [0], "length": len(reply)},
                "captures": {"reserved": {"type": "u32", "offset": 8}},
                "assert": {"reserved": {"equals": 0}}}
        lib_test.check_protocol_response(b"", reply, "natpmp", spec, {})
        for offset in (0, 1, 3, 8, 9, 10, 11):
            bad = bytearray(reply)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(AssertionError):
                lib_test.check_protocol_response(b"", bytes(bad), "natpmp", spec, {})
        with self.assertRaises(AssertionError):
            lib_test.check_protocol_response(b"", reply[:-1], "natpmp", spec, {})

    def test_cleanup_steps_all_run_and_their_errors_are_not_raised(self):
        ran = []

        def run_step(step):
            ran.append(step)
            if step == 2:
                raise AssertionError("cleanup failed")
            if step == 3:
                raise OSError("network down")
        lib_test.run_cleanup([1, 2, 3, 4], run_step)
        self.assertEqual(ran, [1, 2, 3, 4])
        with self.assertRaises(ValueError):
            lib_test.run_cleanup([5], lambda step: (_ for _ in ()).throw(ValueError("a bug")))


class LanProbeTests(unittest.TestCase):
    def udp_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        return sock

    def test_traffic_port_bounds(self):
        with self.assertRaisesRegex(AssertionError, "outside"):
            lib_test.probe_lan_listener(self.udp_socket(), None,
                              {"expect": "delivered", "external_port": 65536}, {}, None)
        lib_test.probe_lan_listener(self.udp_socket(), None,
                          {"expect": "blocked", "external_port": 65536,
                           "skip_unrepresentable_port": True}, {}, None)

    def test_traffic_agent_integration(self):
        # Local sockets only; no daemon, Docker, or external network is used.
        server = traffic_agent.create_server(port=0, source4="127.0.0.1", source6="::1")
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for transport, kind in (("udp", socket.SOCK_DGRAM), ("tcp", socket.SOCK_STREAM)):
                with self.subTest(transport=transport):
                    # Pick an available port for the probe's echo listener.
                    with socket.socket(socket.AF_INET, kind) as reserve:
                        reserve.bind(("127.0.0.1", 0))
                        port = reserve.getsockname()[1]
                    spec = {"transport": transport, "internal_port": port,
                            "external_port": port, "external_address": "::ffff:127.0.0.1",
                            "expect": "delivered"}
                    with patch.object(lib_test, "client_address", return_value="127.0.0.1"):
                        lib_test.probe_lan_listener(self.udp_socket(), ("127.0.0.1", 5351), spec, {},
                                          f"http://127.0.0.1:{server.server_port}")
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


class RequestBuilderTests(unittest.TestCase):
    def test_nonce_of(self):
        self.assertEqual(lib_test.nonce_of({"nonce_hex": "ab" * 12}), b"\xab" * 12)
        self.assertEqual(lib_test.nonce_of({}, b"x" * 12), b"x" * 12)
        self.assertEqual(len(lib_test.nonce_of({})), pcp_packet_encoding.NONCE_LENGTH)
        self.assertEqual(len(lib_test.nonce_of({}, length=4)), 4)

    def test_every_request_kind_with_a_payload_has_a_builder(self):
        self.assertLessEqual(set(lib_test.REQUEST_BUILDERS), lib_test.REQUEST_KINDS)
        with self.assertRaisesRegex(ValueError, "unsupported request kind: nope"):
            lib_test.build_request_payload(None, None, {"kind": "nope"})
        self.assertEqual(lib_test.build_request_payload(None, None, {"kind": "raw", "hex": "0102"}), b"\x01\x02")


class FieldCheckTests(unittest.TestCase):
    def test_rules(self):
        variables = {"low": 10}
        lib_test.check_field("lifetime", 20, {"nonzero": True, "min": "$low", "max": 30, "not_equals": 0,
                                               "remember": "kept"}, variables)
        self.assertEqual(variables["kept"], 20)
        for rules, message in (({"nonzero": False}, "lifetime unexpectedly has value 20"),
                               ({"equals": 21}, "lifetime was 20, expected 21"),
                               ({"not_equals": 20}, "lifetime unexpectedly equals 20"),
                               ({"min": 25}, "lifetime 20 is below 25"),
                               ({"max": 15}, "lifetime 20 exceeds 15")):
            with self.subTest(rules=rules), self.assertRaisesRegex(AssertionError, f"^{message}$"):
                lib_test.check_field("lifetime", 20, rules, {})

    def test_case_artifact_name(self):
        args = SimpleNamespace(family="ipv6", capture_dir="/x")
        self.assertEqual(lib_test.case_artifact_name(args, {"protocol": "pcp", "name": "a/b"}), "ipv6-pcp-a_b")

    def test_python_dash_o_is_refused(self):
        here = os.path.dirname(os.path.abspath(__file__))
        result = subprocess.run([sys.executable, "-O", "-c", "import lib_test"], cwd=here,
                                capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without python -O", result.stderr)


class RunCasesTests(unittest.TestCase):
    def run_quietly(self, *args, **kwargs):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            outcomes = lib_test.run_cases(*args, **kwargs)
        return outcomes, out.getvalue() + err.getvalue()

    def test_outcomes_lines_and_summary(self):
        def run(case):
            if case["name"] == "bad":
                raise AssertionError("boom")
        cases = [{"protocol": "pcp", "name": "good"}, {"protocol": "pcp", "name": "bad"},
                 {"protocol": "natpmp", "name": "known", "known_failure": "RFC says so"},
                 {"protocol": "pcp", "name": "later"}]
        cases[2]["fail"] = True
        outcomes, text = self.run_quietly(
            cases, lambda case: run(dict(case, name="bad") if case.get("fail") else case),
            skip=lambda case, done: "needs good" if case["name"] == "later" and done[("pcp", "bad")][0] == "FAIL"
            else None)
        self.assertEqual(outcomes, {("pcp", "good"): ("PASS", ""), ("pcp", "bad"): ("FAIL", "boom"),
                                    ("natpmp", "known"): ("XFAIL", "boom; expected: RFC says so"),
                                    ("pcp", "later"): ("SKIP", "needs good")})
        self.assertIn("PASS pcp/good\n", text)
        self.assertIn("FAIL pcp/bad: boom\n", text)
        self.assertIn("SKIP pcp/later: needs good\n", text)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(lib_test.print_summary(outcomes), 1)
        self.assertEqual(out.getvalue(), "Summary: 1 passed, 1 failed, 1 expected failures, 1 skipped\n")

    def test_the_summary_keeps_cases_outside_the_run_apart_from_skips(self):
        outcomes = {("pcp", "a"): ("FAIL", "boom"), ("pcp", "b"): ("SKIP", "requires wan-renumber fixture"),
                    ("pcp", "c"): ("SKIP", "not selected for this invocation"),
                    ("pcp", "d"): ("SKIP", "excluded by --family filter")}
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(lib_test.print_summary(outcomes), 1)
        self.assertEqual(out.getvalue(),
                         "Summary: 0 passed, 1 failed, 0 expected failures, 1 skipped, 2 not in this run\n")

    def test_failures_around_and_timestamps(self):
        entered = []

        @contextlib.contextmanager
        def around(case):
            entered.append(case["name"])
            yield
        cases = [{"protocol": "pcp", "name": "a"}]
        with self.assertRaises(KeyError):      # not a failure of the case: the run stops
            self.run_quietly(cases, lambda case: {}["x"], around=around)
        outcomes, text = self.run_quietly(cases, lambda case: {}["x"], failures=(Exception,), timestamps=True)
        self.assertEqual(outcomes[("pcp", "a")][0], "FAIL")
        self.assertRegex(text, r"CASE START \S+ a\n")
        self.assertRegex(text, r"CASE END \S+ a\n")
        self.assertEqual(entered, ["a"])


class RunnerOptionsTests(unittest.TestCase):
    def test_a_runner_gets_its_corpus_options(self):
        parser = argparse.ArgumentParser()
        lib_test.add_corpus_arguments(parser, "corpus.yaml")
        args = parser.parse_args(["--list-cases", "--write-status", "results.tsv"])
        self.assertEqual((args.cases, args.list_cases, args.self_test, args.write_status),
                         ("corpus.yaml", True, False, "results.tsv"))

    def test_run_on_socket_sends_to_host_and_port_and_keeps_the_skip_rule(self):
        args = SimpleNamespace(host="127.0.0.1", port=5351, family="ipv4")
        seen = []
        with patch.object(lib_test, "skip_reason", side_effect=lambda case, _args, _outcomes: case.get("why")):
            outcomes = lib_test.run_on_socket(args, [
                {"protocol": "pcp", "name": "a"}, {"protocol": "pcp", "name": "b", "why": "no fixture"}],
                lambda sock, address, case: seen.append((sock.gettimeout(), address, case["name"])))
        self.assertEqual(seen, [(lib_test.TIMEOUT, ("127.0.0.1", 5351), "a")])
        self.assertEqual(outcomes[("pcp", "b")], ("SKIP", "no fixture"))


class ShellScriptTests(unittest.TestCase):
    """What sh -n cannot see in the drivers."""

    TESTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)

    def scripts(self):
        for directory, _subdirectories, names in os.walk(self.TESTS):
            for name in names:
                if name.endswith(".sh"):
                    path = os.path.join(directory, name)
                    with open(path, encoding="utf-8") as handle:
                        yield path, re.sub(r"<<-?\s*'?(\w+)'?\n.*?^\s*\1$", "", handle.read(), flags=re.S | re.M)

    def test_every_called_helper_is_defined(self):
        scripts = list(self.scripts())
        defined = set()
        for _path, text in scripts:
            defined.update(re.findall(r"^\s*([a-z_][a-z0-9_]*)\(\)", text, re.M))
        call = re.compile(r"(?:^\s*|\$\(\s*|\|\s*|&&\s*|\bthen\s+|\belse\s+|!\s+)([a-z][a-z0-9]*_[a-z0-9_]+)(?=[\s)\"]|$)", re.M)
        for path, text in scripts:
            text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
            missing = {name for name in call.findall(text) if name not in defined}
            self.assertFalse(missing, f"{path}: called, defined nowhere")

    def test_nothing_is_sourced_from_the_working_directory(self):
        for path, text in self.scripts():
            self.assertFalse(re.findall(r"^\s*\. [^\"$\s]", text, re.M), f"{path}: ci.sh runs these in a tree without tests")


class DriverSuiteTests(unittest.TestCase):
    def main(self, argv, **overrides):
        parser = argparse.ArgumentParser()
        lib_test.add_corpus_arguments(parser, "corpus.yaml")
        parser.add_argument("--case", action="append")
        calls = []

        def run(_corpus, _args, _cases):
            calls.append("run")
            return {("pcp", "a"): ("PASS", "")}
        hooks = dict(load=lambda args: {"path": args.cases},
                     write_report=lambda _corpus, path, _args: calls.append(f"report {path}"),
                     self_test=lambda _corpus: calls.append("self-test"),
                     select=lambda _corpus, _args: [{"section": "S", "name": "a"}],
                     validate=lambda _corpus: calls.append("validate"), run=run)
        hooks.update(overrides)
        with patch.object(sys, "argv", ["runner"] + argv), contextlib.redirect_stdout(io.StringIO()) as output, \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            try:
                status = lib_test.run_driver_suite(parser, **hooks)
            except SystemExit as error:
                status = error.code
        return status, calls, output.getvalue(), errors.getvalue()

    def test_a_run_validates_then_runs(self):
        status, calls, output, _errors = self.main([])
        self.assertEqual((status, calls), (0, ["validate", "run"]))
        self.assertIn("Summary: 1 passed", output)

    def test_self_test_and_report_read_only_the_corpus(self):
        self.assertEqual(self.main(["--self-test"])[:2], (0, ["self-test"]))
        self.assertEqual(self.main(["--write-status", "r.tsv"])[:2], (0, ["report r.tsv"]))

    def test_the_list_needs_no_validation_and_has_the_flag(self):
        status, calls, output, _errors = self.main(["--list-cases"], flag=lambda _corpus: lambda _case: False)
        self.assertEqual((status, calls, output), (0, [], "S\ta\tfalse\n"))

    def test_a_case_of_the_other_family_is_an_empty_run_when_the_suite_allows_it(self):
        none = lambda _corpus, _args: []  # noqa: E731
        self.assertEqual(self.main(["--case", "a"], select=none)[0], 2)
        status, calls, _output, _errors = self.main(["--case", "a"], select=none, empty_case_ok=True)
        self.assertEqual((status, calls), (0, ["validate", "run"]))
        self.assertEqual(self.main([], select=none, empty_case_ok=True)[0], 2)

    def test_an_empty_or_wrong_selection_is_a_usage_error(self):
        status, calls, _output, errors = self.main([], select=lambda _corpus, _args: [])
        self.assertEqual((status, calls), (2, ["validate"]))
        self.assertIn("no matching cases", errors)

        def wrong(_corpus, _args):
            raise lib_test.CorpusError("unknown case(s): typo")
        self.assertIn("typo", self.main([], select=wrong)[3])


class SelectionOptionTests(unittest.TestCase):
    """A runner without pcp_wire's options gets what their defaults mean."""

    cases = [{"protocol": "pcp", "name": "a", "families": ["ipv4"], "requires": []}]

    def test_selection_and_skip_with_only_family_and_case(self):
        args = SimpleNamespace(family="ipv4", case=None)
        self.assertEqual([case["name"] for case in lib_test.select_cases(args, self.cases, {"baseline": {}},
                                                                               {"pcp/a": self.cases[0]})], ["a"])
        self.assertIsNone(lib_test.skip_reason(self.cases[0], args, {}))
        self.assertIn("--phase", lib_test.skip_reason({"requires": ["lease-restart"]}, args, {}))

    def test_target_options_and_a_checked_corpus(self):
        parser = argparse.ArgumentParser()
        lib_test.add_target_arguments(parser)
        args = parser.parse_args(["--host", "192.0.2.1", "--case", "a"])
        self.assertEqual((args.host, args.port, args.family, args.case), ("192.0.2.1", 5351, "ipv4", ["a"]))


class CaseSelectionTests(unittest.TestCase):
    corpus = {"sections": [{"name": "S", "cases": [{"name": "a", "families": ["ipv4"]}, {"name": "b"}]}]}

    def test_a_typo_beside_a_good_name_is_refused(self):
        args = SimpleNamespace(family="ipv4", case=["a", "typo"])
        with self.assertRaisesRegex(lib_test.CorpusError, "unknown case.*typo"):
            lib_test.select_family_cases(self.corpus, args, dict)

    def test_family_case_and_keep_narrow_the_selection(self):
        names = lambda **fields: [case["name"] for case in lib_test.select_family_cases(  # noqa: E731
            self.corpus, SimpleNamespace(**fields), dict)]
        self.assertEqual(names(family="ipv6", case=None), ["b"])
        self.assertEqual(names(family="ipv4", case=["b"]), ["b"])
        kept = lib_test.select_family_cases(self.corpus, SimpleNamespace(family="ipv4", case=None), dict,
                                            lambda case: case["name"] == "a")
        self.assertEqual([case["name"] for case in kept], ["a"])

    def test_the_rows_of_a_driver(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            lib_test.print_case_rows([{"section": "S", "name": "a"}], lambda _case: True)
            lib_test.print_case_rows([{"section": "S", "name": "a"}])
        self.assertEqual(output.getvalue(), "S\ta\ttrue\nS\ta\n")


class RouterCallTests(unittest.TestCase):
    LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e_lib.sh")

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = directory.name

    def test_without_a_driver_the_case_fails(self):
        with self.assertRaisesRegex(AssertionError, "router-call-dir"):
            lib_test.router_call(None, "restart")

    def test_an_unanswered_call_ends(self):
        with self.assertRaisesRegex(AssertionError, "did not answer 'restart'"):
            lib_test.router_call(self.directory, "restart", timeout=0.1)

    def test_the_shell_side_answers_and_a_driver_can_replace_the_commands(self):
        script = f""". "{self.LIB}"
router_call() {{ echo "did $1"; }}
for _try in $(seq 1 100); do e2e_serve_router_calls "$1" && exit 0; sleep 0.05; done
exit 1
"""
        server = subprocess.Popen(["sh", "-c", script, "sh", self.directory])
        self.addCleanup(server.wait)
        self.assertEqual(lib_test.router_call(self.directory, "restart", timeout=10), "did restart\n")
        self.assertEqual(os.listdir(self.directory), [])

    def test_a_wipe_of_the_rules_must_remove_some(self):
        for answer, wanted in (("3 0", None), ("0 0", "0 rules before"), ("3 1", "1 after"), ("boom", "answered")):
            with self.subTest(answer=answer), patch.object(lib_test, "router_call", return_value=answer):
                if wanted:
                    with self.assertRaisesRegex(AssertionError, wanted):
                        lib_test.lose_firewall_rules("calls")
                else:
                    lib_test.lose_firewall_rules("calls")

    def test_an_unknown_command_of_the_default_driver_is_named_in_the_answer(self):
        script = f""". "{self.LIB}"; e2e_serve_router_calls "$1"; echo "served $?"; for f in "$1"/*.resp; do cat "$f"; done"""
        with open(os.path.join(self.directory, "1.req"), "w", encoding="utf-8") as request:
            request.write("nonsense")
        output = subprocess.run(["sh", "-c", script, "sh", self.directory], capture_output=True, text=True, check=True).stdout
        self.assertEqual(output, "served 0\nunknown router command: nonsense\n")


class StatusReportTests(unittest.TestCase):
    sections = [
        {"title": "First | section", "description": "About the first.",
         "cases": [{"protocol": "pcp", "name": "a", "families": ["ipv4", "ipv6"], "description": "Case a."},
                   {"protocol": "natpmp", "name": "b", "families": ["ipv4"], "description": "Case b."}]},
        {"title": "Second", "description": "About the second.",
         "cases": [{"protocol": "pcp", "name": "c", "families": ["ipv4"], "description": "Case c."}]},
    ]

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.report = os.path.join(directory.name, "status.md")
        self.data = os.path.join(directory.name, "data", "status-data.json")

    def write(self, platform, family, results, run=None, sections=None, **extra):
        lib_test.write_status(self.report, "Demo", "demo", platform, family, run or {"target": "host:5351"},
                                  results, sections or self.sections, data_path=self.data, **extra)
        with open(self.report, encoding="utf-8") as report:
            return report.read()

    def test_runs_ending_together_lose_no_result(self):
        names = [f"case-{number}" for number in range(8)]
        sections = [{"title": "S", "description": "", "cases": [
            {"protocol": "pcp", "name": name, "families": ["ipv4"], "description": ""} for name in names]}]

        def run(name):
            for _round in range(20):
                lib_test.write_status(self.report, "Demo", "demo", name, "ipv4", {"target": "x"},
                                      {f"pcp/{name}": ("PASS", "")}, sections, data_path=self.data)
        children = [multiprocessing.get_context("fork").Process(target=run, args=(name,)) for name in names]
        for child in children:
            child.start()
        for child in children:
            child.join()
        with open(self.data, encoding="utf-8") as handle:
            data = handle.read()
        for name in names:
            self.assertIn(f'"{name}"', data)

    def test_a_lock_file_of_another_user_does_not_stop_the_report(self):
        os.makedirs(os.path.dirname(self.data))
        with open(self.data + ".lock", "w", encoding="utf-8"):
            pass
        os.chmod(self.data + ".lock", 0o444)
        self.assertIn("| a | pcp | ipv4 | PASS |", self.write("linux", "ipv4", {"pcp/a": ("PASS", "")}))

    def test_driver_results_go_to_their_family_and_unknown_lines_are_left_out(self):
        results = os.path.join(os.path.dirname(self.report), "results.tsv")
        with open(results, "w", encoding="utf-8") as handle:
            handle.write("ipv4\tFirst\ta\tPASS\tok\tfile\nipv6\tFirst\ta\tFAIL\tboom\tfile\n"
                         "ipv4\tFirst\tgone\tPASS\tok\tfile\nshort\tline\n")
        args = SimpleNamespace(status_file=self.report, status_data_file=self.data, platform="linux",
                               run_info=["router=x"])
        lib_test.write_driver_status(results, args, "Demo", "demo", self.sections)
        with open(self.report, encoding="utf-8") as handle:
            report = handle.read()
        self.assertIn("| a | pcp | ipv4 | PASS |", report)
        self.assertIn("| a | pcp | ipv6 | FAIL | boom |", report)
        self.assertNotIn("gone", report)

    def test_results_of_a_runner_read_back_with_a_note_of_several_lines(self):
        results = os.path.join(os.path.dirname(self.report), "results.tsv")
        cases = [{"protocol": "pcp", "name": "a", "section": "First"}, {"protocol": "pcp", "name": "c", "section": "Second"}]
        lib_test.write_results_tsv(results, "ipv4", cases, {("pcp", "a"): ("FAIL", "one\ttwo\nthree")})
        args = SimpleNamespace(status_file=self.report, status_data_file=self.data, platform="linux", run_info=[])
        lib_test.write_driver_status(results, args, "Demo", "demo", self.sections)
        with open(self.report, encoding="utf-8") as handle:
            self.assertIn("| a | pcp | ipv4 | FAIL | one two three |", handle.read())

    def test_the_report_self_test_fails_a_report_that_loses_a_column(self):
        case = {"name": "a", "section": "First"}
        def no_columns(_path, args):
            with open(args.status_file, "w", encoding="utf-8") as report:
                report.write("| Case | Protocol | Family | linux | Result / note |\n")
        with self.assertRaises(AssertionError):
            lib_test.check_report_columns(no_columns, case, "pcp")
        with contextlib.redirect_stdout(io.StringIO()):
            lib_test.check_report_columns(lambda path, args: lib_test.write_driver_status(
                path, args, "Demo", "demo", self.sections), case, "pcp")

    def test_a_describe_function_gives_the_description(self):
        corpus = {"sections": [{"name": "S", "cases": [{"name": "x", "request": {"pcp": "MAP"}, "description": "d"}]}]}
        self.assertEqual(lib_test.status_sections(corpus, lambda _case: "upnp", lambda case: case["description"] + "!")
                         [0]["cases"][0]["description"], "d!")

    def test_a_run_of_a_corpus_section_keeps_the_given_protocol(self):
        corpus = {"sections": [{"name": "S", "cases": [{"name": "x", "exposure": [], "families": ["ipv4"]}]}]}
        self.assertEqual(lib_test.status_sections(corpus, lambda _case: "upnp")[0]["cases"][0]["protocol"], "upnp")

    def test_one_column_per_platform_and_a_run_replaces_only_its_own_family(self):
        self.write("linux", "ipv4", {"pcp/a": ("PASS", ""), "natpmp/b": ("FAIL", "boom"), "pcp/c": ("XFAIL", "known")})
        self.write("linux", "ipv6", {"pcp/a": ("PASS", "")})
        report = self.write("freebsd", "ipv4", {"pcp/a": ("FAIL", "pf says no"), "natpmp/b": ("PASS", "")})
        self.assertIn("# Demo Test Status", report)
        self.assertIn("| Case | Protocol | Family | linux | freebsd | Result / note |", report)
        self.assertIn("| a | pcp | ipv4 | PASS | FAIL | freebsd: pf says no |", report)
        self.assertIn("| a | pcp | ipv6 | PASS | — | Case a. |", report)
        self.assertIn("| b | natpmp | ipv4 | FAIL | PASS | linux: boom |", report)
        self.assertIn("| c | pcp | ipv4 | XFAIL | — | linux: known |", report)
        self.assertIn("### First \\| section", report)
        self.assertIn("- **linux**: **2 PASS**, **1 XFAIL**, **1 FAIL**, **0 SKIP**", report)
        self.assertIn("- **freebsd**: **1 PASS**, **0 XFAIL**, **1 FAIL**, **0 SKIP**", report)
        self.assertIn("ipv4: target `host:5351`", report)
        # the second linux ipv4 run replaces the ipv4 results of linux and leaves ipv6 and freebsd alone
        report = self.write("linux", "ipv4", {"pcp/a": ("FAIL", "now broken")})
        self.assertIn("| a | pcp | ipv4 | FAIL | FAIL | linux: now broken; freebsd: pf says no |", report)
        self.assertIn("| a | pcp | ipv6 | PASS | — |", report)

    def test_the_raw_results_are_written_to_the_data_path(self):
        self.write("linux", "ipv4", {"pcp/a": ("PASS", "")}, run={"target": "x"})
        with open(self.data, encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(data["version"], 1)
        self.assertEqual(data["platforms"]["linux"]["results"], {"ipv4": {"pcp/a": ["PASS", ""]}})
        self.assertEqual(data["platforms"]["linux"]["runs"], {"ipv4": {"target": "x"}})
        self.assertFalse(os.path.exists(os.path.splitext(self.report)[0] + "-data.json"))

    def test_a_section_without_results_is_left_out_and_cases_gone_from_the_corpus_are_forgotten(self):
        report = self.write("linux", "ipv4", {"pcp/a": ("PASS", ""), "pcp/gone": ("PASS", "")})
        self.assertNotIn("### Second", report)
        self.write("linux", "ipv4", {"pcp/a": ("PASS", "")})
        with open(self.data, encoding="utf-8") as handle:
            self.assertEqual(list(json.load(handle)["platforms"]["linux"]["results"]["ipv4"]), ["pcp/a"])

    def test_a_skip_for_a_missing_fixture_keeps_the_earlier_result(self):
        self.write("linux", "ipv4", {"pcp/a": ("PASS", "")})
        keep = ("requires daemon-restart fixture",)
        report = self.write("linux", "ipv4", {"pcp/a": ("SKIP", "requires daemon-restart fixture (--fixture)")},
                            keep_if_skipped=keep)
        self.assertIn("| a | pcp | ipv4 | PASS |", report)
        report = self.write("linux", "ipv4", {"pcp/a": ("SKIP", "requires --mutating")}, keep_if_skipped=keep)
        self.assertIn("| a | pcp | ipv4 | SKIP |", report)

    def test_platforms_are_in_a_fixed_order_and_extra_lines_follow_them(self):
        self.write("freebsd", "ipv4", {"pcp/a": ("PASS", "")})
        report = self.write("linux", "ipv4", {"pcp/a": ("PASS", "")}, extra_lines=["- Artifacts: `x`"])
        self.assertLess(report.index("- **linux**"), report.index("- **freebsd**"))
        self.assertLess(report.index("- Artifacts: `x`"), report.index("## Results by section"))

    def test_the_data_of_a_suite_lives_in_the_repository_tmp_not_in_the_tests(self):
        path = lib_test.status_data_path("pcp_demo")
        self.assertEqual(path, os.path.join(lib_test.repo_root(), ".tmp", "tests", "pcp_demo", "status-data.json"))
        self.assertTrue(os.path.exists(os.path.join(lib_test.repo_root(), "miniupnpd", "tests", "common",
                                                    "lib_test.py")))
        self.assertNotIn(os.path.join("miniupnpd", "tests"), path)

    def test_a_damaged_data_file_starts_again(self):
        os.makedirs(os.path.dirname(self.data))
        with open(self.data, "w", encoding="utf-8") as handle:
            handle.write("not json")
        report = self.write("linux", "ipv4", {"pcp/a": ("PASS", "")})
        self.assertIn("| a | pcp | ipv4 | PASS |", report)


# The daemon-restart case


def fake_fixture(files):
    """A subprocess.run which plays the fixture of the daemon-restart cases: it writes `files` into the
    directory it is given (the second last argument of the command)."""
    def fake(command, **_kwargs):
        for name, data in files.items():
            with open(os.path.join(command[-2], name), "wb") as handle:
                handle.write(data)
        return subprocess.CompletedProcess(command, 0, "", "")
    return fake


def restart_args(family):
    return SimpleNamespace(fixture="fixture.sh", capture_dir=None, family=family)


class DaemonRestartTests(unittest.TestCase):
    def test_unsolicited_announce_fixture(self):
        payload = bytes([2, 128, 0, 0]) + bytes(20)
        udp = struct.pack("!HHHH", 5351, 5350, 8 + len(payload), 0) + payload
        ethernet = bytes(12)
        ipv4 = (ethernet + b"\x08\x00" + bytes([0x45, 0, 0, 20 + len(udp), 0, 0, 0, 0, 1, 17, 0, 0])
                + bytes([192, 168, 1, 1]) + bytes([224, 0, 0, 1]) + udp)
        ipv6 = (ethernet + b"\x86\xdd" + bytes([0x60, 0, 0, 0, 0, len(udp), 17, 1])
                + ipaddress.ip_address("fd42::1").packed + ipaddress.ip_address("ff02::1").packed + udp)

        def pcap(*frames, times=None):
            data = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            for index, frame in enumerate(frames):
                micro = int((times[index] if times else 0) * 1e6)
                data += struct.pack("<IIII", micro // 1000000, micro % 1000000, len(frame), len(frame)) + frame
            return data

        case = {"name": "x", "protocol": "pcp",
                "expect": {"kind": "unsolicited_announce", "source_port": 5351,
                           "destination_port": 5350, "length": 24, "version": 2, "opcode": 128,
                           "result": [0], "lan": "every", "wan": "none",
                           "destinations": {"ipv4": "224.0.0.1", "ipv6": "ff02::1"}}}

        def run(files, family):
            with patch.object(subprocess, "run", fake_fixture(files)):
                run_daemon_restart(case, restart_args(family))

        both = {"lan-0.pcap": pcap(ipv4, ipv6), "lan-1.pcap": pcap(ipv4, ipv6), "wan-0.pcap": pcap()}
        for family in ("ipv4", "ipv6"):
            run(both, family)
        with self.assertRaisesRegex(AssertionError, "no ANNOUNCE .* on lan-1"):
            run({**both, "lan-1.pcap": pcap(ipv6)}, "ipv4")
        with self.assertRaisesRegex(AssertionError, "leaked on wan-0"):
            run({**both, "wan-0.pcap": pcap(ipv4)}, "ipv4")
        run({**both, "wan-0.pcap": pcap(ipv6)}, "ipv4")  # other family is not this case's leak

        repeat = {**case, "expect": {**case["expect"], "min_count": 2, "max_count": 10,
                                     "min_first_gap_ms": 250, "min_gap_ratio": 1.9}}

        def run_repeat(times, epochs=None):
            epochs = epochs or [0] * len(times)
            frames = []
            for epoch in epochs:
                frame = bytearray(ipv4)
                frame[14 + 20 + 8 + 8:14 + 20 + 8 + 12] = struct.pack("!I", epoch)
                frames.append(bytes(frame))
            files = {"lan-0.pcap": pcap(*frames, times=times), "wan-0.pcap": pcap()}
            with patch.object(subprocess, "run", fake_fixture(files)):
                run_daemon_restart(repeat, restart_args("ipv4"))

        run_repeat([0, 0.25, 0.75, 1.75, 3.75], [5, 5, 5, 6, 8])
        with self.assertRaisesRegex(AssertionError, "1 ANNOUNCE packet"):
            run_repeat([0])
        with self.assertRaisesRegex(AssertionError, "first gap 100 ms"):
            run_repeat([0, 0.1, 0.5])
        with self.assertRaisesRegex(AssertionError, "does not grow"):
            run_repeat([0, 0.25, 0.5, 0.75])
        with self.assertRaisesRegex(AssertionError, "Epoch Time decreased"):
            run_repeat([0, 0.25, 0.75], [5, 4, 4])
        with self.assertRaisesRegex(AssertionError, "no LAN or WAN capture"):
            run({"wan-0.pcap": pcap()}, "ipv4")


def map_reply(request, result=0, epoch=10, external="198.51.100.1", options=b""):
    """A MAP response for the MAP `request`: header, the request's nonce and internal port, `external`."""
    header = struct.pack("!BBBBII", 2, 0x81, 0, result, 3600, epoch) + bytes(12)
    body = (request[24:36] + bytes((request[36], 0, 0, 0)) + request[40:42] + struct.pack("!H", 40140)
            + v6_address(external))
    return header + body + options


class WanRenumberTests(unittest.TestCase):
    request = pcp_packet_encoding.pcp_mapping_request(
        2, 1, 3600, v6_address("127.0.0.1"), 17, 40140, 0, b"\x5a" * 12, v6_address("::"), None, b"", 0)
    expect = {"kind": "mapping_update", "source_port": 5351, "version": 2, "result": [0],
              "same_internal_port": True, "external_address": "changed"}

    def problems(self, updates, expect=None, created=None, port=5351):
        return lib_test.mapping_update_problems(updates, self.request, created or map_reply(self.request),
                                                expect or self.expect, port)

    def test_updates_are_checked(self):
        update = map_reply(self.request, external="198.51.100.3")
        self.assertEqual(self.problems([(0.0, update)]), [])
        self.assertIn("no Mapping Update", self.problems([])[0])
        self.assertIn("old external address", self.problems([(0.0, map_reply(self.request))])[0])
        self.assertIn("result", self.problems([(0.0, map_reply(self.request, result=11, external="198.51.100.3"))])[0])
        self.assertIn("from port 5350", self.problems([(0.0, update)], port=5350)[0])
        timed = {**self.expect, "count": 3, "min_first_gap_ms": 250, "second_gap_ms": 500, "epoch_nondecreasing": True}
        updates = [(0.0, update), (0.3, update), (0.8, map_reply(self.request, epoch=11, external="198.51.100.3"))]
        self.assertEqual(self.problems(updates, timed), [])
        self.assertIn("first gap 100 ms", self.problems([(0.0, update), (0.1, update), (0.6, update)], timed)[0])
        self.assertIn("expected 3", self.problems(updates[:2], timed)[0])
        self.assertIn("Epoch Time decreased",
                      self.problems([(0.0, update), (0.3, update), (0.8, map_reply(self.request, epoch=9,
                                                                                   external="198.51.100.3"))],
                                    timed)[0])
        self.assertIn("at most 1", self.problems(updates[:2], {**self.expect, "max_count": 1})[0])

    def test_options_of_an_update(self):
        third_party = pcp_packet_encoding.pcp_option(1, v6_address("192.0.2.99"))
        port_set = pcp_packet_encoding.pcp_option(130, bytes.fromhex("0001c73d00"))
        expect = {**self.expect, "options_present": [{"code": 1, "data_hex": v6_address("192.0.2.99").hex()}],
                  "options_absent": [130]}
        self.assertEqual(self.problems([(0.0, map_reply(self.request, external="198.51.100.3",
                                                        options=third_party))], expect), [])
        found = self.problems([(0.0, map_reply(self.request, external="198.51.100.3", options=port_set))], expect)
        self.assertEqual(found, ["update 1 lacks option 1", "update 1 carries option 130"])

    def router(self, plan):
        """A loopback 'router' which, once it has the client's address, sends what `plan` returns."""
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(3)
        thread = threading.Thread(target=plan, args=(server,), daemon=True)
        return server, thread

    def test_receive_updates_and_refresh(self):
        update = map_reply(self.request, external="198.51.100.3")
        other = map_reply(self.request[:24] + b"\x01" * 12 + self.request[36:], external="198.51.100.3")

        def plan(server):
            _data, client = server.recvfrom(2048)             # the client's hello (its address)
            server.sendto(other, client)                       # another mapping's nonce: ignored
            server.sendto(update, client)
            refresh, client = server.recvfrom(2048)            # the refresh after the first update
            server.sendto(update, client)                      # its reply: not an update
            if refresh == self.request:
                server.sendto(update, client)                  # one more update

        server, thread = self.router(plan)
        with server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            thread.start()
            address = server.getsockname()
            client.sendto(b"hello", address)
            updates = lib_test.receive_mapping_updates(client, address, self.request, 1.0, refresh_after_ms=50)
            thread.join(2)
        self.assertEqual([data for _time, data in updates], [update, update])
        self.assertEqual(client.gettimeout(), 1)

    def test_skip_without_a_wan_renumber_fixture(self):
        case = corpus_case("a", requires=["wan-renumber"])
        self.assertIn("wan-renumber", skip_reason(case, selection_args(), {}))
        for code, skipped in ((0, False), (2, True)):
            done = subprocess.CompletedProcess([], code, "", "")
            with patch.object(subprocess, "run", return_value=done) as run:
                self.assertEqual(skip_reason(case, selection_args(fixture="fixture.sh"), {}) is not None, skipped)
            self.assertEqual(run.call_args[0][0], ["fixture.sh", "supports", "wan-renumber"])


class SecondClientTests(unittest.TestCase):
    def test_a_step_sends_from_the_named_client(self):
        main, second = object(), object()
        self.assertIs(lib_test.step_socket(main, {}, {"second-client": second}), main)
        self.assertIs(lib_test.step_socket(main, {"from": "second-client"}, {"second-client": second}), second)
        with self.assertRaisesRegex(AssertionError, "--second-client"):
            lib_test.step_socket(main, {"from": "second-client"}, {})

    def test_client_sockets_are_bound_to_the_second_address(self):
        args = SimpleNamespace(second_client="127.0.0.2", family="ipv4")
        with lib_test.client_sockets(args) as clients:
            sock = clients["second-client"]
            self.assertEqual(sock.getsockname()[0], "127.0.0.2")
            self.assertEqual(lib_test.client_address(sock, ("127.0.0.1", 5351)), "127.0.0.2")
        self.assertEqual(sock.fileno(), -1)
        with lib_test.client_sockets(SimpleNamespace(second_client=None, family="ipv4")) as clients:
            self.assertEqual(clients, {})

    def test_cleanup_deletes_a_peer_mapping_with_lifetime_zero(self):
        peer = {"opcode": "PEER", "lifetime": 100, "remote_peer": "allowed-peer", "filter": {}}
        self.assertEqual(lib_test.cleanup_request(peer), {"opcode": "PEER", "lifetime": 0, "remote_peer": "allowed-peer"})

    def case_run(self, send, traffic=None):
        args = SimpleNamespace(client_address="10.0.0.2", family="ipv4", external_address="198.51.100.1")
        run = lib_test.CaseRun({"name": "a", "expect": {"results": []}, "request": []}, args, {}, None)
        run.requests = []
        run.active = {("UDP", 1): ({"lifetime": 9}, 1, None), ("UDP", 2): ({"lifetime": 9}, 2, None)}
        run.send = send
        run.close = lambda: None
        run.run_traffic = traffic or (lambda _traffic: None)
        return run

    def test_cleanup_tries_every_mapping_and_reports_the_failures(self):
        sent = []

        def send(_spec, _nonce):
            sent.append(1)
            raise TimeoutError("no answer")
        with self.assertRaisesRegex(AssertionError, "cleanup of PCP UDP/1 .*cleanup of PCP UDP/2"):
            self.case_run(send).cleanup()
        self.assertEqual(len(sent), 2)

    def test_a_cleanup_failure_does_not_hide_the_failure_of_the_case(self):
        def traffic(_traffic):
            raise AssertionError("the real failure")
        with self.assertRaisesRegex(AssertionError, "the real failure"):
            self.case_run(lambda _spec, _nonce: ("MALFORMED_REQUEST", None, None), traffic).run()
        with self.assertRaisesRegex(AssertionError, "cleanup of"):
            self.case_run(lambda _spec, _nonce: ("MALFORMED_REQUEST", None, None)).run()

    def test_scale_cases_are_opt_in(self):
        case = corpus_case("a", requires=["scale"])
        self.assertIn("--scale", skip_reason(case, selection_args(), {}))
        self.assertIsNone(skip_reason(case, selection_args(scale=True), {}))

    def test_skip_without_a_second_client(self):
        case = corpus_case("a", requires=["second-client"])
        self.assertIn("--second-client", skip_reason(case, selection_args(), {}))
        self.assertIsNone(skip_reason(case, selection_args(second_client="192.0.2.200"), {}))


class BulkTests(unittest.TestCase):
    spec = {"template": {"pcp": "PEER", "protocol": "UDP", "peer": "192.0.2.20"}, "count": 25, "window": 5,
            "internal_port": {"first": 30000, "count": 5}, "peer_port": {"first": 20000},
            "nonce_prefix": "b0" * 8}

    def test_requests_of_a_pass(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            requests = lib_test.bulk_requests(sock, ("127.0.0.1", 5351), self.spec, 300)
        self.assertEqual(len(requests), 25)
        self.assertEqual(len({request[24:36] for request in requests}), 25)
        last = requests[-1]
        self.assertEqual(last[1], 2)                                        # PEER
        self.assertEqual(struct.unpack("!I", last[4:8])[0], 300)            # lifetime
        self.assertEqual(struct.unpack("!H", last[40:42])[0], 30004)        # 30000 + 24 % 5
        self.assertEqual(struct.unpack("!H", last[60:62])[0], 20004)        # 20000 + 24 // 5
        self.assertEqual(last[24:36], bytes.fromhex("b0" * 8) + struct.pack("!I", 24))

    def test_window_bounds_the_requests_in_flight(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            requests = lib_test.bulk_requests(sock, ("127.0.0.1", 5351), self.spec, 300)
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(0.2)
        held_most = []
        dropped = []

        def serve():
            answered = set()
            while len(answered) < len(requests):
                held = []
                while True:                     # take what the client sends until it waits
                    try:
                        held.append(server.recvfrom(2048))
                    except socket.timeout:
                        break
                held_most.append(len(held))
                for data, client in held:
                    if data[24:36] == requests[3][24:36] and not dropped:
                        dropped.append(data)    # lose request 3 once: the client sends it again
                        continue
                    reply = bytes((2, data[1] | 0x80, 0, 0)) + data[4:]
                    server.sendto(reply, client)
                    answered.add(data[24:36])

        thread = threading.Thread(target=serve, daemon=True)
        with server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            thread.start()
            responses, lost = lib_test.send_windowed(client, server.getsockname(), requests, 5, retry_after=0.5)
            thread.join(5)
        self.assertEqual(lost, [])
        self.assertEqual(sorted(responses), list(range(25)))
        self.assertTrue(dropped)
        self.assertLessEqual(max(held_most), 5)
        self.assertEqual(client.gettimeout(), 1)

    def test_lost_requests_are_reported(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            silent.bind(("127.0.0.1", 0))
            requests = lib_test.bulk_requests(client, silent.getsockname(), {**self.spec, "count": 3}, 300)
            client.settimeout(1)
            responses, lost = lib_test.send_windowed(client, silent.getsockname(), requests, 2,
                                                     retry_after=0.05, tries=2)
        self.assertEqual((responses, lost), ({}, [0, 1, 2]))


# The corpus, selection and step-engine code the pcp_wire runner uses


class LifecycleRequestTests(unittest.TestCase):
    def test_version_one_map_has_no_nonce(self):
        variables = {"internal_port": 40000, "client_ip": "192.0.2.5", "nonce": bytes(12)}
        step = {"lifetime": 60, "external_port": 0}
        for version, size in ((1, 48), (2, 60)):
            spec = {"operation": "pcp_map", "version": version, "opcode": 1, "protocol_number": 17}
            with self.subTest(version=version):
                request = build_lifecycle_request({"protocol": "pcp"}, spec, step, variables)
                self.assertEqual(len(request), size)


class FakeSocket:
    family = socket.AF_INET

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.sent = []
        self.timeout = lib_test.TIMEOUT

    def sendto(self, data, address):
        self.sent.append((data, address))

    def recvfrom(self, size):
        if not self.responses:
            raise socket.timeout()
        return self.responses.pop(0), ("192.0.2.1", 5351)

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout


class StepEngineTests(unittest.TestCase):
    def test_response_order_and_duplicates(self):
        # Synthetic NAT-PMP replies exercise matching independently of case names.
        replies = [struct.pack("!BBHII", 0, 128, 0, 1, value) for value in (1, 2)]
        step = {"protocol": "natpmp", "request": {"kind": "raw", "hex": "0000"},
                "no_extra_responses": True,
                "responses": [{"expect": {"version": 0, "opcode": 128, "result": [0],
                                          "length": len(replies[0])},
                               "captures": {"value": {"type": "u32", "offset": 8}},
                               "assert": {"value": {"equals": value}}} for value in (1, 2)]}
        for responses in (replies, replies[::-1]):
            sock = FakeSocket(responses)
            run_protocol_step(sock, ("192.0.2.1", 5351), step, {})
            self.assertEqual(len(sock.sent), 1)
            self.assertEqual(sock.timeout, lib_test.TIMEOUT)
        for responses in ([replies[0], replies[0]], replies + replies[:1]):
            sock = FakeSocket(responses)
            with self.subTest(responses=responses), self.assertRaises(AssertionError):
                run_protocol_step(sock, ("192.0.2.1", 5351), step, {})
            self.assertEqual(sock.timeout, lib_test.TIMEOUT)

    def test_status_report_merges_platforms(self):
        case = {"name": "startup", "protocol": "pcp", "families": ["ipv4"], "description": "d"}
        other = {"name": "other", "protocol": "pcp", "families": ["ipv4"], "description": "o"}
        sections = [{"title": "T", "description": "D", "cases": [case, other]}]

        def report(platform, outcomes):
            write_status_report(path, "PCP/NAT-PMP", "pcp_wire", platform, "ipv4", {"target": "h:1"}, sections,
                                outcomes, data_path=os.path.join(directory, "status-data.json"))
            with open(path, encoding="utf-8") as handle:
                return handle.read()

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "status.md")
            report("linux", {("pcp", "startup"): ("PASS", ""), ("pcp", "other"): ("PASS", "")})
            text = report("freebsd", {("pcp", "startup"): ("FAIL", "leaked on wan-0"),
                                      ("pcp", "other"): ("SKIP", "not selected for this invocation")})
            self.assertIn("| startup | pcp | ipv4 | PASS | FAIL | freebsd: leaked on wan-0 |", text)
            self.assertIn("| other | pcp | ipv4 | PASS | — |", text)
            # A later Linux run replaces only Linux's column.
            text = report("linux", {("pcp", "startup"): ("FAIL", "x"), ("pcp", "other"): ("PASS", "")})
            self.assertIn("| startup | pcp | ipv4 | FAIL | FAIL | linux: x; freebsd: leaked on wan-0 |", text)


class ExchangeCaseTests(unittest.TestCase):
    def test_a_case_with_a_silent_daemon_must_not_get_an_answer(self):
        sock = FakeSocket()
        silent_case = {"protocol": "pcp", "request": {"kind": "pcp_header", "version": 2, "opcode": 0, "lifetime": 0,
                                                      "client": "127.0.0.1"}, "expect": {"kind": "silence"}}
        run_exchange_case(sock, ("127.0.0.1", 5351), silent_case)
        self.assertEqual(len(sock.sent), 1)


def corpus_case(name, protocol="pcp", families=("ipv4",), **extra):
    result = {"name": name, "protocol": protocol, "families": list(families),
              "request": {"kind": "raw"}, "expect": {"kind": "silence"}}
    result.update(extra)
    return result


def selection_args(**overrides):
    values = dict(profile="baseline", protocol="both", family="ipv4", fixture_only=False, case=None,
                  allow_empty_selection=False, mutating=False, peer_url=None, unsupported=[], phase=None,
                  fixture=None)
    values.update(overrides)
    return SimpleNamespace(**values)


class CorpusTests(unittest.TestCase):
    profiles = {"baseline": {}, "extra": {}}

    def test_validation_errors(self):
        for bad, message in (
                (corpus_case("a", request={"kind": "nope"}), "unsupported request kind"),
                (corpus_case("a", expect={"kind": "nope"}), "unsupported expectation kind"),
                (corpus_case("a", expect={"kind": "response", "version": 2}), "response expectation incomplete"),
                (corpus_case("a", profiles=["missing"]), "unknown server profile"),
                (corpus_case("a", requires=["nothing"]), "unknown required fixture"),
                (corpus_case("a", depends_on="pcp/x"), "depends_on must be a list"),
                (corpus_case("a", depends_on=["pcp/later"]), "must be an earlier case")):
            with self.subTest(message=message), self.assertRaisesRegex(CorpusError, message):
                validate_cases([bad], self.profiles)
        with self.assertRaisesRegex(CorpusError, "duplicate case names"):
            validate_cases([corpus_case("a"), corpus_case("a")], self.profiles)
        with self.assertRaisesRegex(CorpusError, "needs name"):
            validate_cases([{"name": "a"}], self.profiles)

    def test_prerequisites_must_cover_family_and_profile(self):
        first = corpus_case("first", families=("ipv4",))
        with self.assertRaisesRegex(CorpusError, "lacks a required family"):
            validate_cases([first, corpus_case("second", families=("ipv4", "ipv6"), depends_on=["pcp/first"])], self.profiles)
        with self.assertRaisesRegex(CorpusError, "lacks a required profile"):
            validate_cases([corpus_case("first", profiles=["baseline"]),
                            corpus_case("second", profiles=["baseline", "extra"], depends_on=["pcp/first"])], self.profiles)
        known = validate_cases([first, corpus_case("second", depends_on=["pcp/first"])], self.profiles)
        self.assertEqual(sorted(known), ["pcp/first", "pcp/second"])

    def select(self, cases, **overrides):
        known = validate_cases(cases, self.profiles)
        return [c["name"] for c in select_cases(selection_args(**overrides), cases, self.profiles, known)]

    def test_selection_filters(self):
        cases = [corpus_case("v4"), corpus_case("v6", families=("ipv6",)), corpus_case("natpmp-only", protocol="natpmp"),
                 corpus_case("extra-only", profiles=["extra"]), corpus_case("mutates", mutating=True)]
        self.assertEqual(self.select(cases), ["v4", "natpmp-only"])
        self.assertEqual(self.select(cases, mutating=True), ["v4", "natpmp-only", "mutates"])
        self.assertEqual(self.select(cases, family="ipv6"), ["v6"])
        self.assertEqual(self.select(cases, protocol="natpmp"), ["natpmp-only"])
        self.assertEqual(self.select(cases, profile="extra"), ["v4", "natpmp-only", "extra-only"])

    def test_case_selection_errors_and_dependencies(self):
        cases = [corpus_case("base"), corpus_case("needs-base", depends_on=["pcp/base"]), corpus_case("other"),
                 corpus_case("mutates", mutating=True)]
        self.assertEqual(self.select(cases, case=["needs-base"]), ["base", "needs-base"])
        with self.assertRaisesRegex(CorpusError, "unknown case"):
            self.select(cases, case=["nope"])
        with self.assertRaisesRegex(CorpusError, "does not match"):
            self.select(cases, case=["base"], family="ipv6")
        self.assertEqual(self.select(cases, case=["base"], family="ipv6", allow_empty_selection=True), [])
        with self.assertRaisesRegex(CorpusError, "require --mutating"):
            self.select(cases, case=["mutates"])
        self.assertEqual(self.select(cases, case=["mutates"], mutating=True), ["mutates"])

    def test_fixture_only_runs_the_daemon_restart_cases(self):
        cases = [corpus_case("plain"), corpus_case("restarts", requires=["daemon-restart"])]
        self.assertEqual(self.select(cases, fixture_only=True), ["restarts"])

    def test_skip_reasons(self):
        outcomes = {}
        self.assertIsNone(skip_reason(corpus_case("a"), selection_args(), outcomes))
        self.assertIn("wan-peer", skip_reason(corpus_case("a", requires=["wan-peer"]), selection_args(), outcomes))
        self.assertIsNone(skip_reason(corpus_case("a", requires=["wan-peer"]), selection_args(peer_url="http://x"), outcomes))
        self.assertEqual(skip_reason(corpus_case("a", requires=["pcp-peer"]), selection_args(unsupported=["pcp-peer"]), outcomes),
                         "requires pcp-peer, unsupported on this platform")
        self.assertIn("wan-renumber", skip_reason(corpus_case("a", requires=["wan-renumber"]), selection_args(), outcomes))
        lease = corpus_case("a", requires=["lease-restart"])
        self.assertEqual(skip_reason(lease, selection_args(), outcomes), "requires lease-restart driver (--phase)")
        self.assertIsNone(skip_reason(lease, selection_args(phase="create"), outcomes))
        restart = corpus_case("a", requires=["daemon-restart"])
        self.assertEqual(skip_reason(restart, selection_args(), outcomes), "requires daemon-restart fixture (--fixture)")
        self.assertIsNone(skip_reason(restart, selection_args(fixture="x"), outcomes))

    def test_a_case_is_skipped_when_a_prerequisite_did_not_pass(self):
        dependent = corpus_case("b", depends_on=["pcp/a"])
        self.assertIn("pcp/a (SKIP)", skip_reason(dependent, selection_args(), {}))
        self.assertIn("pcp/a (FAIL)", skip_reason(dependent, selection_args(), {("pcp", "a"): ("FAIL", "x")}))
        self.assertIsNone(skip_reason(dependent, selection_args(), {("pcp", "a"): ("PASS", "")}))

    def test_filter_reason_is_the_text_of_the_report(self):
        base = corpus_case("a", protocol="natpmp", families=("ipv4",), profiles=["baseline"])
        self.assertIsNone(filter_reason(base, selection_args(), self.profiles))
        self.assertEqual(filter_reason(base, selection_args(profile="extra"), self.profiles),
                         "excluded by --profile filter")
        self.assertEqual(filter_reason(base, selection_args(protocol="pcp"), self.profiles),
                         "excluded by --protocol filter")
        self.assertEqual(filter_reason(base, selection_args(family="ipv6"), self.profiles),
                         "excluded by --family filter")
        self.assertIsNone(filter_reason(corpus_case("b", protocol="both"), selection_args(protocol="pcp"), self.profiles))

    def test_with_dependencies_follows_the_chain(self):
        earlier = {"pcp/c": {"depends_on": ["pcp/b"]}, "pcp/b": {"depends_on": ["pcp/a"]}, "pcp/a": {},
                   "pcp/d": {}}
        self.assertEqual(with_dependencies({"pcp/c"}, earlier), {"pcp/a", "pcp/b", "pcp/c"})
        self.assertEqual(with_dependencies({"pcp/d"}, earlier), {"pcp/d"})
        self.assertEqual(with_dependencies(set(), earlier), set())

    def test_unselected_reasons(self):
        def reason(c, selected=(), **overrides):
            return unselected_reason(c, selection_args(**overrides), self.profiles, set(selected))
        self.assertEqual(reason(corpus_case("a", profiles=["extra"])), "excluded by --profile filter")
        self.assertEqual(reason(corpus_case("a", protocol="natpmp"), protocol="pcp"), "excluded by --protocol filter")
        self.assertEqual(reason(corpus_case("a", families=("ipv6",))), "excluded by --family filter")
        self.assertEqual(reason(corpus_case("a"), case=["b"]), "not selected by --case")
        self.assertEqual(reason(corpus_case("a", mutating=True)), "requires --mutating")
        self.assertEqual(reason(corpus_case("a")), "not selected for this invocation")
        self.assertEqual(reason(corpus_case("a"), selected=[("pcp", "a")]), "not run")


# The e2e case: the requests it builds


def check_packet_encoding():
    """The bytes of the PCP MAP / PEER requests the runner builds: FILTER options in RFC order, the
    maximum size, a cleared filter set, PEER; and the NAT-PMP request."""
    addresses = {"allowed-peer": "198.51.100.2", "denied-peer": "198.51.100.130"}
    spec = {"protocol": "udp", "lifetime": 120, "internal_port": 41000,
            "suggested_external_port": 41000, "filter": {"remote_peer": "allowed-peer",
            "remote_port": 42000, "prefix_length": 32}}
    packet, nonce, _ = build_map_packet("172.28.41.2", spec, addresses, bytes(range(12)))
    assert packet[24:36] == nonce
    assert packet[60:64] == bytes((3, 0, 0, 20))
    assert packet[64:68] == bytes((0, 128, 0xA4, 0x10))
    assert packet[68:84] == v6_address(addresses["allowed-peer"])

    spec["filters"] = [spec.pop("filter"), {"remote_peer": "denied-peer",
                                             "remote_port": 0, "prefix_length": 128}]
    spec["filters"][0]["prefix_length"] = 128
    multi, _, _ = build_map_packet("2001:db8:1::2", spec, {
        "allowed-peer": "2001:db8:9000::2", "denied-peer": "2001:db8:9000::130"}, nonce)
    assert multi[60] == 3 and multi[84] == 3
    assert multi[65] == 128 and multi[89] == 128
    max_filter_spec = {
        "protocol": "udp", "lifetime": 120, "internal_port": 41017,
        "suggested_external_port": 41017, "prefer_failure": True,
        "unknown_optional_options": 1,
        "filter": {"remote_peer": "allowed-peer", "remote_port": 0,
                    "prefix_length": 32, "repeat": 43},
    }
    max_filter, _, _ = build_map_packet("172.28.41.2", max_filter_spec, addresses, nonce)
    assert len(max_filter) == 1100
    assert max_filter[-8:] == bytes((2, 0, 0, 0, pcp_packet_encoding.OPTION_UNKNOWN_OPTIONAL, 0, 0, 0))
    spec["filters"] = [{"remote_peer": "::", "remote_port": 0, "prefix_length": 0}]
    cleared, _, _ = build_map_packet("2001:db8:1::2", spec, {}, nonce)
    assert cleared[65:68] == bytes((0, 0, 0))
    peer, _, _ = build_map_packet("172.28.41.2", {
        "opcode": "PEER", "protocol": "udp", "lifetime": 120,
        "internal_port": 41020, "suggested_external_port": 41020,
        "remote_peer": "allowed-peer", "remote_peer_port": 42100,
        "unknown_optional_options": 255,
    }, addresses, nonce)
    assert len(peer) == 1100 and peer[1] == 2
    assert peer[60:64] == bytes((0xA4, 0x74, 0, 0))
    assert peer[64:80] == v6_address(addresses["allowed-peer"])
    natpmp_udp = pcp_packet_encoding.natpmp_packet(1, 41100, 41100, 120)
    assert len(natpmp_udp) == 12 and natpmp_udp[1] == 1
    # a named suggested external address is the one the driver passes for the name
    named, _, _ = build_map_packet("172.28.42.2", {
        "protocol": "udp", "lifetime": 60, "internal_port": 1, "suggested_external_port": 1,
        "suggested_external_address": "router-wan"}, {"router-wan": "198.18.1.1"}, nonce)
    assert named[44:60] == v6_address("198.18.1.1")
    assert str(wan_network("198.18.3.1")) == "198.18.3.0/24"
    assert str(wan_network("2001:db8:9000:3::1")) == "2001:db8:9000:3::/64"


def check_expander():
    """The named form of a request (pcp: MAP, natpmp: TCP, ...) expands to the low-level one, and a wrong
    option order is refused."""
    named = pcp_corpus_expander.expand_e2e_request({
        "pcp": "MAP", "lifetime": 120, "protocol": "udp", "internal_port": 1, "suggested_external_port": 1,
        "options": [{"FILTER": "allowed-peer"}, {"FILTER": {"remote_peer": "denied-peer", "remote_port": 5,
                    "prefix_length": 24}}, "PREFER_FAILURE", {"UNKNOWN_OPTIONAL": 2}]})
    assert named["opcode"] == "MAP" and named["prefer_failure"] and named["unknown_optional_options"] == 2
    assert named["filters"] == [
        {"remote_peer": "allowed-peer", "remote_port": 0, "prefix_length": {"ipv4": 32, "ipv6": 128}},
        {"remote_peer": "denied-peer", "remote_port": 5, "prefix_length": 24}]
    assert pcp_corpus_expander.expand_e2e_request({"natpmp": "TCP", "private_port": 1}) == {
        "protocol_family": "NAT-PMP", "opcode": "TCP", "protocol": "tcp", "private_port": 1}
    try:
        pcp_corpus_expander.expand_e2e_request({"pcp": "MAP", "options": ["PREFER_FAILURE", {"FILTER": "x"}]})
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-order options must be rejected")


def check_upnp_body():
    """The SOAP body of an AddPortMapping / DeletePortMapping request."""
    upnp_add = pcp_corpus_expander.expand_e2e_request({
        "upnp": "AddPortMapping", "protocol": "udp", "internal_port": 41200,
        "external_port": 41201, "lease_duration": 30})
    assert upnp_add["protocol_family"] == "UPnP"
    body = upnp_soap_body(upnp_add, "172.28.41.2")
    assert "<NewExternalPort>41201</NewExternalPort>" in body and "<NewProtocol>UDP</NewProtocol>" in body
    assert "<NewInternalClient>172.28.41.2</NewInternalClient>" in body
    assert "<NewLeaseDuration>30</NewLeaseDuration>" in body and "AddPortMapping" in body
    assert "NewInternalPort" not in upnp_soap_body(dict(upnp_add, action="DeletePortMapping"), "172.28.41.2")


class E2eRequestTests(unittest.TestCase):
    def test_pcp_map_and_peer_packets(self):
        check_packet_encoding()

    def test_named_requests_expand(self):
        check_expander()

    def test_upnp_soap_body(self):
        check_upnp_body()



# The UPnP client code (SSDP, HTTP, description, SOAP, GENA, the upnp steps), against loopback servers


ROOT_DESC = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>1</minor></specVersion>
<device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>test IGD</friendlyName><UDN>uuid:00000000-0000-0000-0000-000000000001</UDN>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
<serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId><SCPDURL>/L3F.xml</SCPDURL>
<controlURL>/ctl/L3F</controlURL><eventSubURL>/evt/L3F</eventSubURL></service></serviceList>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<UDN>uuid:00000000-0000-0000-0000-000000000002</UDN><deviceList><device>
<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<UDN>uuid:00000000-0000-0000-0000-000000000003</UDN><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><SCPDURL>/WANIPCn.xml</SCPDURL>
<controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL></service></serviceList>
</device></deviceList></device></deviceList></device></root>"""

SCPD = """<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>
<actionList><action><name>GetExternalIPAddress</name><argumentList><argument>
<name>NewExternalIPAddress</name><direction>out</direction>
<relatedStateVariable>ExternalIPAddress</relatedStateVariable></argument></argumentList></action>
<action><name>DeletePortMapping</name></action></actionList>
<serviceStateTable><stateVariable sendEvents="yes"><name>ExternalIPAddress</name><dataType>string</dataType>
</stateVariable><stateVariable sendEvents="no"><name>RemoteHost</name><dataType>string</dataType></stateVariable>
</serviceStateTable></scpd>"""


def soap_reply(action, out):
    inner = "".join(f"<{name}>{value}</{name}>" for name, value in out)
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="{lib_test.SOAP_ENVELOPE_NS}"><s:Body>'
            f'<u:{action}Response xmlns:u="urn:x">{inner}</u:{action}Response></s:Body></s:Envelope>')


def soap_fault(code):
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="{lib_test.SOAP_ENVELOPE_NS}"><s:Body><s:Fault>'
            '<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>'
            f'<UPnPError xmlns="{lib_test.UPNP_CONTROL_NS}"><errorCode>{code}</errorCode>'
            '<errorDescription>Conflict</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>')


class FakeIgd:
    """A loopback HTTP server with canned description, SCPD, SOAP and GENA answers; `requests` keeps
    (method, path, headers, body) of each request."""

    def __init__(self, soap=None):
        self.requests = []
        self.soap = soap or {}
        igd = self

        class Handler(lib_test.http.server.BaseHTTPRequestHandler):
            def reply(self, status, body=b"", headers=()):
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def record(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
                igd.requests.append((self.command, self.path, dict(self.headers), body))
                return body

            def do_GET(self):  # noqa: N802
                self.record()
                docs = {"/rootDesc.xml": ROOT_DESC, "/L3F.xml": SCPD, "/WANIPCn.xml": SCPD}
                if self.path in docs:
                    self.reply(200, docs[self.path].encode(), [("Content-Type", "text/xml")])
                else:
                    self.reply(404)

            def do_POST(self):  # noqa: N802
                self.record()
                action = self.headers.get("SOAPAction", "").strip('"').split("#")[-1]
                status, body = igd.soap.get(action, (401, ""))
                self.reply(status, body.encode(), [("Content-Type", 'text/xml; charset="utf-8"')])

            def do_SUBSCRIBE(self):  # noqa: N802
                self.record()
                if self.headers.get("SID") and self.headers.get("NT"):
                    self.reply(400)
                elif self.headers.get("SID") not in (None, "uuid:sub-1"):
                    self.reply(412)
                else:
                    self.reply(200, headers=[("SID", "uuid:sub-1"), ("TIMEOUT", "Second-1800")])

            def do_UNSUBSCRIBE(self):  # noqa: N802
                self.record()
                self.reply(200 if self.headers.get("SID") == "uuid:sub-1" else 412)

            def log_message(self, *_args):
                pass

        self.server = lib_test.http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class SsdpTests(unittest.TestCase):
    def test_parse_ssdp_keys_headers_in_lower_case(self):
        start, headers = lib_test.parse_ssdp(b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: upnp:rootdevice\r\n"
                                             b"EXT:\r\n\r\n")
        self.assertEqual(start, "HTTP/1.1 200 OK")
        self.assertEqual(headers, {"cache-control": "max-age=120", "st": "upnp:rootdevice", "ext": ""})
        with self.assertRaises(ValueError):
            lib_test.parse_ssdp(b"HTTP/1.1 200 OK\r\nno colon here\r\n\r\n")

    def test_msearch_message_leaves_out_none_headers(self):
        message = lib_test.msearch_message("ssdp:all", mx=None, man=None).decode()
        self.assertTrue(message.startswith("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"))
        self.assertNotIn("MX:", message)
        self.assertNotIn("MAN:", message)
        self.assertTrue(message.endswith("ST: ssdp:all\r\n\r\n"))
        self.assertIn("HOST: [ff02::c]:1900", lib_test.msearch_message("x", family="ipv6").decode())
        self.assertNotIn("HOST", lib_test.msearch_message("x", host=False).decode())
        self.assertEqual([lib_test.msearch_wait(mx) for mx in (1, 3, 9, None, "x")], [2, 4, 6, 1, 1])

    def test_msearch_collects_the_responses(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(("127.0.0.1", 0))
            client.bind(("127.0.0.1", 0))
            received = []

            def answer():
                data, source = server.recvfrom(2048)
                received.append(data)
                for st in ("upnp:rootdevice", "uuid:1"):
                    server.sendto(f"HTTP/1.1 200 OK\r\nST: {st}\r\nUSN: uuid:1::{st}\r\n\r\n".encode(), source)
                server.sendto(b"NOTIFY * HTTP/1.1\r\nNTS: ssdp:alive\r\n\r\n", source)
            thread = threading.Thread(target=answer)
            thread.start()
            responses = lib_test.ssdp_msearch(client, server.getsockname(), "ssdp:all", mx=1, wait=0.5)
            thread.join()
        self.assertIn(b"ST: ssdp:all", received[0])
        self.assertEqual([r["headers"]["st"] for r in responses], ["upnp:rootdevice", "uuid:1"])
        values = lib_test.ssdp_values(responses)
        self.assertEqual(values["count"], 2)
        self.assertEqual(values["header.st"], "upnp:rootdevice")


class CannedTcpServer:
    """Accepts one connection, reads a request, sends the canned bytes (None: closes without answering)."""

    def __init__(self, reply):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.received = b""
        self.thread = threading.Thread(target=self.serve, args=(reply,))
        self.thread.start()

    def serve(self, reply):
        connection, _ = self.sock.accept()
        with connection:
            connection.settimeout(2)
            try:
                self.received = connection.recv(65535)
            except socket.timeout:
                pass
            if reply is not None:
                connection.sendall(reply)

    def close(self):
        self.thread.join()
        self.sock.close()


class HttpTests(unittest.TestCase):
    def exchange(self, reply, data=b"GET / HTTP/1.1\r\n\r\n", count=1):
        server = CannedTcpServer(reply)
        try:
            return lib_test.http_exchange("127.0.0.1", server.port, data, count, timeout=2), server.received
        finally:
            server.close()

    def test_content_length_chunked_and_pipelined_responses(self):
        (responses, closed), received = self.exchange(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 500 X\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", count=2)
        self.assertEqual(received, b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual([(r["status"], r["body"]) for r in responses], [(200, b"ok"), (500, b"abcde")])
        self.assertFalse(closed)

    def test_close_without_answer(self):
        (responses, closed), _ = self.exchange(None)
        self.assertEqual(responses, [])
        self.assertTrue(closed)
        server = CannedTcpServer(b"HTTP/1.0 400 Bad Request\r\nServer: x\r\n\r\nbad")
        try:
            status, headers, body = lib_test.http_raw("127.0.0.1", server.port, b"BAD\r\n\r\n", timeout=2)
        finally:
            server.close()
        self.assertEqual((status, headers["server"], body), (400, "x", b"bad"))

    def test_malformed_status_line_fails(self):
        with self.assertRaises(AssertionError):
            self.exchange(b"garbage\r\n\r\n")


class DescriptionTests(unittest.TestCase):
    def test_parse_description_flattens_the_device_tree(self):
        description = lib_test.parse_description(ROOT_DESC.encode(), "http://10.0.0.1:5000/rootDesc.xml")
        self.assertEqual(description["spec_version"], "1.1")
        self.assertEqual(description["udn"], "uuid:00000000-0000-0000-0000-000000000001")
        self.assertEqual(len(description["udns"]), 3)
        self.assertEqual(description["device_types"][2], "urn:schemas-upnp-org:device:WANConnectionDevice:1")
        wanip = description["services"][1]
        self.assertEqual(wanip["control"], "http://10.0.0.1:5000/ctl/IPConn")
        self.assertEqual(wanip["scpd"], "http://10.0.0.1:5000/WANIPCn.xml")
        with self.assertRaises(AssertionError):
            lib_test.parse_description(b"<root/>", "http://x/")

    def test_parse_scpd(self):
        scpd = lib_test.parse_scpd(SCPD.encode())
        self.assertEqual(sorted(scpd["actions"]), ["DeletePortMapping", "GetExternalIPAddress"])
        self.assertEqual(scpd["actions"]["GetExternalIPAddress"][0]["direction"], "out")
        self.assertTrue(scpd["variables"]["ExternalIPAddress"]["evented"])
        self.assertFalse(scpd["variables"]["RemoteHost"]["evented"])
        values = lib_test.scpd_values(SCPD.encode())
        self.assertEqual(values["scpd.evented"], ["ExternalIPAddress"])
        self.assertEqual(values["scpd.args.GetExternalIPAddress"], ["NewExternalIPAddress"])

    def test_fetch_from_a_server(self):
        igd = FakeIgd()
        try:
            description = lib_test.fetch_description(igd.url("/rootDesc.xml"))
            self.assertEqual(description["services"][0]["scpd"], igd.url("/L3F.xml"))
            self.assertIn("GetExternalIPAddress", lib_test.fetch_scpd(description["services"][1]["scpd"])["actions"])
            with self.assertRaises(AssertionError):
                lib_test.fetch_scpd(igd.url("/missing.xml"))
        finally:
            igd.close()


class SoapTests(unittest.TestCase):
    def setUp(self):
        self.igd = FakeIgd({
            "GetExternalIPAddress": (200, soap_reply("GetExternalIPAddress", [("NewExternalIPAddress", "198.51.100.1")])),
            "AddPortMapping": (500, soap_fault(718)),
            "DeletePortMapping": (200, soap_reply("DeletePortMapping", [])),
            "AddAnyPortMapping": (200, soap_reply("AddAnyPortMapping", [("NewReservedPort", "41999")])),
            "AddPinhole": (200, soap_reply("AddPinhole", [("UniqueID", "7")])),
            "DeletePinhole": (404, ""),
        })
        self.addCleanup(self.igd.close)

    def test_envelope_escapes_values(self):
        body = lib_test.soap_envelope("urn:x", "A", [("NewPortMappingDescription", "a<b&c")])
        self.assertIn("<NewPortMappingDescription>a&lt;b&amp;c</NewPortMappingDescription>", body)
        self.assertIn('<u:A xmlns:u="urn:x">', body)

    def test_success_fault_and_garbage(self):
        status, out = lib_test.soap_call(self.igd.url("/ctl/IPConn"), "urn:x", "GetExternalIPAddress")
        self.assertEqual((status, out["NewExternalIPAddress"], out["_element"]),
                         (200, "198.51.100.1", "GetExternalIPAddressResponse"))
        self.assertEqual(self.igd.requests[-1][2]["SOAPAction"], '"urn:x#GetExternalIPAddress"')
        status, fault = lib_test.soap_call(self.igd.url("/ctl/IPConn"), "urn:x", "AddPortMapping")
        self.assertEqual((status, fault), (500, lib_test.SoapFault(718, "Conflict")))
        self.assertIsNone(lib_test.parse_soap_response(b"not xml"))
        lib_test.soap_call(self.igd.url("/ctl/IPConn"), "urn:x", "Nope", soapaction=False)
        self.assertNotIn("SOAPAction", self.igd.requests[-1][2])

    def test_upnp_request_wrapper(self):
        """upnp_request (the pcp_e2e UPnP section) maps HTTP 200 to SUCCESS and a fault to UPNP_<code>."""
        spec = pcp_corpus_expander.expand_e2e_request({
            "upnp": "AddPortMapping", "protocol": "udp", "internal_port": 41200, "external_port": 41200})
        with patch.object(lib_test, "UPNP_HTTP_PORT", self.igd.port):
            self.assertEqual(lib_test.upnp_request("127.0.0.1", "172.28.41.2", spec), ("UPNP_718", 0, None))
            sent = self.igd.requests[-1]
            self.assertEqual(sent[1], "/ctl/IPConn")
            self.assertEqual(sent[3].decode(), upnp_soap_body(spec, "172.28.41.2"))
            delete = dict(spec, action="DeletePortMapping")
            self.assertEqual(lib_test.upnp_request("127.0.0.1", "c", delete), ("SUCCESS", 41200, None))
            anyport = dict(spec, action="AddAnyPortMapping")
            self.assertEqual(lib_test.upnp_request("127.0.0.1", "c", anyport), ("SUCCESS", 41999, None))
            pinhole = {"protocol_family": "UPnP", "action": "AddPinhole", "protocol": "udp", "internal_port": 41300,
                       "remote_host": "allowed-peer", "lease_time": 60}
            self.assertEqual(lib_test.upnp_request("127.0.0.1", "2001:db8:1::2", pinhole,
                                                   {"allowed-peer": "2001:db8:9000::2"}), ("SUCCESS", 41300, "7"))
            self.assertEqual(self.igd.requests[-1][1], "/ctl/IP6FCtl")
            self.assertIn(b"<RemoteHost>2001:db8:9000::2</RemoteHost>", self.igd.requests[-1][3])
            self.assertIn(b"<Protocol>17</Protocol>", self.igd.requests[-1][3])
            with self.assertRaisesRegex(AssertionError, "HTTP 404"):
                lib_test.upnp_request("127.0.0.1", "c", dict(pinhole, action="DeletePinhole"), unique_id="7")

    def test_cleanup_and_validation_of_the_new_kinds(self):
        anyport = {"protocol_family": "UPnP", "action": "AddAnyPortMapping", "protocol": "tcp",
                   "internal_port": 41000, "external_port": 41000}
        self.assertEqual(lib_test.cleanup_request(anyport, 41999)["external_port"], 41999)
        self.assertEqual(lib_test.cleanup_request(anyport, 41999)["action"], "DeletePortMapping")
        pinhole = {"protocol_family": "UPnP", "action": "AddPinhole", "protocol": "udp", "internal_port": 41300}
        self.assertEqual(lib_test.cleanup_request(pinhole)["action"], "DeletePinhole")
        lib_test.validate_upnp_request("x", pinhole, "ipv6")
        with self.assertRaisesRegex(ValueError, "IPv6"):
            lib_test.validate_upnp_request("x", pinhole, "ipv4")
        with self.assertRaisesRegex(ValueError, "IPv4"):
            lib_test.validate_upnp_request("x", anyport, "ipv6")
        lib_test.validate_upnp_request("x", {"action": "DeletePortMappingRange", "protocol": "udp",
                                             "start_port": 1024, "end_port": 2048}, "ipv4")


class GenaTests(unittest.TestCase):
    def test_subscribe_renew_unsubscribe(self):
        igd = FakeIgd()
        try:
            url = igd.url("/evt/IPConn")
            self.assertEqual(lib_test.gena_subscribe(url, "http://127.0.0.1:1/"), (200, "uuid:sub-1", "Second-1800"))
            headers = igd.requests[-1][2]
            self.assertEqual((headers["CALLBACK"], headers["NT"]), ("<http://127.0.0.1:1/>", "upnp:event"))
            self.assertEqual(lib_test.gena_renew(url, "uuid:sub-1")[0], 200)
            self.assertNotIn("NT", igd.requests[-1][2])
            self.assertEqual(lib_test.gena_renew(url, "uuid:other")[0], 412)
            self.assertEqual(lib_test.gena_request(url, "SUBSCRIBE", [("SID", "uuid:sub-1"), ("NT", "upnp:event")])[0], 400)
            self.assertEqual(lib_test.gena_unsubscribe(url, "uuid:sub-1")[0], 200)
        finally:
            igd.close()

    def test_event_listener_collects_notify(self):
        listener = lib_test.EventListener("127.0.0.1")
        try:
            body = (f'<e:propertyset xmlns:e="{lib_test.UPNP_EVENT_NS}"><e:property><PortMappingNumberOfEntries>2'
                    '</PortMappingNumberOfEntries></e:property></e:propertyset>').encode()
            for seq in (0, 1):
                connection = lib_test.http.client.HTTPConnection("127.0.0.1", listener.port, timeout=2)
                connection.request("NOTIFY", "/", body, {"SID": "uuid:s", "SEQ": str(seq), "NT": "upnp:event",
                                                         "NTS": "upnp:propchange", "Content-Type": "text/xml"})
                self.assertEqual(connection.getresponse().status, 200)
                connection.close()
            event = listener.wait("uuid:s", 1, timeout=2)
            self.assertEqual(event["properties"], {"PortMappingNumberOfEntries": "2"})
            self.assertIsNone(listener.wait("uuid:other", timeout=0.1))
        finally:
            listener.close()


class UpnpStepTests(unittest.TestCase):
    def setUp(self):
        self.igd = FakeIgd({"GetExternalIPAddress": (200, soap_reply("GetExternalIPAddress",
                                                                    [("NewExternalIPAddress", "198.51.100.1")])),
                            "AddPortMapping": (500, soap_fault(718))})
        self.addCleanup(self.igd.close)
        self.resources = []
        self.variables = {"router": "127.0.0.1", "client": "127.0.0.1", "family": "ipv4", "http_port": self.igd.port,
                          "_resources": self.resources,
                          "services": {"WANIPConnection": {"type": "urn:schemas-upnp-org:service:WANIPConnection:1",
                                                           "control": "/ctl/IPConn", "event": "/evt/IPConn"}}}

    def tearDown(self):
        for resource in self.resources:
            resource.close()

    def sequence(self, steps, cleanup=()):
        case = {"name": "c", "variables": self.variables, "request": {"steps": steps, "cleanup": list(cleanup)}}
        lib_test.run_protocol_sequence(None, None, case)

    def test_soap_http_and_subscribe_steps_capture_and_check(self):
        self.sequence([
            {"kind": "soap", "action": "GetExternalIPAddress", "capture": {"ext": "out.NewExternalIPAddress"},
             "expect": {"status": 200, "out.NewExternalIPAddress": {"matches": r"^198\."}}},
            {"kind": "soap", "action": "AddPortMapping", "expect": {"status": 500, "fault": 718}},
            {"kind": "http", "path": "/rootDesc.xml", "parse": "description", "check_urls": True,
             "expect": {"status": 200, "desc.spec_version": "1.1", "desc.broken_urls": [],
                        "desc.service_types": {"contains": "urn:schemas-upnp-org:service:WANIPConnection:1"}}},
            {"kind": "http", "path": "/missing", "expect": {"status": 404}},
            {"kind": "http", "raw": "GET /rootDesc.xml HTTP/1.1\r\nHOST: {host}\r\n\r\n",
             "expect": {"status": 200, "body": {"contains": "InternetGatewayDevice"}}},
            {"kind": "subscribe", "capture": {"sid": "sid"}, "expect": {"status": 200, "timeout": "Second-1800"}},
            {"kind": "subscribe", "mode": "renew", "sid": "$sid", "expect": {"status": 200}},
        ], cleanup=[{"kind": "subscribe", "mode": "unsubscribe", "sid": "$sid", "expect": {"status": 200}}])
        self.assertEqual(self.igd.requests[-1][0], "UNSUBSCRIBE")
        self.assertEqual(len(self.resources), 1)    # the listener the runner closes

    def test_a_failed_check_names_the_step(self):
        with self.assertRaisesRegex(AssertionError, r"step 1 \(soap\).*fault was 718, expected 714"):
            self.sequence([{"kind": "soap", "action": "AddPortMapping", "expect": {"fault": 714}}])

    def test_value_rules(self):
        values = {"a": "abc", "n": 5, "l": ["x", "y"], "none": None}
        lib_test.check_upnp_values(values, {"a": {"matches": "^ab", "contains": "b", "not_contains": "z"},
                                            "n": {"min": 1, "max": 5, "one_of": [4, 5]}, "l": {"contains": ["x", "y"]},
                                            "none": {"present": False}, "missing": {"present": False}}, {})
        for checks in ({"a": {"matches": "^b"}}, {"l": {"contains": "z"}}, {"n": {"one_of": [1]}},
                       {"none": {"present": True}}, {"n": 4}):
            with self.assertRaises(AssertionError):
                lib_test.check_upnp_values(values, checks, {})

    def test_a_restart_the_driver_does_not_confirm_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            self.variables["router_call_dir"] = directory
            thread = threading.Thread(target=self.answer_router_call, args=(directory, "timed out\n"))
            thread.start()
            with self.assertRaisesRegex(AssertionError, "did not restart"):
                self.sequence([{"kind": "restart"}])
            thread.join()

    @staticmethod
    def answer_router_call(directory, text):
        while True:
            requests = [name for name in os.listdir(directory) if name.endswith(".req")]
            if requests:
                request = os.path.join(directory, requests[0])
                os.unlink(request)
                with open(request[:-4] + ".resp", "w", encoding="utf-8") as response:
                    response.write(text)
                return
            time.sleep(0.01)

    def test_restart_and_lease_step(self):
        with tempfile.TemporaryDirectory() as directory:
            self.variables["router_call_dir"] = directory
            thread = threading.Thread(target=self.answer_router_call, args=(directory, "restarted\n"))
            thread.start()
            self.sequence([{"kind": "restart"}])
            thread.join()
            leases = os.path.join(directory, "miniupnpd.leases")
            with open(leases, "w", encoding="utf-8") as handle:
                handle.write("UDP:41000:172.28.41.2:41000:1700000000:upnp-wire\n")
            lease = lib_test.LeaseSource(files=leases)
            lib_test.run_upnp_step({"kind": "upnp-lease", "match": "^UDP:41000:", "expect": {"count": 1}},
                                   self.variables, lease)
            with self.assertRaises(AssertionError):
                lib_test.run_upnp_step({"kind": "upnp-lease", "match": "^TCP:", "expect": {"count": 1}},
                                       self.variables, lease)



class BuildVariantTests(unittest.TestCase):
    def test_resolve_variant_and_case_builds(self):
        case = {"name": "c", "expect": {"fault": {"igd1": 401, "igd2": 606}, "other": {"igd1": 1}}}
        self.assertEqual(lib_test.resolve_variant(case, ("igd1", "igd2"), "igd2")["expect"],
                         {"fault": 606, "other": {"igd1": 1}})
        self.assertEqual(lib_test.case_builds(case, {"igd2", "igd1"}), ["igd1", "igd2"])
        self.assertEqual(lib_test.case_builds(dict(case, builds=["igd2"]), {"igd1", "igd2"}), ["igd2"])
        with self.assertRaises(ValueError):
            lib_test.case_builds(dict(case, builds=[]), {"igd1"})



class WanExposureTests(unittest.TestCase):
    def test_an_answer_or_an_accepted_connection_is_exposure(self):
        with patch.object(lib_test.traffic_agent, "request_probe", return_value={"delivered": False}) as probe:
            with self.assertRaisesRegex(AssertionError, "answered a WAN peer"):
                lib_test.check_wan_exposure("http://agent", "tcp", "198.51.100.1", 5000, "GET / HTTP/1.0\r\n\r\n")
            self.assertEqual(probe.call_args.args[1:5], ("tcp", "198.51.100.1", 5000, b"GET / HTTP/1.0\r\n\r\n".hex()))
        with patch.object(lib_test.traffic_agent, "request_probe", return_value={"delivered": False, "error": "timed out"}):
            lib_test.check_wan_exposure("http://agent", "udp", "2001:db8:9000::1", 1900, "M-SEARCH")


if __name__ == "__main__":
    unittest.main()

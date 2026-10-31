#!/usr/bin/env python3
"""Offline decoder and comparison tests; no daemon or packet privileges needed."""

import ipaddress
import struct
import tempfile
import unittest
from pathlib import Path

import compare_pcaps as compare


def pcp(opcode=1, response=False, body=None):
    common = struct.pack('!BBBBI', 2, opcode | (128 if response else 0), 0,
                         6 if response else 0, 1800 if response else 300)
    common += struct.pack('!I', 42) + bytes(12) if response else ipaddress.ip_address('::ffff:192.0.2.1').packed
    if body is None:
        body = bytes.fromhex('112233445566778899aabbcc')
        body += struct.pack('!B3sHH', 17, b'\xff\xff\xff', 50001, 50002)
        body += ipaddress.ip_address('::ffff:198.51.100.1').packed
    return common + body


def udp_packet(payload, ipv6=False):
    udp = struct.pack('!HHHH', 12345, 5351, 8 + len(payload), 0) + payload
    if ipv6:
        # A hop-by-hop extension header precedes UDP.
        header = struct.pack('!IHBB', 6 << 28, 8 + len(udp), 0, 64)
        header += ipaddress.ip_address('2001:db8::1').packed + ipaddress.ip_address('2001:db8::2').packed
        return header + bytes([17, 0]) + bytes(6) + udp
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                         ipaddress.ip_address('192.0.2.1').packed, ipaddress.ip_address('192.0.2.2').packed)
    return header + udp


def pcap_file(frame, endian='<', linktype=101):
    magic = b'\xd4\xc3\xb2\xa1' if endian == '<' else b'\xa1\xb2\xc3\xd4'
    header = magic + struct.pack(endian + 'HHIIII', 2, 4, 0, 0, 65535, linktype)
    return header + struct.pack(endian + 'IIII', 100, 500000, len(frame), len(frame)) + frame


class DecodeTests(unittest.TestCase):
    def test_pcp_map(self):
        _, direction, opcode, fields = compare.decode_protocol(pcp(response=True))
        self.assertEqual((direction, opcode), ('Response', 1))
        self.assertEqual(fields.values['Result code'], '6 (MALFORMED_OPTION)')
        self.assertEqual(fields.values['Mapping nonce'], '112233445566778899aabbcc')
        self.assertEqual(fields.values['Opcode reserved'], 'ffffff')
        self.assertEqual(fields.values['Internal port'], '50001')
        self.assertEqual(fields.values['External port'], '50002')
        self.assertEqual(fields.values['Epoch (seconds)'], '42')

    def test_peer_and_legacy_map(self):
        message = pcp(opcode=2) + struct.pack('!H2s', 443, b'\xff\xff')
        message += ipaddress.ip_address('2001:db8::99').packed
        fields = compare.decode_protocol(message)[3].values
        self.assertEqual(fields['Remote peer reserved'], 'ffff')
        self.assertEqual(fields['Remote peer port'], '443')
        self.assertEqual(fields['Remote peer address'], '2001:db8::99')
        legacy = bytes([1]) + pcp()[1:24] + pcp()[36:]
        fields = compare.decode_protocol(legacy)[3].values
        self.assertNotIn('Mapping nonce', fields)
        self.assertEqual(fields['Internal port'], '50001')

    def test_filter_and_padding(self):
        option = struct.pack('!BBHBBH', 3, 0, 20, 0, 95, 443)
        option += ipaddress.ip_address('::ffff:192.0.2.99').packed
        option += bytes.fromhex('fe000001aa000000')
        fields = compare.decode_protocol(pcp() + option)[3].values
        self.assertEqual(fields['Option 1: prefix length'], '95')
        self.assertEqual(fields['Option 1: remote peer port'], '443')
        self.assertEqual(fields['Option 2: captured payload length'], '1')
        self.assertEqual(fields['Option 2: padding hex'], '000000')
        self.assertEqual(fields['Option count'], '2')

    def test_port_set(self):
        fields = compare.decode_protocol(pcp() + bytes.fromhex('820000050002c351ff000000'))[3].values
        self.assertEqual(fields['Option 1: PORT_SET size'], '2')
        self.assertEqual(fields['Option 1: PORT_SET first internal port'], '50001')
        self.assertEqual(fields['Option 1: PORT_SET parity bit'], '1')
        self.assertEqual(fields['Option 1: PORT_SET reserved bits'], 'fe')

    def test_malformed_packets_remain_visible(self):
        for size in range(60):
            compare.decode_protocol(pcp()[:size])
        fields = compare.decode_protocol(pcp() + bytes.fromhex('03000014ff'))[3]
        self.assertTrue(any('extends beyond' in note for note in fields.notes))
        fields = compare.decode_protocol(pcp() + bytes.fromhex('02000004ffffffff'))[3]
        self.assertTrue(any('expected 0' in note for note in fields.notes))

    def test_natpmp(self):
        req = struct.pack('!BBHHHI', 0, 1, 0, 50001, 50002, 300)
        res = struct.pack('!BBHIHHI', 0, 129, 2, 42, 50001, 0, 0)
        fields = compare.decode_protocol(req)[3].values
        self.assertEqual(fields['Protocol'], 'NAT-PMP')
        self.assertEqual(fields['Lifetime (seconds)'], '300')
        fields = compare.decode_protocol(res)[3].values
        self.assertEqual(fields['Result code'], '2 (NOT_AUTHORIZED)')
        self.assertEqual(fields['Internal port'], '50001')
        self.assertEqual(fields['External port'], '0')
        public = struct.pack('!BBHI', 0, 128, 0, 42) + ipaddress.ip_address('198.51.100.1').packed
        self.assertEqual(compare.decode_protocol(public)[3].values['External address'], '198.51.100.1')

    def test_ip_and_linktypes(self):
        payload = pcp(opcode=0, body=b'')
        ipv4, ipv6 = udp_packet(payload), udp_packet(payload, ipv6=True)
        ethernet = bytes(12) + bytes.fromhex('8100000186dd') + ipv6
        variants = [(101, ipv4), (101, ipv6), (1, ethernet),
                    (113, bytes(14) + bytes.fromhex('0800') + ipv4),
                    (276, bytes.fromhex('86dd') + bytes(18) + ipv6),
                    (0, bytes(4) + ipv4)]
        for linktype, frame in variants:
            self.assertEqual(compare.udp_payload(frame, linktype)[4], payload)
        fragmented = bytearray(ipv4)
        fragmented[6] = 0x20
        with self.assertRaisesRegex(ValueError, 'fragmented'):
            compare.udp_payload(fragmented, 101)

    def test_capture_and_comparison(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'capture.pcap'
            for endian in ('<', '>'):
                path.write_bytes(pcap_file(udp_packet(pcp()), endian))
                packets, warnings = compare.load_capture(path, 5351)
                self.assertEqual(len(packets), 1)
                self.assertFalse(warnings)
                self.assertEqual(compare.load_capture(path, 1234)[0], [])
                report = compare.markdown(path, path, packets, [], ([], []), True)
                self.assertIn('after frame: absent', report)
                self.assertIn('50001', report)
                self.assertNotIn('payload hex', report)
                same = compare.markdown(path, path, packets, packets, ([], []), True)
                self.assertIn('No field differences', same)
            path.write_bytes(pcap_file(udp_packet(pcp()))[:-1])
            with self.assertRaisesRegex(ValueError, 'truncated pcap record'):
                compare.load_capture(path, 5351)


if __name__ == '__main__':
    unittest.main()

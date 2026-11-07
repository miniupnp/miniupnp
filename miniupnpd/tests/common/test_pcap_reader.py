"""Tests of pcap_reader.read_pcap_packets and parse_udp_frame (python3 test_pcap_reader.py)."""

import ipaddress
import struct
import tempfile
import unittest
from pathlib import Path

import pcap_reader


def udp4_frame(source, destination, source_port, destination_port, payload):
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     ipaddress.ip_address(source).packed, ipaddress.ip_address(destination).packed)
    return b"\x00" * 12 + b"\x08\x00" + ip + udp


def pcap_file(records, linktype=1):
    data = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
    for seconds, frame in records:
        data += struct.pack("<IIII", seconds, 500000, len(frame), len(frame)) + frame
    return data


class PcapHelperTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def write(self, data):
        path = self.directory / "capture.pcap"
        path.write_bytes(data)
        return path

    def test_packets_have_timestamps_and_frames(self):
        frames = [udp4_frame("10.0.0.1", "224.0.0.1", 5351, 5350, b"first"),
                  udp4_frame("10.0.0.1", "224.0.0.1", 5351, 5350, b"second")]
        packets = pcap_reader.read_pcap_packets(self.write(pcap_file([(100, frames[0]), (101, frames[1])])))
        self.assertEqual([frame for _t, frame in packets], frames)
        self.assertEqual([t for t, _f in packets], [100.5, 101.5])

    def test_another_link_type_is_refused(self):
        with self.assertRaisesRegex(AssertionError, "unsupported link type 101"):
            pcap_reader.read_pcap_packets(self.write(pcap_file([(1, b"\x45" + bytes(19))], linktype=101)))

    def test_a_capture_cut_off_in_a_record_keeps_the_records_before_it(self):
        frame = udp4_frame("10.0.0.1", "10.0.0.2", 1, 2, b"x")
        data = pcap_file([(1, frame), (2, frame)])
        self.assertEqual(len(pcap_reader.read_pcap_packets(self.write(data[:-5]))), 1)

    def test_a_file_which_is_no_pcap_is_an_error(self):
        with self.assertRaisesRegex(AssertionError, "not a supported pcap"):
            pcap_reader.read_pcap_packets(self.write(b"nothing like a capture file"))

    def test_udp_frame_is_decoded(self):
        decoded = pcap_reader.parse_udp_frame(udp4_frame("10.0.0.1", "224.0.0.1", 5351, 5350, b"hello"))
        self.assertEqual(decoded, (ipaddress.ip_address("10.0.0.1"), ipaddress.ip_address("224.0.0.1"),
                                   5351, 5350, b"hello"))

    def test_frames_which_are_not_udp_give_none(self):
        self.assertIsNone(pcap_reader.parse_udp_frame(b"\x00" * 5))
        arp = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28
        self.assertIsNone(pcap_reader.parse_udp_frame(arp))


if __name__ == "__main__":
    unittest.main()

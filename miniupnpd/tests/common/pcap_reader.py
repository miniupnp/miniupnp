"""Classic pcap / pcapng reading and UDP datagram decoding shared by the PCP test tools."""

import io
import ipaddress
import struct
import subprocess
from pathlib import Path


def named(value, names):
    name = names.get(value, 'UNKNOWN') if isinstance(names, dict) else (
        names[value] if value < len(names) else 'UNKNOWN')
    return f'{value} ({name})'


def read_pcap(path):
    """Yield classic pcap records; use tcpdump to normalize pcapng if needed."""
    data = path.read_bytes()
    if data[:4] == b'\x0a\x0d\x0d\x0a':
        try:
            result = subprocess.run(['tcpdump', '-r', str(path.resolve()), '-w', '-'],
                                    capture_output=True, check=True)
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError(f'{path}: pcapng conversion requires working tcpdump: {error}') from error
        data = result.stdout
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000000),
               b'\xa1\xb2\xc3\xd4': ('>', 1000000),
               b'\x4d\x3c\xb2\xa1': ('<', 1000000000),
               b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
    if len(data) < 24 or data[:4] not in formats:
        raise ValueError(f'{path}: not a supported pcap/pcapng file')
    endian, scale = formats[data[:4]]
    linktype = struct.unpack_from(endian + 'I', data, 20)[0] & 0xffff
    stream = io.BytesIO(data[24:])
    number = 0
    while header := stream.read(16):
        number += 1
        if len(header) != 16:
            raise ValueError(f'{path}: truncated pcap record header #{number}')
        seconds, fraction, captured, original = struct.unpack(endian + 'IIII', header)
        frame = stream.read(captured)
        if len(frame) != captured:
            raise ValueError(f'{path}: truncated pcap record #{number}')
        yield number, seconds + fraction / scale, linktype, frame, captured < original


def udp_payload(frame, linktype):
    """Decode common tcpdump link types, IPv4/IPv6 and complete UDP datagrams."""
    if linktype == 1:  # Ethernet, including VLAN tags
        if len(frame) < 14:
            raise ValueError('truncated Ethernet header')
        kind = int.from_bytes(frame[12:14], 'big')
        offset = 14
        while kind in (0x8100, 0x88a8, 0x9100):
            if len(frame) < offset + 4:
                raise ValueError('truncated VLAN header')
            kind = int.from_bytes(frame[offset + 2:offset + 4], 'big')
            offset += 4
        if kind not in (0x0800, 0x86dd):
            return None
        packet = frame[offset:]
    elif linktype in (113, 276):  # Linux cooked v1 / v2
        size, proto_offset = (16, 14) if linktype == 113 else (20, 0)
        if len(frame) < size:
            raise ValueError('truncated Linux cooked header')
        kind = int.from_bytes(frame[proto_offset:proto_offset + 2], 'big')
        if kind not in (0x0800, 0x86dd):
            return None
        packet = frame[size:]
    elif linktype in (0, 108):  # BSD loopback
        packet = frame[4:]
    elif linktype in (12, 101, 228, 229):  # raw IP / IPv4 / IPv6
        packet = frame
    else:
        raise ValueError(f'unsupported capture link type {linktype}')
    if not packet:
        raise ValueError('missing IP header')
    version = packet[0] >> 4
    ip_fields = {'IP version': str(version)}
    if version == 4:
        if len(packet) < 20:
            raise ValueError('truncated IPv4 header')
        offset = (packet[0] & 15) * 4
        total = int.from_bytes(packet[2:4], 'big')
        if offset < 20 or total < offset or len(packet) < offset:
            raise ValueError('invalid IPv4 header length')
        if int.from_bytes(packet[6:8], 'big') & 0x3fff:
            raise ValueError('fragmented IPv4 datagram; reassembly is not supported')
        if packet[9] != 17:
            return None
        source, dest = str(ipaddress.ip_address(packet[12:16])), str(ipaddress.ip_address(packet[16:20]))
        fragment = int.from_bytes(packet[6:8], 'big')
        ip_fields.update({
            'IPv4 header length (bytes)': str(offset),
            'IPv4 DSCP': str(packet[1] >> 2),
            'IPv4 ECN': str(packet[1] & 3),
            'IPv4 total length (bytes)': str(total),
            'IPv4 identification': packet[4:6].hex(),
            'IPv4 flags': str(fragment >> 13),
            'IPv4 fragment offset': str(fragment & 0x1fff),
            'IPv4 TTL': str(packet[8]),
            'IPv4 protocol': named(packet[9], {17: 'UDP'}),
            'IPv4 header checksum': packet[10:12].hex(),
            'IPv4 options hex': packet[20:offset].hex(),
        })
        packet = packet[:total]
    elif version == 6:
        if len(packet) < 40:
            raise ValueError('truncated IPv6 header')
        source, dest = str(ipaddress.ip_address(packet[8:24])), str(ipaddress.ip_address(packet[24:40]))
        first_word = int.from_bytes(packet[:4], 'big')
        ip_fields.update({
            'IPv6 traffic class': str((first_word >> 20) & 255),
            'IPv6 flow label': str(first_word & 0xfffff),
            'IPv6 payload length (bytes)': str(int.from_bytes(packet[4:6], 'big')),
            'IPv6 next header': named(packet[6], {0: 'HOP_BY_HOP', 17: 'UDP',
                                                43: 'ROUTING', 44: 'FRAGMENT',
                                                51: 'AH', 60: 'DESTINATION_OPTIONS'}),
            'IPv6 hop limit': str(packet[7]),
        })
        packet = packet[:40 + int.from_bytes(packet[4:6], 'big')]
        protocol, offset = packet[6], 40
        while protocol in (0, 43, 44, 51, 60):
            if len(packet) < offset + 2:
                raise ValueError('truncated IPv6 extension header')
            if protocol == 44:
                raise ValueError('IPv6 fragment header; reassembly is not supported')
            length = (packet[offset + 1] + 2) * 4 if protocol == 51 else (packet[offset + 1] + 1) * 8
            if len(packet) < offset + length:
                raise ValueError('truncated IPv6 extension header')
            label = f'IPv6 extension at offset {offset}'
            ip_fields[f'{label}: type'] = str(protocol)
            ip_fields[f'{label}: next header'] = str(packet[offset])
            ip_fields[f'{label}: length (bytes)'] = str(length)
            ip_fields[f'{label}: hex'] = packet[offset:offset + length].hex()
            protocol, offset = packet[offset], offset + length
        if protocol != 17:
            return None
    else:
        return None
    if len(packet) < offset + 8:
        raise ValueError('truncated UDP header')
    sport, dport, length = struct.unpack_from('!HHH', packet, offset)
    if length < 8:
        raise ValueError('invalid UDP length')
    payload = packet[offset + 8:offset + length]
    ip_fields = {'IP version': str(version), 'IP source address': source,
                 'IP destination address': dest, **ip_fields}
    return source, sport, dest, dport, payload, length - 8, ip_fields


def read_pcap_packets(path):
    """(timestamp seconds, Ethernet frame) pairs of a pcap file written by tcpdump -w.

    Raises AssertionError for another link type. A capture cut off in the middle of a record
    (tcpdump killed) keeps the records before it."""
    records = []
    try:
        for _number, timestamp, linktype, frame, _truncated in read_pcap(Path(path)):
            if linktype != 1:
                raise AssertionError(f"{path}: unsupported link type {linktype} (need Ethernet)")
            records.append((timestamp, frame))
    except ValueError as error:
        if "truncated pcap record" not in str(error):
            raise AssertionError(str(error)) from error
    return records


def parse_udp_frame(frame):
    """(source ip, destination ip, source port, destination port, payload) of an Ethernet frame
    carrying a UDP datagram, or None."""
    try:
        decoded = udp_payload(frame, 1)
    except ValueError:
        return None
    if decoded is None:
        return None
    source, source_port, destination, destination_port, payload = decoded[:5]
    return (ipaddress.ip_address(source), ipaddress.ip_address(destination),
            source_port, destination_port, payload)

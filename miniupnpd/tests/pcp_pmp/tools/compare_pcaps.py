#!/usr/bin/env python3
"""Compare PCP/NAT-PMP wire fields in two packet captures as Markdown."""

import argparse
import io
import ipaddress
import struct
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PCP_RESULTS = (
    'SUCCESS', 'UNSUPP_VERSION', 'NOT_AUTHORIZED', 'MALFORMED_REQUEST',
    'UNSUPP_OPCODE', 'UNSUPP_OPTION', 'MALFORMED_OPTION', 'NETWORK_FAILURE',
    'NO_RESOURCES', 'UNSUPP_PROTOCOL', 'USER_EX_QUOTA', 'CANNOT_PROVIDE_EXTERNAL',
    'ADDRESS_MISMATCH', 'EXCESSIVE_REMOTE_PEERS',
)
PMP_RESULTS = ('SUCCESS', 'UNSUPP_VERSION', 'NOT_AUTHORIZED',
               'NETWORK_FAILURE', 'NO_RESOURCES', 'UNSUPP_OPCODE')
PCP_OPCODES = {0: 'ANNOUNCE', 1: 'MAP', 2: 'PEER'}
PMP_OPCODES = {0: 'PUBLIC_ADDRESS', 1: 'UDP_MAP', 2: 'TCP_MAP'}
OPTION_NAMES = {1: 'THIRD_PARTY', 2: 'PREFER_FAILURE', 3: 'FILTER', 130: 'PORT_SET'}


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
        packet = packet[:total]
    elif version == 6:
        if len(packet) < 40:
            raise ValueError('truncated IPv6 header')
        source, dest = str(ipaddress.ip_address(packet[8:24])), str(ipaddress.ip_address(packet[24:40]))
        packet = packet[:40 + int.from_bytes(packet[4:6], 'big')]
        protocol, offset = packet[6], 40
        while protocol in (0, 43, 44, 51, 60):
            if len(packet) < offset + 2:
                raise ValueError('truncated IPv6 extension header')
            if protocol == 44:
                raise ValueError('IPv6 fragment header; reassembly is not supported')
            length = (packet[offset + 1] + 2) * 4 if protocol == 51 else (packet[offset + 1] + 1) * 8
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
    return source, sport, dest, dport, payload, length - 8


class Fields:
    def __init__(self, data):
        self.data = data
        self.values = {'Captured payload length (bytes)': str(len(data))}
        self.notes = []

    def add(self, name, offset, size, kind='uint', names=None):
        raw = self.data[offset:offset + size]
        if len(raw) != size:
            self.values[name] = f'truncated ({len(raw)}/{size} bytes; hex {raw.hex() or "empty"})'
            return None
        if kind == 'hex':
            value = raw.hex()
        elif kind == 'address':
            address = ipaddress.ip_address(raw)
            value = str(address)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                value += f' (IPv4 {address.ipv4_mapped})'
        else:
            value = int.from_bytes(raw, 'big')
        self.values[name] = named(value, names) if names is not None else str(value)
        return value


def decode_options(fields, offset):
    data = fields.data
    count = 0
    while offset < len(data):
        count += 1
        label = f'Option {count}'
        code = fields.add(f'{label}: code', offset, 1, names=OPTION_NAMES)
        fields.add(f'{label}: reserved', offset + 1, 1, 'hex')
        length = fields.add(f'{label}: payload length', offset + 2, 2)
        if code is not None:
            fields.values[f'{label}: processing'] = 'mandatory' if code < 128 else 'optional'
        if length is None:
            fields.notes.append(f'{label}: incomplete option header')
            break
        start = offset + 4
        fields.values[f'{label}: captured payload length'] = str(min(length, max(0, len(data) - start)))
        if length > len(data) - start:
            fields.notes.append(f'{label}: declared payload extends beyond captured data')
            break
        expected_length = {1: 16, 2: 0, 3: 20, 130: 5}.get(code)
        if expected_length is not None and length != expected_length:
            fields.notes.append(f'{label}: expected {expected_length} payload bytes, got {length}')
        if code == 1 and length == 16:
            fields.add(f'{label}: third-party address', start, 16, 'address')
        elif code == 3 and length == 20:
            fields.add(f'{label}: FILTER reserved', start, 1, 'hex')
            fields.add(f'{label}: prefix length', start + 1, 1)
            fields.add(f'{label}: remote peer port', start + 2, 2)
            fields.add(f'{label}: remote peer address', start + 4, 16, 'address')
        elif code == 130 and length == 5:
            fields.add(f'{label}: PORT_SET size', start, 2)
            fields.add(f'{label}: PORT_SET first internal port', start + 2, 2)
            fields.add(f'{label}: PORT_SET flags', start + 4, 1, 'hex')
            fields.values[f'{label}: PORT_SET parity bit'] = str(data[start + 4] & 1)
            fields.values[f'{label}: PORT_SET reserved bits'] = f'{data[start + 4] & 0xfe:02x}'
        padding = (-length) % 4
        fields.add(f'{label}: padding hex', start + length, padding, 'hex')
        if start + length + padding > len(data):
            fields.notes.append(f'{label}: missing padding')
        offset = start + length + padding
    fields.values['Option count'] = str(count)


def decode_protocol(data):
    f = Fields(data)
    version = f.add('Version', 0, 1)
    wire_opcode = data[1] if len(data) > 1 else None
    response = bool(wire_opcode & 128) if wire_opcode is not None else None
    opcode = wire_opcode & 127 if wire_opcode is not None else None
    protocol = 'NAT-PMP' if version == 0 else 'PCP'
    direction = 'Response' if response else 'Request' if response is not None else 'Incomplete header'
    f.values['Protocol'] = protocol
    f.values['Message type'] = direction
    f.add('Opcode byte', 1, 1, 'hex')
    if opcode is not None:
        f.values['Opcode'] = named(opcode, PMP_OPCODES if version == 0 else PCP_OPCODES)
    if version == 0:
        if response:
            f.add('Result code', 2, 2, names=PMP_RESULTS)
            f.add('Epoch (seconds)', 4, 4)
            if opcode == 0:
                f.add('External address', 8, 4, 'address')
            elif opcode in (1, 2):
                f.add('Internal port', 8, 2)
                f.add('External port', 10, 2)
                f.add('Lifetime (seconds)', 12, 4)
        elif opcode in (1, 2):
            f.add('Reserved', 2, 2, 'hex')
            f.add('Internal port', 4, 2)
            f.add('External port', 6, 2)
            f.add('Lifetime (seconds)', 8, 4)
        known_length = (12 if opcode == 0 else 16) if response else (2 if opcode == 0 else 12)
        if opcode not in (0, 1, 2) or len(data) > known_length:
            f.values['Uninterpreted payload length (bytes)'] = str(len(data[(8 if response else 2):]))
    else:
        if response:
            f.add('Common reserved', 2, 1, 'hex')
            f.add('Result code', 3, 1, names=PCP_RESULTS)
            f.add('Epoch (seconds)', 8, 4)
            f.add('Common reserved bytes 12–23', 12, 12, 'hex')
        else:
            f.add('Common reserved', 2, 2, 'hex')
            f.add('Client address', 8, 16, 'address')
        f.add('Lifetime (seconds)', 4, 4)
        offset = 24
        if opcode in (1, 2) and version in (1, 2):
            if version == 2:
                f.add('Mapping nonce', offset, 12, 'hex')
                offset += 12
            f.add('IP protocol', offset, 1, names={0: 'ALL', 6: 'TCP', 17: 'UDP'})
            f.add('Opcode reserved', offset + 1, 3, 'hex')
            f.add('Internal port', offset + 4, 2)
            f.add('External port', offset + 6, 2)
            f.add('External address', offset + 8, 16, 'address')
            offset += 24
            if opcode == 2:
                f.add('Remote peer port', offset, 2)
                f.add('Remote peer reserved', offset + 2, 2, 'hex')
                f.add('Remote peer address', offset + 4, 16, 'address')
                offset += 20
        elif opcode != 0 or version not in (1, 2):
            f.values['Uninterpreted payload length (bytes)'] = str(len(data[24:]))
            offset = len(data)
        if len(data) >= offset:
            decode_options(f, offset)
        else:
            f.notes.append(f'incomplete opcode body: expected at least {offset} bytes')
    return protocol, direction, opcode, f


def load_capture(path, port):
    packets, warnings = [], []
    for number, timestamp, linktype, frame, truncated in read_pcap(path):
        try:
            udp = udp_payload(frame, linktype)
        except ValueError as error:
            warnings.append(f'Frame {number}: {error}')
            continue
        if udp is None:
            continue
        source, sport, dest, dport, data, declared = udp
        if port not in (sport, dport):
            continue
        protocol, direction, opcode, fields = decode_protocol(data)
        fields.values = {'UDP payload length (declared bytes)': str(declared), **fields.values}
        if truncated or len(data) != declared:
            fields.notes.append('capture or datagram is truncated; fields may be incomplete')
        packets.append({'frame': number, 'time': timestamp, 'source': f'[{source}]:{sport}',
                        'destination': f'[{dest}]:{dport}', 'protocol': protocol,
                        'direction': direction, 'opcode': opcode, 'fields': fields})
    return packets, warnings


def cell(value):
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\n', ' ')


def markdown(before_path, after_path, before, after, warnings, changes_only):
    lines = ['# PCP/NAT-PMP capture comparison', '', f'- Before: {cell(before_path)}',
             f'- After: {cell(after_path)}', '',
             '### Packet overview', '', '| Run | Frame | UTC time | Source | Destination | Message |',
             '|:--|--:|:--|:--|:--|:--|']
    for label, packets in [('Before', before), ('After', after)]:
        for p in packets:
            stamp = datetime.fromtimestamp(p['time'], timezone.utc).isoformat(timespec='microseconds')
            message = f"{p['protocol']} {p['direction']} {p['fields'].values.get('Opcode', 'unknown opcode')}"
            lines.append('| ' + ' | '.join(map(cell, (label, p['frame'], stamp, p['source'], p['destination'], message))) + ' |')
    lines += ['', '### Field comparison', '',
              'Messages are aligned by protocol, request/response direction, opcode, and occurrence within each capture. '
              'This is an ordered comparison, not transaction matching. Retries, missing responses, extra traffic, or reordered '
              'packets can shift the alignment. Check the frame numbers and request fields. '
              'Missing responses are not proof of a server discard; capture loss is also possible.', '']
    if not before or not after:
        lines += ['One or both captures contain no matching UDP packets.', '']
    groups = []
    for packets in (before, after):
        counts, indexed = defaultdict(int), {}
        for p in packets:
            key = (p['protocol'], p['direction'], p['opcode'])
            counts[key] += 1
            indexed[(*key, counts[key])] = p
        groups.append(indexed)
    keys = list(dict.fromkeys([*groups[0], *groups[1]]))
    for key in keys:
        left, right = groups[0].get(key), groups[1].get(key)
        sample = left or right
        title = f"{key[0]} {key[1]} {sample['fields'].values.get('Opcode', 'unknown opcode')} — occurrence {key[3]}"
        lines += [f'#### {title}', '',
                  f"Before frame: {left['frame'] if left else 'absent'}; after frame: {right['frame'] if right else 'absent'}.", '']
        for label, p in (('Before', left), ('After', right)):
            if p:
                lines += [f'{label}: {cell(note)}.' for note in p['fields'].notes]
        lines += ['', '| Field | Before | After | Changed |', '|:--|:--|:--|:--|']
        a = left['fields'].values if left else {}
        b = right['fields'].values if right else {}
        shown = 0
        for field in dict.fromkeys([*a, *b]):
            different = a.get(field) != b.get(field)
            if changes_only and not different:
                continue
            lines.append('| ' + ' | '.join(map(cell, (field, a.get(field, 'absent'), b.get(field, 'absent'), 'yes' if different else ''))) + ' |')
            shown += 1
        if not shown:
            lines.append('| No field differences | | | |')
        lines.append('')
    if any(warnings):
        lines += ['### Capture decoding notes', '']
        for label, notes in zip(('Before', 'After'), warnings):
            lines += [f'- {label}: {cell(note)}.' for note in notes]
        lines.append('')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path, help='before-fix pcap or pcapng')
    parser.add_argument('after', type=Path, help='after-fix pcap or pcapng')
    parser.add_argument('-o', '--output', type=Path, help='Markdown output (default: stdout)')
    parser.add_argument('--port', type=int, default=5351, help='server UDP port (default: 5351; use 5350 for notifications)')
    parser.add_argument('--changes-only', action='store_true', help='omit identical fields')
    args = parser.parse_args()
    if args.output and args.output.resolve() in (args.before.resolve(), args.after.resolve()):
        parser.error('output must not overwrite an input capture')
    try:
        before, before_notes = load_capture(args.before, args.port)
        after, after_notes = load_capture(args.after, args.port)
        output = markdown(args.before, args.after, before, after, (before_notes, after_notes), args.changes_only)
        if args.output:
            args.output.write_text(output, encoding='utf-8')
        else:
            print(output)
    except (OSError, ValueError) as error:
        parser.exit(2, f'{parser.prog}: {error}\n')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Rootless L2 bridge between a QEMU stream netdev and a Docker interface.

QEMU (client side) connects to --listen over TCP and exchanges Ethernet frames
framed with a 4-byte big-endian length. The relay copies them to and from an
AF_PACKET socket bound to --iface (leaving out the relay's own QEMU connection,
which arrives over that same interface from Docker's port proxy), which is the container end of a Docker
bridge network, so the VM NIC behaves like one more host on that bridge.
"""
import argparse
import select
import socket
import struct

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_CSUMNOTREADY = 8


def recv_exact(conn, count):
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def ones_complement(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def complete_checksum(frame):
    """Fill in the TCP/UDP/ICMPv6 checksum a Linux veth left to hardware offload.

    The VM's NIC sees a plain Ethernet wire, so a frame whose checksum is still
    the pseudo-header seed would be dropped as corrupt.
    """
    ethertype = frame[12:14]
    if ethertype == b"\x08\x00":
        header = 14 + (frame[14] & 0x0F) * 4
        proto = frame[23]
        length = struct.unpack(">H", frame[16:18])[0] - (header - 14)
        pseudo = frame[26:34] + struct.pack(">BBH", 0, proto, length)
    elif ethertype == b"\x86\xdd":
        header = 54
        proto = frame[20]
        length = struct.unpack(">H", frame[18:20])[0]
        pseudo = frame[22:54] + struct.pack(">IBBBB", length, 0, 0, 0, proto)
    else:
        return frame
    offset = {6: 16, 17: 6, 58: 2}.get(proto)
    if offset is None or len(frame) < header + offset + 2:
        return frame
    segment = bytearray(frame[header:header + length])
    segment[offset:offset + 2] = b"\x00\x00"
    value = ones_complement(pseudo + bytes(segment)) or (0xFFFF if proto == 17 else 0)
    return frame[:header + offset] + struct.pack(">H", value) + frame[header + offset + 2:]


def is_control(frame, ports):
    """True for the IPv4/TCP frames of the relay's own QEMU connection."""
    if len(frame) < 38 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
        return False
    header = 14 + (frame[14] & 0x0F) * 4
    source, dest = struct.unpack(">HH", frame[header:header + 4])
    return source in ports or dest in ports


def serve(listener, iface, ports):
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    raw.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    raw.bind((iface, 0))
    while True:
        conn, _ = listener.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        buffer = b""
        try:
            while True:
                readable, _, _ = select.select([raw, conn], [], [])
                if raw in readable:
                    frame, ancillary, _, info = raw.recvmsg(65535, 256)
                    if info[2] != PACKET_OUTGOING and not is_control(frame, ports):
                        for level, kind, data in ancillary:
                            if (level, kind) == (SOL_PACKET, PACKET_AUXDATA) and \
                                    struct.unpack_from("I", data)[0] & TP_STATUS_CSUMNOTREADY:
                                frame = complete_checksum(frame)
                        conn.sendall(struct.pack(">I", len(frame)) + frame)
                if conn in readable:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buffer += chunk
                    while len(buffer) >= 4:
                        size = struct.unpack(">I", buffer[:4])[0]
                        if len(buffer) < 4 + size:
                            break
                        raw.send(buffer[4:4 + size])
                        buffer = buffer[4 + size:]
        except OSError:
            pass
        finally:
            conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--iface", required=True)
    parser.add_argument("--control-port", type=int, action="append", default=[],
                        help="TCP port of a QEMU connection to hide from the VM (repeatable)")
    args = parser.parse_args()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", args.listen))
    listener.listen(1)
    serve(listener, args.iface, set(args.control_port) | {args.listen})


if __name__ == "__main__":
    main()

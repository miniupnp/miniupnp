#!/usr/bin/env python3
"""A minimal STUN server for the daemon_options fixture: it answers Binding Requests with a fixed
MAPPED-ADDRESS per port, names an OTHER-ADDRESS (RFC 5780) and ignores CHANGE-REQUEST, so the daemon
sees a filtered connection."""

import select
import socket
import struct

MAPPED = {3478: "203.0.113.7", 3479: "203.0.113.8"}
BINDING_REQUEST, BINDING_RESPONSE, MAPPED_ADDRESS, CHANGE_REQUEST = 0x0001, 0x0101, 0x0001, 0x0003
OTHER_ADDRESS = 0x802c


def asks_for_change(message):
    """A CHANGE-REQUEST with a flag set: this server has no second address to answer from."""
    offset = 20
    while offset + 4 <= len(message):
        kind, length = struct.unpack_from("!HH", message, offset)
        if kind == CHANGE_REQUEST and any(message[offset + 4:offset + 4 + length]):
            return True
        offset += 4 + length + (-length % 4)
    return False


def main():
    sockets = {}
    for port in MAPPED:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
        sockets[sock] = port
    while True:
        for sock in select.select(list(sockets), [], [])[0]:
            message, peer = sock.recvfrom(1024)
            if len(message) < 20 or struct.unpack_from("!H", message)[0] != BINDING_REQUEST:
                continue
            if asks_for_change(message):
                continue
            attribute = struct.pack("!HHBBH", MAPPED_ADDRESS, 8, 0, 1, peer[1])
            attribute += socket.inet_aton(MAPPED[sockets[sock]])
            attribute += struct.pack("!HHBBH", OTHER_ADDRESS, 8, 0, 1, 3480) + socket.inet_aton("192.0.2.1")
            sock.sendto(struct.pack("!HH", BINDING_RESPONSE, len(attribute)) + message[4:20] + attribute, peer)


if __name__ == "__main__":
    main()

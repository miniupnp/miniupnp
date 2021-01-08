#!/usr/bin/env python3
# vim: sw=4 ts=4 expandtab
# (c) 2021 Thomas BERNARD
# Python3 module to submit service to running MiniSSDPd
# MiniSSDPd: See http://miniupnp.free.fr/minissdpd.html
import socket, os


def codelength(s):
    """ returns the given string/bytes as bytes, prepended with the 7-bit-encoded length """
    # We want bytes
    if not isinstance(s, bytes):
        # Not bytes. Let's try to convert to bytes, but only plain ASCII
        try:
            s = str.encode(s, "ascii")
        except:
            s = b''
    l = len(s)
    if l == 0:
        return b'\x00'
    encodedlen = (l & 0x7F).to_bytes(1, 'little')
    while l > 0x7F:
        l = l >> 7
        c = (l & 0x7F) | 0x80
        encodedlen = c.to_bytes(1, 'little') + encodedlen
    return encodedlen + s


def submit_to_minissdpd(st, usn, server, url, sockpath="/var/run/minissdpd.sock"):
    """ submits the specified service to MiniSSDPD (if running)"""
    # First check if sockpath exists i.e. MiniSSDPD is running
    if not os.path.exists(sockpath):
        return -1, f"Error: {sockpath} does not exist. Is minissdpd running?"
    # OK, submit
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(sockpath)
        sock.send(b'\x04' + codelength(st) + codelength(usn) + codelength(server) + codelength(url))
    except socket.error as msg:
        print(msg)
        return -1, msg
    finally:
        sock.close()
    return 0, "OK"


if __name__ == "__main__":
    # Example usage
    rc, message = submit_to_minissdpd(
        b'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
        b'uuid:73616d61-6a6b-7a74-650a-0d24d4a5d636::urn:schemas-upnp-org:device:InternetGatewayDevice:1',
        b'MyServer/0.0',
        b'http://192.168.0.1:1234/rootDesc.xml',
    )
    if rc == 0:
        print("OK: submitting to MiniSSDPD went well")
    else:
        print("Not OK. Error message is:", message)

#!/usr/bin/env python3
# vim: sw=4 ts=4 expandtab
# (c) 2021 Thomas BERNARD
# Python 3 : code sample
import socket

def codelength(s):
    l = len(s)
    if l == 0:
        return b'\x00'
    encodedlen = b''
    while l > 0:
        c = l & 0x7F
        l = l >> 7
        if l > 0:
            c = c + 128
        encodedlen = c.to_bytes(1, 'little') + encodedlen
    return encodedlen + s

def SubmitServicesToMiniSSDPD(st, usn, server, url, sockpath = "/var/run/minissdpd.sock"):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(sockpath)
        sock.send(b'\x04' + codelength(st) + codelength(usn) + codelength(server) + codelength(url))
    except socket.error as msg:
        print(msg)
        return -1
    finally:
        sock.close()
    return 0

SubmitServicesToMiniSSDPD(b'urn:schemas-upnp-org:device:InternetGatewayDevice:1', b'uuid:73616d61-6a6b-7a74-650a-0d24d4a5d636::urn:schemas-upnp-org:device:InternetGatewayDevice:1', b'MyServer/0.0', b'http://192.168.0.1:1234/rootDesc.xml')

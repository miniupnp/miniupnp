#!/usr/bin/env python3
# Traffic agent for isolated gateway integration tests.
#
# Protocol replies alone cannot show whether a gateway forwards or blocks
# traffic correctly. This agent runs on the WAN side so tests can request
# TCP/UDP probes through the shared HTTP-controlled traffic service.
#
# The command-line interface selects probe source addresses and optionally
# installs an IPv6 route through the gateway under test. The calling harness supplies the
# topology, keeping fixture-specific addresses out of this reusable agent.
"""Reusable HTTP-controlled TCP/UDP traffic agent for isolated end-to-end tests."""

import argparse
import errno
import ipaddress
import itertools
import json
import socket
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOURCE_PORTS = itertools.count(40000)


def probe(spec, source4='0.0.0.0', source6='::'):
    if not isinstance(spec, dict):
        raise ValueError('probe must be a JSON object')
    if type(spec['port']) is not int or not 1 <= spec['port'] <= 65535:
        raise ValueError('probe port must be between 1 and 65535')
    target = ipaddress.ip_address(spec['host'])
    if isinstance(target, ipaddress.IPv6Address) and target.ipv4_mapped:
        target = target.ipv4_mapped
    family = socket.AF_INET6 if target.version == 6 else socket.AF_INET
    transport = {'tcp': socket.SOCK_STREAM, 'udp': socket.SOCK_DGRAM}[spec['protocol']]
    token = bytes.fromhex(spec['token_hex'])
    if not 0 < len(token) <= 4096:
        raise ValueError('token must contain 1..4096 bytes')
    timeout = spec.get('timeout', 0.5)
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
        raise ValueError('timeout must be greater than zero and at most 30 seconds')
    with socket.socket(family, transport) as sock:
        sock.settimeout(timeout)
        source = source6 if target.version == 6 else source4
        # Fresh tuples ensure conntrack entries from an earlier probe cannot
        # keep a deleted mapping looking usable. Never recycle actor ports.
        requested_source_port = spec.get('source_port')
        if requested_source_port is not None and (
                type(requested_source_port) is not int or not 1 <= requested_source_port <= 65535):
            raise ValueError('source_port must be between 1 and 65535')
        source_ports = ([requested_source_port] if requested_source_port is not None
                        else SOURCE_PORTS)
        for port in source_ports:
            if port > 65535:
                raise ValueError('traffic agent exhausted its fresh source ports')
            try:
                sock.bind((source, port))
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    if requested_source_port is not None:
                        return {'delivered': False, 'error': str(error)}
                    raise
            else:
                break
        try:
            sock.connect((str(target), spec['port']))
            sock.sendall(token)
            received = b''
            while len(received) < len(token):
                block = sock.recv(4096)
                if not block:
                    break
                received += block
                if transport == socket.SOCK_DGRAM:
                    break
            return {'delivered': received == token}
        except OSError as error:
            return {'delivered': False, 'error': str(error)}


def create_server(host='127.0.0.1', port=18080, source4='0.0.0.0', source6='::'):
    """Create a controllable server; callers own its serving thread and cleanup."""
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ('/', '/health'):
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ready":true}')

        def do_POST(self):
            if self.path != '/probe':
                self.send_error(404)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 4096:
                    raise ValueError('invalid probe length')
                result = probe(json.loads(self.rfile.read(length)), source4, source6)
            except (ValueError, TypeError, KeyError, OSError) as error:
                self.send_error(400, str(error))
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

    class AgentHTTPServer(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ':' in host else socket.AF_INET

        def server_bind(self):
            if self.address_family == socket.AF_INET6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()

    return AgentHTTPServer((host, port), Handler)


def run_self_tests():
    import threading
    import unittest
    import urllib.error
    import urllib.request

    class TrafficAgentTests(unittest.TestCase):
        def setUp(self):
            self.server = create_server(port=0, source4='127.0.0.1', source6='::1')
            self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.worker.start()
            self.url = f'http://127.0.0.1:{self.server.server_port}'

        def tearDown(self):
            self.server.shutdown()
            self.server.server_close()
            self.worker.join()

        def request(self, spec, path='/probe'):
            request = urllib.request.Request(self.url + path, data=json.dumps(spec).encode(),
                                             headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, timeout=3) as response:
                return json.load(response)

        def test_health(self):
            with urllib.request.urlopen(self.url + '/health', timeout=3) as response:
                self.assertEqual(json.load(response), {'ready': True})

        def test_echo_round_trip(self):
            for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                for protocol, kind in (('udp', socket.SOCK_DGRAM), ('tcp', socket.SOCK_STREAM)):
                    with self.subTest(host=host, protocol=protocol), socket.socket(family, kind) as listener:
                        try:
                            listener.bind((host, 0))
                        except OSError:
                            if family == socket.AF_INET6 and not socket.has_ipv6:
                                continue
                            raise
                        listener.settimeout(2)
                        if protocol == 'tcp':
                            listener.listen(1)

                        def echo():
                            if protocol == 'udp':
                                data, remote = listener.recvfrom(4096)
                                listener.sendto(data, remote)
                            else:
                                connection, _ = listener.accept()
                                with connection:
                                    connection.settimeout(2)
                                    data = connection.recv(4096)
                                    connection.sendall(data)

                        worker = threading.Thread(target=echo, daemon=True)
                        worker.start()
                        try:
                            outcome = self.request({'protocol': protocol, 'host': host,
                                                    'port': listener.getsockname()[1],
                                                    'token_hex': b'end-to-end'.hex()})
                            self.assertEqual(outcome, {'delivered': True})
                        finally:
                            worker.join(timeout=3)
                        self.assertFalse(worker.is_alive())

        def test_blocked_probe(self):
            # A bound, non-listening TCP socket cannot accept the probe.
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                outcome = self.request({'protocol': 'tcp', 'host': '127.0.0.1',
                                        'port': listener.getsockname()[1], 'token_hex': 'ab'})
            self.assertFalse(outcome['delivered'])

        def test_invalid_requests(self):
            valid = {'protocol': 'tcp', 'host': '127.0.0.1', 'port': 12345, 'token_hex': 'ab'}
            for spec in ([], {}, dict(valid, port=65536), dict(valid, token_hex=''),
                         dict(valid, timeout=-1), dict(valid, protocol='invalid')):
                with self.subTest(spec=spec), self.assertRaises(urllib.error.HTTPError) as error:
                    self.request(spec)
                self.assertEqual(error.exception.code, 400)
                error.exception.close()
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.request(valid, '/unknown')
            self.assertEqual(error.exception.code, 404)
            error.exception.close()


    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TrafficAgentTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true',
                        help='run HTTP and TCP/UDP checks on loopback; no gateway needed')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=18080)
    parser.add_argument('--source4', default='0.0.0.0')
    parser.add_argument('--source6', default='::')
    parser.add_argument('--route6', help='IPv6 destination prefix routed through the gateway')
    parser.add_argument('--gateway6', help='IPv6 gateway on the probe source interface')
    args = parser.parse_args()
    if args.self_test:
        return run_self_tests()
    if bool(args.route6) != bool(args.gateway6):
        parser.error('--route6 and --gateway6 must be supplied together')
    if args.route6:
        interfaces = json.loads(subprocess.check_output(['ip', '-j', 'address']))
        interface = next(item['ifname'] for item in interfaces
                         if any(addr.get('local') == args.source4 for addr in item['addr_info']))
        subprocess.run(['ip', '-6', 'route', 'replace', args.route6,
                        'via', args.gateway6, 'dev', interface, 'metric', '1'], check=True)

    with create_server(args.host, args.port, args.source4, args.source6) as server:
        server.serve_forever()


if __name__ == '__main__':
    raise SystemExit(main())

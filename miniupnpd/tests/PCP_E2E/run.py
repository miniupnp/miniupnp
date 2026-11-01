#!/usr/bin/env python3
"""Execute YAML PCP MAP scenarios and verify their real forwarding behavior."""
import argparse
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

try:
    import yaml
except ImportError as exc:
    raise SystemExit("PyYAML is required") from exc

RESULTS = {0: "SUCCESS", 1: "UNSUPP_VERSION", 2: "NOT_AUTHORIZED", 3: "MALFORMED_REQUEST",
           4: "UNSUPP_OPCODE", 5: "UNSUPP_OPTION", 6: "MALFORMED_OPTION", 7: "NETWORK_FAILURE",
           8: "NO_RESOURCES", 9: "UNSUPP_PROTOCOL", 10: "USER_EX_QUOTA",
           11: "CANNOT_PROVIDE_EXTERNAL", 12: "ADDRESS_MISMATCH", 13: "EXCESSIVE_REMOTE_PEERS"}
TIMEOUT = 1.0


def v6_address(value):
    address = ipaddress.ip_address(value)
    if address.version == 4:
        return socket.inet_pton(socket.AF_INET6, f"::ffff:{address}")
    return socket.inet_pton(socket.AF_INET6, str(address))


def map_request(sock, router, client, spec, peer_addresses, nonce=None):
    nonce = nonce or os.urandom(12)
    body = nonce + bytes(({"tcp": 6, "udp": 17}[spec["protocol"]], 0, 0, 0))
    body += struct.pack("!HH", spec["internal_port"], spec["suggested_external_port"])
    body += b"\0" * 16
    packet = bytes((2, 1, 0, 0)) + struct.pack("!I", spec["lifetime"])
    packet += v6_address(client) + body
    filters = spec.get("filters")
    if filters is None:
        filters = [spec["filter"]] if spec.get("filter") else []
    for filt in filters:
        peer = filt["remote_peer"]
        peer = peer_addresses.get(peer, peer)
        prefix = filt["prefix_length"]
        if prefix and ipaddress.ip_address(peer).version == 4:
            prefix += 96
        remote_port = filt.get("remote_port", 0)
        if remote_port == "any":
            remote_port = 0
        packet += bytes((3, 0, 0, 20)) + bytes((0, prefix))
        packet += struct.pack("!H", remote_port) + v6_address(peer)
    if spec.get("prefer_failure"):
        packet += bytes((2, 0, 0, 0))
    sock.sendto(packet, (router, 5351))
    response, _ = sock.recvfrom(2048)
    if len(response) < 60 or response[:2] != bytes((2, 0x81)):
        raise AssertionError(f"malformed PCP MAP response ({len(response)} bytes)")
    result = RESULTS.get(response[3], f"UNKNOWN({response[3]})")
    if result == "SUCCESS":
        if response[24:36] != nonce:
            raise AssertionError("PCP response did not echo the MAP nonce")
        if response[36] != body[12] or response[40:42] != body[16:18]:
            raise AssertionError("PCP response changed the mapped protocol or internal port")
    return result, struct.unpack("!H", response[42:44])[0], nonce


def probe(agent, host, port, transport, expect, source_port=None):
    data = {"protocol": transport, "host": host, "port": port,
            "token_hex": os.urandom(16).hex(), "timeout": TIMEOUT}
    if source_port is not None:
        data["source_port"] = source_port
    request = urllib.request.Request(agent.rstrip("/") + "/probe", data=json.dumps(data).encode(),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=3) as response:
        outcome = json.load(response)
    delivered = outcome["delivered"]
    if delivered != (expect == "delivered"):
        raise AssertionError(f"{transport} {host}:{port}: expected {expect}; got {outcome}")


class Echo:
    def __init__(self, family, bind, port, protocol):
        self.sock = socket.socket(family, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind, port))
        self.sock.settimeout(0.2)
        if protocol == "tcp":
            self.sock.listen(8)
        self.protocol = protocol
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                if self.protocol == "udp":
                    payload, peer = self.sock.recvfrom(4096)
                    self.sock.sendto(payload, peer)
                else:
                    conn, _ = self.sock.accept()
                    with conn:
                        conn.settimeout(1)
                        payload = conn.recv(4096)
                        if payload:
                            conn.sendall(payload)
            except socket.timeout:
                pass
            except OSError:
                break

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=1)


def run_case(case, args, agents, pcp_sock):
    requests = case["requests"] if "requests" in case else [case["request"]]
    expected = case["expect"].get("results", [case["expect"].get("result", "SUCCESS")])
    if len(requests) != len(expected):
        raise AssertionError("requests/results lengths differ")
    active = {}

    def cleanup_mappings():
        for (protocol, internal_port), (original, _port, nonce) in active.items():
            delete = dict(original, lifetime=0)
            delete.pop("filter", None)
            delete.pop("filters", None)
            result, _assigned, _ = map_request(
                pcp_sock, args.router, args.client_address, delete,
                args.peer_addresses, nonce)
            if result != "SUCCESS":
                raise AssertionError(f"cleanup of {protocol}/{internal_port} returned {result}")

    listeners = {}
    def run_traffic(traffic_items):
        for traffic in traffic_items:
            service_port = traffic.get("service_port")
            if service_port is None:
                service_port = requests[0].get("internal_port")
            if service_port is None:
                service_port = next(iter(active.values()))[0]["internal_port"]
            external_port = traffic.get("external_port")
            if external_port is None:
                mapping = active.get((traffic["protocol"], service_port))
                external_port = mapping[1] if mapping else requests[0]["suggested_external_port"]
            if traffic["expect"] == "delivered":
                key = (traffic["protocol"], service_port)
                if key not in listeners:
                    listeners[key] = Echo(args.socket_family, args.client_address,
                                          service_port, traffic["protocol"])
            time.sleep(0.1)
            probe_host = args.external_address if args.family == "ipv4" else args.client_address
            probe(agents[traffic["from"]], probe_host, external_port,
                  traffic["protocol"], traffic["expect"], traffic.get("source_port"))

    try:
        stages = case["expect"].get("traffic_stages", [])
        for request_index, (spec, wanted) in enumerate(zip(requests, expected), 1):
            key = (spec["protocol"], spec["internal_port"])
            prior = active.get(key)
            result, port, nonce = map_request(
                pcp_sock, args.router, args.client_address, spec,
                args.peer_addresses, prior[2] if prior else None)
            if result != wanted:
                raise AssertionError(f"PCP response expected {wanted}, got {result}")
            if result == "SUCCESS" and spec["lifetime"]:
                active[key] = (spec, port, nonce)
            elif result == "SUCCESS":
                active.pop(key, None)

            for stage in stages:
                if stage["after_request"] == request_index:
                    run_traffic(stage["traffic"])

        run_traffic(case["expect"].get("traffic", []))
    finally:
        for listener in listeners.values():
            listener.close()
        cleanup_mappings()
    print(f"PASS {case['name']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", default=os.path.join(os.path.dirname(__file__), "pcp-e2e-cases.yaml"))
    parser.add_argument("--router", default="172.28.41.1")
    parser.add_argument("--client-address", default="172.28.41.2")
    parser.add_argument("--external-address", default="198.51.100.1")
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    parser.add_argument("--agent", action="append", default=[], metavar="NAME=URL")
    parser.add_argument("--peer-address", action="append", default=[], metavar="NAME=ADDRESS")
    parser.add_argument("--case", action="append")
    parser.add_argument("--route-through-router", action="store_true",
                        help="route replies from the LAN echo service back through the test router")
    args = parser.parse_args()
    if args.route_through_router:
        if args.family == "ipv4":
            subprocess.run(["ip", "route", "replace", "198.51.100.0/24",
                            "via", args.router], check=True)
        else:
            subprocess.run(["ip", "-6", "route", "replace", "fd42:5351:5352::/64",
                            "via", "fd42:5351:5351::1"], check=True)
    with open(args.cases, encoding="utf-8") as source:
        corpus = yaml.safe_load(source)
    agents = dict(item.split("=", 1) for item in args.agent)
    args.peer_addresses = dict(item.split("=", 1) for item in args.peer_address)
    args.socket_family = socket.AF_INET6 if args.family == "ipv6" else socket.AF_INET
    needed = {traffic["from"] for case in corpus["cases"]
              for traffic in (case.get("expect", {}).get("traffic", []) +
                              [probe for stage in case.get("expect", {}).get("traffic_stages", [])
                               for probe in stage["traffic"]])
              if case.get("family", "ipv4") == args.family}
    if needed - agents.keys():
        parser.error("missing agents for: " + ", ".join(sorted(needed - agents.keys())))
    cases = [case for case in corpus["cases"]
             if case.get("family", "ipv4") == args.family
             and (not args.case or case["name"] in args.case)]
    if not cases:
        parser.error("no matching cases")
    failures = 0
    with socket.socket(args.socket_family, socket.SOCK_DGRAM) as pcp_sock:
        pcp_sock.settimeout(2)
        pcp_sock.bind((args.client_address, 0))
        for case in cases:
            timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            print(f"CASE START {timestamp} {case['name']}", flush=True)
            try:
                run_case(case, args, agents, pcp_sock)
            except Exception as error:
                failures += 1
                print(f"FAIL {case['name']}: {error}", file=sys.stderr)
            finally:
                timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                print(f"CASE END {timestamp} {case['name']}", flush=True)
    print(f"Summary: {len(cases) - failures} passed, {failures} failed")
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())

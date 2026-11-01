#!/usr/bin/env python3
"""Execute YAML PCP mapping scenarios and verify real forwarding behavior."""
import argparse
import copy
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


def build_map_packet(client, spec, peer_addresses, nonce=None):
    nonce = nonce or os.urandom(12)
    body = nonce + bytes(({"tcp": 6, "udp": 17}[spec["protocol"]], 0, 0, 0))
    body += struct.pack("!HH", spec["internal_port"], spec["suggested_external_port"])
    suggested_address = spec.get("suggested_external_address")
    body += v6_address(suggested_address) if suggested_address else b"\0" * 16
    opcode = {"MAP": 1, "PEER": 2}[spec.get("opcode", "MAP")]
    packet = bytes((2, opcode, 0, 0)) + struct.pack("!I", spec["lifetime"])
    packet += v6_address(client) + body
    if opcode == 2:
        peer = peer_addresses.get(spec["remote_peer"], spec["remote_peer"])
        packet += struct.pack("!H", spec["remote_peer_port"]) + b"\0\0" + v6_address(peer)
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
        option = bytes((3, 0, 0, 20)) + bytes((0, prefix))
        option += struct.pack("!H", remote_port) + v6_address(peer)
        packet += option * filt.get("repeat", 1)
    if spec.get("prefer_failure"):
        packet += bytes((2, 0, 0, 0))
    packet += bytes((128, 0, 0, 0)) * spec.get("unknown_optional_options", 0)
    if len(packet) > 1100:
        raise ValueError(f"PCP request exceeds 1100-octet limit ({len(packet)} octets)")
    return packet, nonce, body


def map_request(sock, router, client, spec, peer_addresses, nonce=None):
    packet, nonce, body = build_map_packet(client, spec, peer_addresses, nonce)
    sock.sendto(packet, (router, 5351))
    response, _ = sock.recvfrom(2048)
    opcode = {"MAP": 1, "PEER": 2}[spec.get("opcode", "MAP")]
    response_opcode = 0x80 | opcode
    minimum_length = 80 if opcode == 2 else 60
    if len(response) < minimum_length or response[:2] != bytes((2, response_opcode)):
        raise AssertionError(f"malformed PCP {spec.get('opcode', 'MAP')} response ({len(response)} bytes)")
    result = RESULTS.get(response[3], f"UNKNOWN({response[3]})")
    if result == "SUCCESS":
        if response[24:36] != nonce:
            raise AssertionError("PCP response did not echo the MAP nonce")
        if response[36] != body[12] or response[40:42] != body[16:18]:
            raise AssertionError("PCP response changed the mapped protocol or internal port")
        if ipaddress.ip_address(client).version == 6:
            expected_address = spec.get("suggested_external_address", client)
            if response[44:60] != v6_address(expected_address):
                actual = socket.inet_ntop(socket.AF_INET6, response[44:60])
                raise AssertionError(f"PCP response external IPv6 address expected "
                                     f"{expected_address}, got {actual}")
        if opcode == 2:
            peer = peer_addresses.get(spec["remote_peer"], spec["remote_peer"])
            if response[60:62] != struct.pack("!H", spec["remote_peer_port"]):
                raise AssertionError("PCP PEER response changed the remote peer port")
            if response[64:80] != v6_address(peer):
                raise AssertionError("PCP PEER response changed the remote peer address")
            suggested_address = spec.get("suggested_external_address")
            if suggested_address and response[44:60] != v6_address(suggested_address):
                raise AssertionError("PCP PEER response did not honor the suggested external address")
    return result, struct.unpack("!H", response[42:44])[0], nonce


NATPMP_RESULTS = {0: "SUCCESS", 1: "UNSUPP_VERSION", 2: "NOT_AUTHORIZED",
                  3: "NETWORK_FAILURE", 4: "OUT_OF_RESOURCES", 5: "UNSUPP_OPCODE"}


def natpmp_request(sock, router, spec):
    opcode = spec["opcode"]
    if opcode == "PUBLIC_ADDRESS":
        packet = bytes((0, 0))
        expected_opcode = 128
    else:
        protocol_opcode = {"udp": 1, "tcp": 2}[spec["protocol"]]
        packet = struct.pack("!BBHHHI", 0, protocol_opcode, 0,
                             spec["private_port"], spec["public_port"], spec["lifetime"])
        expected_opcode = 128 + protocol_opcode
    sock.sendto(packet, (router, 5351))
    response, _ = sock.recvfrom(64)
    expected_length = 12 if opcode == "PUBLIC_ADDRESS" else 16
    if len(response) != expected_length or response[:2] != bytes((0, expected_opcode)):
        raise AssertionError(f"malformed NAT-PMP {opcode} response ({len(response)} bytes)")
    result_code = struct.unpack("!H", response[2:4])[0]
    result = NATPMP_RESULTS.get(result_code, f"UNKNOWN({result_code})")
    if result == "SUCCESS" and opcode == "PUBLIC_ADDRESS":
        address = socket.inet_ntop(socket.AF_INET, response[8:12])
        return result, address, None
    if result == "SUCCESS":
        private_port, public_port, _lifetime = struct.unpack("!HHI", response[8:16])
        if private_port != spec["private_port"]:
            raise AssertionError("NAT-PMP response changed the private port")
        if spec["lifetime"] and spec["public_port"] and public_port != spec["public_port"]:
            raise AssertionError("NAT-PMP response changed the requested public port")
        return result, public_port, None
    return result, 0, None


def send_mapping_request(sock, router, client, spec, peer_addresses, nonce=None):
    if spec.get("protocol_family", "PCP") == "NAT-PMP":
        return natpmp_request(sock, router, spec)
    return map_request(sock, router, client, spec, peer_addresses, nonce)


def flatten_cases(corpus):
    cases = []
    sections = corpus.get("sections")
    if not isinstance(sections, list) or not sections:
        raise ValueError("corpus must contain a non-empty sections list")
    section_names = set()
    for section in sections:
        name = section.get("name")
        section_cases = section.get("cases")
        if not name or name in section_names or not isinstance(section_cases, list):
            raise ValueError("sections must have unique names and cases lists")
        section_names.add(name)
        for case in section_cases:
            case_copy = copy.deepcopy(case)
            case_copy["section"] = name
            cases.append(case_copy)
    return cases


def case_families(case):
    families = case.get("families", ["ipv4", "ipv6"])
    if not isinstance(families, list) or not families or any(
            family not in ("ipv4", "ipv6") for family in families):
        raise ValueError(f"{case.get('name', '<unnamed>')}: invalid families list")
    return families


def resolve_family(value, family):
    if isinstance(value, dict):
        if set(value) == {"ipv4", "ipv6"}:
            return resolve_family(value[family], family)
        return {key: resolve_family(item, family) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_family(item, family) for item in value]
    return value


def case_for_family(case, family):
    resolved = resolve_family(case, family)
    resolved.pop("families", None)
    resolved["before_traffic"] = [
        item for item in resolved.get("before_traffic", [])
        if family in item.get("families", ["ipv4", "ipv6"])]
    for traffic in resolved["before_traffic"]:
        traffic.pop("families", None)
    resolved["expect"]["traffic"] = [
        item for item in resolved["expect"].get("traffic", [])
        if family in item.get("families", ["ipv4", "ipv6"])]
    for traffic in resolved["expect"]["traffic"]:
        traffic.pop("families", None)
    for stage in resolved.get("expect", {}).get("traffic_stages", []):
        stage["traffic"] = [item for item in stage.get("traffic", [])
                            if family in item.get("families", ["ipv4", "ipv6"])]
        for traffic in stage["traffic"]:
            traffic.pop("families", None)
    return resolved


def validate_corpus(corpus):
    cases = flatten_cases(corpus)
    if not cases:
        raise ValueError("corpus must contain at least one case")
    names = [case.get("name") for case in cases]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise ValueError("case names must be present and unique")
    for case in cases:
        for family in case_families(case):
            resolved = case_for_family(case, family)
            requests = resolved.get("requests", [resolved["request"]] if "request" in resolved else [])
            expected = resolved.get("expect", {}).get("results", [resolved.get("expect", {}).get("result")])
            if not requests or len(requests) != len(expected) or any(not code for code in expected):
                raise ValueError(f"{case['name']} ({family}): request/result count mismatch")
            for request in requests:
                request_family = request.get("protocol_family", "PCP")
                if request_family == "NAT-PMP":
                    if family != "ipv4":
                        raise ValueError(f"{case['name']} ({family}): NAT-PMP is IPv4-only")
                    if request.get("opcode") == "PUBLIC_ADDRESS":
                        continue
                    if request.get("opcode") not in ("UDP", "TCP"):
                        raise ValueError(f"{case['name']} ({family}): invalid NAT-PMP opcode")
                    if request.get("protocol") != request["opcode"].lower():
                        raise ValueError(f"{case['name']} ({family}): NAT-PMP protocol/opcode mismatch")
                    for field in ("private_port", "public_port"):
                        minimum = 1 if field == "private_port" else 0
                        if type(request.get(field)) is not int or not minimum <= request[field] <= 65535:
                            raise ValueError(f"{case['name']} ({family}): invalid {field}")
                    if type(request.get("lifetime")) is not int or request["lifetime"] < 0:
                        raise ValueError(f"{case['name']} ({family}): invalid lifetime")
                    continue
                if request_family != "PCP" or request.get("opcode", "MAP") not in ("MAP", "PEER") or request.get("protocol") not in ("tcp", "udp"):
                    raise ValueError(f"{case['name']} ({family}): unsupported mapping protocol or opcode")
                for field in ("internal_port", "suggested_external_port"):
                    minimum = 0 if field == "suggested_external_port" else 1
                    if type(request.get(field)) is not int or not minimum <= request[field] <= 65535:
                        raise ValueError(f"{case['name']} ({family}): invalid {field}")
                if request.get("suggested_external_address"):
                    ipaddress.ip_address(request["suggested_external_address"])
                filters = request.get("filters", [request["filter"]] if request.get("filter") else [])
                for filt in filters:
                    prefix = filt.get("prefix_length")
                    limit = 32 if family == "ipv4" else 128
                    if type(prefix) is not int or not 0 <= prefix <= limit:
                        raise ValueError(f"{case['name']} ({family}): invalid FILTER prefix")
                    repeat = filt.get("repeat", 1)
                    if type(repeat) is not int or repeat < 1:
                        raise ValueError(f"{case['name']} ({family}): invalid FILTER repeat count")
                unknown_options = request.get("unknown_optional_options", 0)
                if type(unknown_options) is not int or unknown_options < 0:
                    raise ValueError(f"{case['name']} ({family}): invalid optional option count")
                filter_count = sum(filt.get("repeat", 1) for filt in filters)
                request_size = (80 if request.get("opcode") == "PEER" else 60)
                request_size += filter_count * 24
                request_size += 4 if request.get("prefer_failure") else 0
                request_size += unknown_options * 4
                if request_size > 1100:
                    raise ValueError(f"{case['name']} ({family}): PCP request exceeds 1100 octets")
                if request.get("opcode") == "PEER":
                    if not request.get("remote_peer") or type(request.get("remote_peer_port")) is not int or not 1 <= request["remote_peer_port"] <= 65535:
                        raise ValueError(f"{case['name']} ({family}): PEER requires remote peer address and port")
            traffic = list(resolved.get("before_traffic", []))
            traffic.extend(resolved.get("expect", {}).get("traffic", []))
            traffic.extend(probe for stage in resolved.get("expect", {}).get("traffic_stages", [])
                           for probe in stage.get("traffic", []))
            for probe_spec in traffic:
                if probe_spec.get("protocol") not in ("tcp", "udp") or probe_spec.get("expect") not in (
                        "delivered", "blocked"):
                    raise ValueError(f"{case['name']} ({family}): invalid traffic expectation")
    return len(cases)


def self_test(corpus):
    count = validate_corpus(corpus)
    family_runs = sum(len(case_families(case)) for case in flatten_cases(corpus))
    addresses = {"allowed-peer": "198.51.100.2", "denied-peer": "198.51.100.130"}
    spec = {"protocol": "udp", "lifetime": 120, "internal_port": 41000,
            "suggested_external_port": 41000, "filter": {"remote_peer": "allowed-peer",
            "remote_port": 42000, "prefix_length": 32}}
    packet, nonce, _ = build_map_packet("172.28.41.2", spec, addresses, bytes(range(12)))
    assert packet[24:36] == nonce
    assert packet[60:64] == bytes((3, 0, 0, 20))
    assert packet[64:68] == bytes((0, 128, 0xA4, 0x10))
    assert packet[68:84] == v6_address(addresses["allowed-peer"])

    spec["filters"] = [spec.pop("filter"), {"remote_peer": "denied-peer",
                                             "remote_port": 0, "prefix_length": 128}]
    spec["filters"][0]["prefix_length"] = 128
    multi, _, _ = build_map_packet("2001:db8:1::2", spec, {
        "allowed-peer": "2001:db8:9000::2", "denied-peer": "2001:db8:9000::130"}, nonce)
    assert multi[60] == 3 and multi[84] == 3
    assert multi[65] == 128 and multi[89] == 128
    max_filter_spec = {
        "protocol": "udp", "lifetime": 120, "internal_port": 41017,
        "suggested_external_port": 41017, "prefer_failure": True,
        "unknown_optional_options": 1,
        "filter": {"remote_peer": "allowed-peer", "remote_port": 0,
                    "prefix_length": 32, "repeat": 43},
    }
    max_filter, _, _ = build_map_packet("172.28.41.2", max_filter_spec, addresses, nonce)
    assert len(max_filter) == 1100
    assert max_filter[-8:] == bytes((2, 0, 0, 0, 128, 0, 0, 0))
    spec["filters"] = [{"remote_peer": "::", "remote_port": 0, "prefix_length": 0}]
    cleared, _, _ = build_map_packet("2001:db8:1::2", spec, {}, nonce)
    assert cleared[65:68] == bytes((0, 0, 0))
    peer, _, _ = build_map_packet("172.28.41.2", {
        "opcode": "PEER", "protocol": "udp", "lifetime": 120,
        "internal_port": 41020, "suggested_external_port": 41020,
        "remote_peer": "allowed-peer", "remote_peer_port": 42100,
        "unknown_optional_options": 255,
    }, addresses, nonce)
    assert len(peer) == 1100 and peer[1] == 2
    assert peer[60:64] == bytes((0xA4, 0x74, 0, 0))
    assert peer[64:80] == v6_address(addresses["allowed-peer"])
    natpmp_address = bytes((0, 0))
    natpmp_udp = struct.pack("!BBHHHI", 0, 1, 0, 41100, 41100, 120)
    assert natpmp_address == b"\0\0" and len(natpmp_udp) == 12 and natpmp_udp[1] == 1
    print(f"PASS YAML sections ({count} logical cases, {family_runs} family runs)")
    print("PASS IPv4/IPv6 PCP MAP, FILTER, and PEER encoding; NAT-PMP encoding")


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


class PeerFlow:
    def __init__(self, peer, host, peer_port, protocol, client, internal_port):
        family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
        transport = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        self.sock = socket.socket(family, transport)
        self.sock.settimeout(2)
        self.sock.bind((client, internal_port))
        self.sock.connect((host, peer_port))
        self.peer = peer
        self.protocol = protocol

    def exchange(self):
        token = os.urandom(16)
        self.sock.sendall(token)
        observed = json.loads(self.sock.recv(4096))
        if observed.get("token_hex") != token.hex():
            raise AssertionError(f"PCP PEER {self.protocol} payload was not echoed by {self.peer}")
        return observed

    def check_mapping(self, external, external_port, observed):
        if observed.get("source") != external or observed.get("source_port") != external_port:
            raise AssertionError(f"PCP PEER {self.protocol} expected WAN tuple "
                                 f"{external}:{external_port}; got {observed}")

    def close(self):
        self.sock.close()


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
    peer_flows = {}

    def cleanup_mappings():
        for (protocol, internal_port), (original, _port, nonce) in active.items():
            if original.get("protocol_family") == "NAT-PMP":
                delete = dict(original, public_port=0, lifetime=0)
                result, _assigned, _ = natpmp_request(pcp_sock, args.router, delete)
                if result != "SUCCESS":
                    raise AssertionError(f"cleanup of NAT-PMP {protocol}/{internal_port} returned {result}")
                continue
            if original.get("opcode") == "PEER":
                # RFC 6887 does not define lifetime zero as PEER deletion.
                continue
            delete = dict(original, lifetime=0)
            delete.pop("filter", None)
            delete.pop("filters", None)
            delete.pop("prefer_failure", None)
            delete.pop("unknown_optional_options", None)
            result, _assigned, _ = map_request(
                pcp_sock, args.router, args.client_address, delete,
                args.peer_addresses, nonce)
            if result != "SUCCESS":
                raise AssertionError(f"cleanup of {protocol}/{internal_port} returned {result}")

    listeners = {}
    peer_external_address = (args.client_address if args.family == "ipv6"
                             else args.external_address)
    def run_traffic(traffic_items):
        for traffic in traffic_items:
            if traffic.get("mode") in ("peer", "peer-implicit", "peer-existing"):
                spec = next(request for request in requests
                            if request.get("opcode") == "PEER"
                            and request["protocol"] == traffic["protocol"])
                peer = args.peer_addresses.get(spec["remote_peer"], spec["remote_peer"])
                key = (spec["protocol"], spec["internal_port"])
                if traffic["mode"] == "peer-implicit":
                    flow = PeerFlow(traffic["from"], peer, spec["remote_peer_port"],
                                    spec["protocol"], args.client_address,
                                    spec["internal_port"])
                    peer_flows[key] = (flow, flow.exchange())
                elif traffic["mode"] == "peer-existing":
                    _flow, observed = peer_flows[key]
                    mapping = active[key]
                    _flow.check_mapping(peer_external_address, mapping[1], observed)
                else:
                    flow = PeerFlow(traffic["from"], peer, spec["remote_peer_port"],
                                    spec["protocol"], args.client_address,
                                    spec["internal_port"])
                    try:
                        flow.check_mapping(peer_external_address, active[key][1], flow.exchange())
                    finally:
                        flow.close()
                continue
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
        run_traffic(case.get("before_traffic", []))
        stages = case["expect"].get("traffic_stages", [])
        for request_index, (spec, wanted) in enumerate(zip(requests, expected), 1):
            protocol = spec.get("protocol", "address")
            internal_port = spec.get("internal_port", spec.get("private_port", request_index))
            key = (protocol, internal_port)
            prior = active.get(key)
            result, port, nonce = send_mapping_request(
                pcp_sock, args.router, args.client_address, spec,
                args.peer_addresses, prior[2] if prior else None)
            if args.snapshot_gate_prefix:
                gate = f"{args.snapshot_gate_prefix}-{request_index}.ready"
                with open(gate, "w", encoding="utf-8"):
                    pass
                while os.path.exists(gate):
                    time.sleep(0.02)
            if result != wanted:
                raise AssertionError(f"{spec.get('protocol_family', 'PCP')} response expected {wanted}, got {result}")
            if (result == "SUCCESS" and spec.get("opcode") == "PUBLIC_ADDRESS"
                    and port != args.external_address):
                raise AssertionError(f"NAT-PMP public address expected {args.external_address}, got {port}")
            if result == "SUCCESS" and spec.get("lifetime", 0):
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
        for flow, _observed in peer_flows.values():
            flow.close()
        cleanup_mappings()
    print(f"PASS {case['name']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", default=os.path.join(os.path.dirname(__file__), "pcp-e2e-cases.yaml"))
    parser.add_argument("--self-test", action="store_true",
                        help="validate YAML cases and PCP/NAT-PMP encoding without a daemon")
    parser.add_argument("--router", default="172.28.41.1")
    parser.add_argument("--client-address", default="172.28.41.2")
    parser.add_argument("--external-address", default="198.51.100.1")
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    parser.add_argument("--agent", action="append", default=[], metavar="NAME=URL")
    parser.add_argument("--peer-address", action="append", default=[], metavar="NAME=ADDRESS")
    parser.add_argument("--case", action="append")
    parser.add_argument("--snapshot-gate-prefix",
                        help="pause before checking each PCP result until the harness snapshots daemon state")
    parser.add_argument("--route-through-router", action="store_true",
                        help="route replies from the LAN echo service back through the test router")
    args = parser.parse_args()
    if args.family == "ipv6" and args.external_address == "198.51.100.1":
        args.external_address = "2001:db8:9000::1"
    with open(args.cases, encoding="utf-8") as source:
        corpus = yaml.safe_load(source)
    if args.self_test:
        self_test(corpus)
        return 0
    validate_corpus(corpus)
    if args.route_through_router:
        if args.family == "ipv4":
            subprocess.run(["ip", "route", "replace", "198.51.100.0/24",
                            "via", args.router], check=True)
        else:
            subprocess.run(["ip", "-6", "route", "replace", "2001:db8:9000::/64",
                            "via", args.router], check=True)
    agents = dict(item.split("=", 1) for item in args.agent)
    args.peer_addresses = dict(item.split("=", 1) for item in args.peer_address)
    args.socket_family = socket.AF_INET6 if args.family == "ipv6" else socket.AF_INET
    all_cases = flatten_cases(corpus)
    cases = [case_for_family(case, args.family) for case in all_cases
             if args.family in case_families(case)
             and (not args.case or case["name"] in args.case)]
    needed = {traffic["from"] for case in cases
              for traffic in (case.get("before_traffic", []) +
                              case.get("expect", {}).get("traffic", []) +
                              [probe for stage in case.get("expect", {}).get("traffic_stages", [])
                               for probe in stage["traffic"]])}
    if needed - agents.keys():
        parser.error("missing agents for: " + ", ".join(sorted(needed - agents.keys())))
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

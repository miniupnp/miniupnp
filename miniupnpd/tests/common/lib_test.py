"""Helpers the PCP test runners share (pcp_wire/run_pcp_wire_cases.py, pcp_e2e/run_pcp_e2e_cases.py)."""

import argparse
import collections
import contextlib
import copy
import fcntl
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import re
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import pcap_reader  # noqa: E402
import pcp_corpus_expander  # noqa: E402
import pcp_packet_encoding  # noqa: E402
import traffic_agent  # noqa: E402

# The checks of the PCP tests are assert statements, which python -O removes: every case would pass.
if not __debug__:
    raise SystemExit("run the PCP tests without python -O (or PYTHONOPTIMIZE): their checks are asserts")


class LanEcho:
    """A UDP or TCP echo listener on the LAN client, which a WAN agent reaches through a mapping.

    once=True serves one exchange and ends (a traffic probe: the payloads it received are in
    `received`, to compare with what the WAN agent sent). Otherwise it serves until close().
    read_bytes: a TCP exchange reads until that many bytes arrived (default: one recv)."""

    def __init__(self, family, bind, port, protocol, once=False, read_bytes=None):
        self.protocol = protocol
        self.once = once
        self.read_bytes = read_bytes
        self.received = []
        self.sock = socket.socket(family, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind, port))
        self.sock.settimeout(1.0 if once else 0.2)
        if protocol == "tcp":
            self.sock.listen(1 if once else 8)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                self.serve_one()
            except socket.timeout:
                if self.once:
                    return
            except OSError:
                return
            else:
                if self.once:
                    return

    def serve_one(self):
        if self.protocol == "udp":
            payload, peer = self.sock.recvfrom(4096)
            self.received.append(payload)
            self.sock.sendto(payload, peer)
            return
        conn, _ = self.sock.accept()
        with conn:
            conn.settimeout(1.0)
            if self.read_bytes:
                payload = b""
                while len(payload) < self.read_bytes:
                    block = conn.recv(4096)
                    if not block:
                        break
                    payload += block
            else:
                payload = conn.recv(4096)
            self.received.append(payload)
            if payload:
                conn.sendall(payload)

    def join(self, timeout):
        self.thread.join(timeout=timeout)

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=1)


# Sending requests to a daemon, and building their bytes from the expanded YAML of the PCP test corpora


TIMEOUT = 2.0


def exchange(sock, address, request):
    """Send `request` and return the first datagram back; the socket needs a timeout (a silent daemon
    would block the run otherwise)."""
    if sock.gettimeout() is None:
        raise ValueError("exchange needs a socket with a timeout (sock.settimeout)")
    sock.sendto(request, address)
    response, _ = sock.recvfrom(2048)
    return response


def receive_within(sock, seconds=0.25):
    """What arrives within `seconds` (a datagram), or None; the timeout of the socket is put back."""
    previous = sock.gettimeout()
    sock.settimeout(seconds)
    try:
        return sock.recvfrom(2048)[0]
    except socket.timeout:
        return None
    finally:
        sock.settimeout(previous)


def expect_silence(sock, address, request):
    sock.sendto(request, address)
    response = receive_within(sock)
    if response is not None:
        raise AssertionError(f"expected packet to be ignored, got {len(response)} response bytes")


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


def socket_family(name):
    """AF_INET6 for "ipv6", else AF_INET."""
    return socket.AF_INET6 if name == "ipv6" else socket.AF_INET


def key_value_pairs(items):
    """{KEY: VALUE} from command-line items of the form KEY=VALUE."""
    return dict(item.split("=", 1) for item in items)


def probe_and_check(agent, transport, host, port, expect, token=None, source_port=None, timeout=None):
    """Ask the WAN agent to send a token to host:port; its outcome has to be `expect` ("delivered" or
    "blocked"). Returns the outcome."""
    token = token or os.urandom(16)
    outcome = traffic_agent.request_probe(agent, transport, host, port, token.hex(),
                                          source_port=source_port, timeout=timeout)
    if outcome["delivered"] != (expect == "delivered"):
        raise AssertionError(f"{transport} {host}:{port}: expected {expect}; got {outcome}")
    return outcome


def client_address(sock, address):
    """The source address of requests sent with `sock`: the address it is bound to, else the one the
    route to `address` picks."""
    bound = sock.getsockname()[0]
    if bound not in ("0.0.0.0", "::"):
        return bound
    probe = socket.socket(sock.family, socket.SOCK_DGRAM)
    try:
        probe.connect(address)
        return probe.getsockname()[0]
    finally:
        probe.close()


pcp_option = pcp_packet_encoding.pcp_option


def client_ip_bytes(sock, address, selector):
    if selector == "unspecified":
        return b"\x00" * 16
    value = client_address(sock, address) if selector == "source" else selector
    return pcp_packet_encoding.ipv6_bytes(value)


def pcp_options(options):
    encoded = []
    for option in options:
        if "raw_hex" in option:
            encoded.append(bytes.fromhex(option["raw_hex"]))
        else:
            data = bytes.fromhex(option.get("data_hex", "")) * option.get("data_repeat", 1)
            encoded.append(pcp_option(option["code"], data))
    return b"".join(encoded)


def build_request(sock, address, spec):
    request = build_request_payload(sock, address, spec)
    for patch in spec.get("patches", []):
        offset = patch["offset"]
        data = bytes.fromhex(patch["hex"])
        if offset < 0 or offset + len(data) > len(request):
            raise ValueError("packet patch falls outside the request")
        request = request[:offset] + data + request[offset + len(data):]
    return request


def nonce_of(spec, default=None, length=pcp_packet_encoding.NONCE_LENGTH):
    """The nonce of a request: its nonce_hex, else `default`, else `length` random octets."""
    if "nonce_hex" in spec:
        return bytes.fromhex(spec["nonce_hex"])
    return default if default is not None else os.urandom(length)


def build_raw(sock, address, spec):
    return bytes.fromhex(spec["hex"])


def build_pcp_header(sock, address, spec):
    """A bare PCP common header, then append_hex, padded to size / cut to truncate_to."""
    request = pcp_packet_encoding.pcp_header(spec["version"], spec["opcode"], spec.get("lifetime", 0),
                                             client_ip_bytes(sock, address, spec.get("client", "unspecified")),
                                             spec.get("reserved", 0))
    if spec.get("response_bit"):
        request = request[:1] + bytes((request[1] | 0x80,)) + request[2:]
    request += bytes.fromhex(spec.get("append_hex", ""))
    if "size" in spec:
        request = request.ljust(spec["size"], b"\x00")
    if "truncate_to" in spec:
        request = request[:spec["truncate_to"]]
    return request


def build_pcp_mapping(sock, address, spec):
    """A PCP MAP (kind pcp_map) or PEER (pcp_peer, version 2 only) request with its options."""
    version = spec["version"]
    peer = None
    if spec["kind"] == "pcp_peer":
        if version != 2:
            raise ValueError("pcp_peer request builder requires version 2")
        peer = (spec["peer_port"], spec["peer_address"], spec.get("peer_reserved", 0))
    request = pcp_packet_encoding.pcp_mapping_request(
        version, spec.get("opcode", 1), spec.get("lifetime", 0),
        client_ip_bytes(sock, address, spec.get("client", "unspecified")),
        spec["protocol_number"], spec.get("internal_port", 40000), spec.get("external_port", 0),
        nonce_of(spec, pcp_packet_encoding.DEFAULT_NONCE) if version == 2 else None,
        client_ip_bytes(sock, address, spec.get("external_address", "::")),
        peer, pcp_options(spec.get("options", [])), spec.get("reserved", 0))
    request += bytes.fromhex(spec.get("append_hex", ""))
    if "truncate_to" in spec:
        request = request[:spec["truncate_to"]]
    return request


def build_pcp_auth(sock, address, spec):
    """A PCP AUTHENTICATION request: header, session ID, sequence number, options."""
    header = bytes((2, spec["opcode"], 0, spec["result_code"]))
    header += struct.pack("!I", 0) + (b"\x00" * 16)
    body = struct.pack("!II", spec["session_id"], spec["sequence_number"])
    return header + body + pcp_options(spec.get("options", []))


def build_natpmp(sock, address, spec):
    return pcp_packet_encoding.natpmp_packet(
        spec["opcode"], spec.get("private_port", 0), spec.get("public_port", 0), spec.get("lifetime", 0),
        version=spec["version"], reserved=spec.get("reserved", 0))


# The request kinds of an expanded corpus and their builders
REQUEST_BUILDERS = {"raw": build_raw, "pcp_header": build_pcp_header, "pcp_map": build_pcp_mapping,
                    "pcp_peer": build_pcp_mapping, "pcp_auth": build_pcp_auth, "natpmp": build_natpmp}


def build_request_payload(sock, address, spec):
    builder = REQUEST_BUILDERS.get(spec["kind"])
    if builder is None:
        raise ValueError(f"unsupported request kind: {spec['kind']}")
    return builder(sock, address, spec)


# Checking responses as the YAML corpora describe them: variables, captured fields, header, options


def assert_response_echo(request, response, expectation):
    for region in expectation.get("echo_request", []):
        start = region["offset"]
        end = start + region["length"]
        assert 0 <= start <= end <= len(request), "invalid request echo region"
        assert len(response) >= end, "response truncates echoed request bytes"
        assert response[start:end] == request[start:end], f"request bytes {start}:{end} were not echoed"


def resolve_value(value, variables):
    if isinstance(value, dict) and set(value) == {"add"}:
        return sum(resolve_value(part, variables) for part in value["add"])
    if isinstance(value, str) and value.startswith("$"):
        key = value[1:]
        if key not in variables:
            raise AssertionError(f"lifecycle variable {key!r} has not been set")
        return variables[key]
    return value


def resolve_request(value, variables):
    if isinstance(value, dict):
        if set(value) == {"add"}:
            return resolve_value(value, variables)
        return {key: resolve_request(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_request(item, variables) for item in value]
    return resolve_value(value, variables)


def capture_response(response, capture_spec):
    offset = capture_spec["offset"]
    size = {"u8": 1, "u16": 2, "u32": 4, "address": 16}.get(
        capture_spec["type"], capture_spec.get("length"))
    if size is None or offset < 0 or offset + size > len(response):
        raise AssertionError(f"response field at {offset} is truncated or has no length")
    if capture_spec["type"] == "u8":
        return response[offset]
    if capture_spec["type"] == "hex":
        return response[offset:offset + size].hex()
    if capture_spec["type"] == "address":
        address = ipaddress.ip_address(response[offset:offset + size])
        # str() of a mapped address differs: hex groups before Python 3.13, dotted since.
        return f"::ffff:{address.ipv4_mapped}" if address.ipv4_mapped else str(address)
    if capture_spec["type"] == "u16":
        return struct.unpack("!H", response[offset:offset + 2])[0]
    if capture_spec["type"] == "u32":
        return struct.unpack("!I", response[offset:offset + 4])[0]
    raise ValueError(f"unsupported capture type {capture_spec['type']}")


def check_field(name, actual, rules, variables):
    """The rules of one captured field (nonzero, equals, not_equals, min, max; remember keeps the value in
    `variables`). `name` is what the failure message calls the field."""
    if "nonzero" in rules:
        assert (actual != 0) == rules["nonzero"], f"{name} unexpectedly has value {actual}"
    if "equals" in rules:
        wanted = resolve_value(rules["equals"], variables)
        assert actual == wanted, f"{name} was {actual}, expected {wanted}"
    if "not_equals" in rules:
        forbidden = resolve_value(rules["not_equals"], variables)
        assert actual != forbidden, f"{name} unexpectedly equals {forbidden}"
    if "min" in rules:
        assert actual >= resolve_value(rules["min"], variables), f"{name} {actual} is below {rules['min']}"
    if "max" in rules:
        assert actual <= resolve_value(rules["max"], variables), f"{name} {actual} exceeds {rules['max']}"
    if "remember" in rules:
        variables[rules["remember"]] = actual


def assert_step_values(values, checks, variables):
    for field, rules in checks.items():
        check_field(field, values[field], rules, variables)


def response_result(response, protocol, offset=None):
    """The result code of a PCP (one octet, default offset 3) or NAT-PMP (two octets, default 2) response."""
    if protocol == "pcp":
        return response[3 if offset is None else offset]
    if protocol == "natpmp":
        offset = 2 if offset is None else offset
        return struct.unpack("!H", response[offset:offset + 2])[0]
    raise ValueError(f"unsupported protocol in sequence: {protocol}")


def check_protocol_response(request, response, protocol, spec, variables):
    expect = spec["expect"]
    assert len(response) >= 4, "response header is truncated"
    if protocol == "pcp":
        assert response[0] == expect["version"], f"unexpected PCP version {response[0]}"
        assert response[1] == expect["opcode"], f"unexpected PCP opcode {response[1]}"
    elif protocol == "natpmp":
        assert response[0] == expect["version"], f"unexpected NAT-PMP version {response[0]}"
        assert response[1] == expect["opcode"], f"unexpected NAT-PMP opcode {response[1]}"
    else:
        raise ValueError(f"unsupported protocol in sequence: {protocol}")
    result = response_result(response, protocol)
    assert result in expect["result"], f"unexpected {protocol} result code {result}"
    expected_length = len(request) if expect["length"] == "request" else expect["length"]
    assert len(response) in (expected_length if isinstance(expected_length, list) else [expected_length]), \
        f"expected {expected_length}-byte {protocol} response, got {len(response)}"
    assert_response_echo(request, response, expect)
    values = {name: capture_response(response, field)
              for name, field in spec.get("captures", {}).items()}
    assert_step_values(values, spec.get("assert", {}), variables)


def check_response_header(response, case, expect):
    """The version, opcode and reserved bytes of the response; returns its result code."""
    if case["protocol"] == "pcp":
        version_offset = expect.get("version_offset", 0)
        opcode_offset = expect.get("opcode_offset", 1)
        result_offset = expect.get("result_offset", 3)
        reserved_offset = expect.get("reserved_offset", 2)
        assert response[version_offset] == expect["version"], f"unexpected PCP response version {response[version_offset]}"
        assert response[opcode_offset] == expect["opcode"], f"unexpected PCP response opcode {response[opcode_offset]}"
        assert response[reserved_offset] == expect.get("reserved", 0), "bad PCP response reserved byte"
    else:
        version_offset = expect.get("version_offset", 0)
        opcode_offset = expect.get("opcode_offset", 1)
        result_offset = expect.get("result_offset", 2)
        assert response[version_offset] == expect["version"], f"unexpected NAT-PMP response version {response[version_offset]}"
        assert response[opcode_offset] == expect["opcode"], f"unexpected NAT-PMP response opcode {response[opcode_offset]}"
    return response_result(response, case["protocol"], result_offset)


def check_required_options(response, expect):
    """The options the response has to carry (expect.required_options)."""
    try:
        found = pcp_packet_encoding.parse_options(response, expect.get("options_offset", 24), "response option")
    except ValueError as error:
        raise AssertionError(str(error)) from None
    for required in expect["required_options"]:
        matching = [data for code, data in found if code == required["code"]]
        assert matching, f"required response option {required['code']} missing"
        if "data_hex" in required:
            assert bytes.fromhex(required["data_hex"]) in matching, f"response option {required['code']} data mismatch"
        if "minimum_length" in required:
            assert any(len(data) >= required["minimum_length"] for data in matching), f"response option {required['code']} too short"


# The daemon's lease files (lease_file and lease_file6) as lease records: which records a selector matches,
# and whether two sets of records are the same


LEASE_NONCE_FIELD = 7
LEASE_FIELDS = 15   # kind|proto|eport|family|iaddr|iport|ifname|nonce|prefer_failure|since|expiry|eaddr|raddr|rport|label


def lease_kind(desc):
    """The kind of a lease line by its description, and the PCP nonce in it: miniupnpd describes a PCP mapping
    as "PCP MAP <nonce>" or "PCP PEER <nonce>" (pcpserver.c) and a NAT-PMP one as "NAT-PMP <port> <proto>"
    (natpmp.c); anything else was made by UPnP IGD."""
    words = desc.split()
    if len(words) == 3 and words[0] == "PCP" and words[1] in ("MAP", "PEER"):
        return ("PCP-M" if words[1] == "MAP" else "PCP-P"), words[2].lower()
    if desc.startswith("NAT-PMP "):
        return "NAT-PMP", "NA"
    return "UPNP", "NA"


def lease_record(line):
    """One line of lease_file or lease_file6 as a lease record (LEASE_FIELDS, NA where the line has no such field),
    or None for a line of neither format.

    lease_file:  PROTO:eport:iaddr:iport:timestamp:desc, or PROTO:eport:rhost:iaddr:iport:timestamp:desc
                 with SUPPORT_REMOTEHOST (upnpredirect.c lease_file_add)
    lease_file6: PROTO;iaddr;iport;rhost;rport;uid;timestamp;desc (upnppinhole.c lease_file6_add); the
                 external port is the internal port, and the uid is left out (a reload may give another)."""
    def record(kind, proto, eport, family, iaddr, iport, nonce, expiry, raddr="NA", rport="NA", label="NA"):
        return "|".join((kind, proto, eport, family, iaddr, iport, "NA", nonce, "NA", "NA", expiry, "NA",
                         raddr or "NA", rport, label))
    head = line.split(";", 1)[0]
    if head.isalpha() and line.count(";") >= 7:
        proto, iaddr, iport, raddr, rport, _uid, expiry, desc = line.split(";", 7)
        if not (iport.isdigit() and expiry.isdigit()):
            return None
        kind, nonce = lease_kind(desc)
        label = desc if kind == "UPNP" else "NA"
        return record(kind, proto, iport, "IPv6", iaddr, iport, nonce, expiry, raddr,
                      rport if rport != "0" else "NA", label)
    fields = line.split(":", 6)
    if len(fields) < 6 or not fields[0].isalpha() or not fields[1].isdigit():
        return None
    if fields[3].isdigit() and fields[4].isdigit():
        proto, eport, iaddr, iport, expiry, desc = line.split(":", 5)
        raddr = ""
    elif len(fields) == 7 and fields[4].isdigit() and fields[5].isdigit():
        proto, eport, raddr, iaddr, iport, expiry, desc = fields
    else:
        return None
    kind, nonce = lease_kind(desc)
    return record(kind, proto, eport, "IPv4", iaddr, iport, nonce, expiry, raddr,
                  label=desc if kind == "UPNP" else "NA")


def lease_records(lines):
    """The lease records of the lines of lease_file and lease_file6 (in any order, also mixed)."""
    return [record for record in map(lease_record, lines) if record is not None]


def lease_nonces(nonce):
    """The ways a lease line can show the nonce `nonce` (hex, as on the wire): pcpserver.c copies the 12 bytes
    into three uint32_t and prints them with %08x, so on a little-endian host each 4-byte word is reversed."""
    nonce = nonce.lower()
    words = [nonce[i:i + 8] for i in range(0, len(nonce), 8)]
    swapped = "".join("".join(reversed([word[i:i + 2] for i in range(0, len(word), 2)])) for word in words)
    return {nonce, swapped}


def lease_line_matches(line, selector):
    """selector: kind (PCP-M, PCP-F, PCP-P, NAT-PMP), optional family (IPv4/IPv6), internal_port, nonce (hex),
    label (the last field as written: the escaped DESCRIPTION text, NA if none)."""
    fields = line.split("|")
    return (fields[0] == selector["kind"] and len(fields) > 5
            and ("family" not in selector or fields[3] == selector["family"])
            and ("internal_port" not in selector or fields[5] == str(selector["internal_port"]))
            and ("nonce" not in selector
                 or (len(fields) > LEASE_NONCE_FIELD and fields[LEASE_NONCE_FIELD] in lease_nonces(selector["nonce"])))
            and ("label" not in selector or fields[-1] == selector["label"]))


def match_lease_lines(selectors, lines):
    matched = []
    for selector in selectors:
        found = [line for line in lines if lease_line_matches(line, selector)]
        label = ", ".join(f"{key}={value}" for key, value in selector.items() if key != "count")
        if "count" in selector:
            assert len(found) == selector["count"], (
                f"lease file: expected {selector['count']} line(s) of {label}, found {len(found)}")
        else:
            assert found, f"lease file: no line of {label}"
        matched += found
    return sorted(matched)


LEASE_EXPIRY_FIELD = 10


def with_lease_expiry(line, expiry):
    """A lease line with its expiry field replaced."""
    fields = line.split("|")
    fields[LEASE_EXPIRY_FIELD] = str(expiry)
    return "|".join(fields)


def same_lease_lines(before, after, tolerance):
    """Equal lines; the expiry of a line may differ by `tolerance` seconds (the daemon computes the
    remaining lifetime again when it starts, which rounds to the second)."""
    if len(before) != len(after):
        return False
    for old, new in zip(before, after):
        if old == new:
            continue
        old_fields, new_fields = old.split("|"), new.split("|")
        if (not tolerance or len(old_fields) != len(new_fields) or len(old_fields) <= LEASE_EXPIRY_FIELD
                or old_fields[0] == "PCP-F"):
            return False
        old_expiry, new_expiry = old_fields[LEASE_EXPIRY_FIELD], new_fields[LEASE_EXPIRY_FIELD]
        old_fields[LEASE_EXPIRY_FIELD] = new_fields[LEASE_EXPIRY_FIELD] = ""
        if (old_fields != new_fields or not old_expiry.isdigit() or not new_expiry.isdigit()
                or abs(int(old_expiry) - int(new_expiry)) > tolerance):
            return False
    return True


# Checking the fields of a corpus request


def check_port(where, request, field, minimum=1):
    if type(request.get(field)) is not int or not minimum <= request[field] <= 65535:
        raise ValueError(f"{where}: invalid {field}")


def check_count(where, request, field, minimum=0):
    if type(request.get(field, 0)) is not int or request.get(field, 0) < minimum:
        raise ValueError(f"{where}: invalid {field}")


# Running the steps of a corpus case: cleanup, matching responses, probing a LAN listener


def run_cleanup(steps, run_step):
    """Run the cleanup steps of a case (they undo what it made); one that fails does not stop the others
    nor hide the result of the case."""
    for step in steps:
        try:
            run_step(step)
        except (AssertionError, OSError):
            pass


def match_responses(sock, request, protocol, expected, variables):
    """Receive one response per entry of `expected` (they may come in any order); each has to satisfy
    one of the entries that is left. The captured values go into `variables`."""
    for _ in range(len(expected)):
        response, _sender = sock.recvfrom(2048)
        errors = []
        for index, spec in enumerate(expected):
            candidate_variables = dict(variables)
            try:
                check_protocol_response(request, response, protocol, spec, candidate_variables)
            except AssertionError as error:
                errors.append(str(error))
                continue
            variables.update(candidate_variables)
            del expected[index]
            break
        else:
            raise AssertionError("response matched none of the expected replies: " + "; ".join(errors))


def probe_lan_listener(sock, address, spec, variables, peer_url):
    """A WAN actor probes a temporary LAN listener; both ends must agree."""
    spec = resolve_request(spec, variables)
    if spec["expect"] not in {"delivered", "blocked"}:
        raise ValueError("traffic_probe expect must be delivered or blocked")
    if not 1 <= spec["external_port"] <= 65535:
        if spec["expect"] == "blocked" and spec.get("skip_unrepresentable_port"):
            print(f"INFO: adjacent port {spec['external_port']} is outside the transport port space")
            return
        raise AssertionError("traffic_probe external port is outside 1..65535")
    token = os.urandom(24)
    echo = LanEcho(sock.family, client_address(sock, address), spec["internal_port"], spec["transport"],
                   once=True, read_bytes=len(token))
    try:
        outcome = probe_and_check(peer_url, spec["transport"], spec["external_address"],
                                  spec["external_port"], spec["expect"], token)
    finally:
        echo.join(1.5)
        echo.close()
    received = echo.received
    assert (token in received) == (spec["expect"] == "delivered"), \
        f"{spec['transport']} port {spec['external_port']}: expected {spec['expect']}, got {outcome}, LAN received={bool(received)}"


def matching_udp_packets(path, expect, family, check_payload):
    """UDP packets in a capture that go to the expected multicast destination."""
    destination = ipaddress.ip_address(expect["destinations"][family])
    matches = []
    for timestamp, frame in pcap_reader.read_pcap_packets(path):
        packet = pcap_reader.parse_udp_frame(frame)
        if packet is None or packet[1] != destination or packet[3] != expect["destination_port"]:
            continue
        if check_payload:
            payload = packet[4]
            if (packet[2] != expect["source_port"] or len(payload) != expect["length"]
                    or payload[0] != expect["version"] or payload[1] != expect["opcode"]
                    or payload[3] not in expect["result"]):
                continue
        matches.append(packet + (timestamp,))
    return matches


def parse_auth_response(response):
    """(result, session id, sequence number, {option code: data}) of a PCP AUTHENTICATION response;
    a malformed one fails the check."""
    try:
        return pcp_packet_encoding.parse_auth_response(response)
    except ValueError as error:
        raise AssertionError(str(error)) from None


# Packet capture with tcpdump, one pcap (and its tcpdump log) per case


class PacketCapture:
    """A running tcpdump writing <directory>/<name>.pcap; stop() ends it and writes <name>.tcpdump.log."""

    START_TIMEOUT = 5.0     # seconds tcpdump may take to report "listening on"

    def __init__(self, process, pcap_path, log_path, stop_timeout, ready_line):
        self.process = process
        self.pcap_path = pcap_path
        self.log_path = log_path
        self.stop_timeout = stop_timeout
        self.ready_line = ready_line

    @classmethod
    def start(cls, tcpdump, interface, capture_filter, directory, name, stop_timeout):
        pcap_path = os.path.join(directory, name + ".pcap")
        log_path = os.path.join(directory, name + ".tcpdump.log")
        command = [tcpdump, "--immediate-mode", "-i", interface, "-nn", "-s0", "-U", "-w", pcap_path,
                   capture_filter]
        try:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except OSError as error:
            raise SystemExit(f"unable to start tcpdump: {error}") from error
        ready, _, _ = select.select([process.stderr], [], [], cls.START_TIMEOUT)
        ready_line = process.stderr.readline() if ready else ""
        if "listening on" not in ready_line:
            process.kill()
            details = ready_line + process.communicate()[1]
            raise SystemExit(f"tcpdump failed to start for case {name}: {details.strip() or 'no output'}")
        return cls(process, pcap_path, log_path, stop_timeout, ready_line)

    def stop(self):
        process = self.process
        try:
            process.send_signal(signal.SIGINT)
            _, details = process.communicate(timeout=self.stop_timeout)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGINT)
            try:
                _, details = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                _, details = process.communicate()
        with open(self.log_path, "w", encoding="utf-8") as log_file:
            log_file.write(self.ready_line + details)
        print(f"PCAP {self.pcap_path}")


# Capture options of a runner: one directory per invocation, one pcap per case


def capture_name(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value):
        raise argparse.ArgumentTypeError(
            "capture name must start with a letter or digit and contain only letters, digits, _, - or .")
    return value


def prepare_capture_directory(args):
    if not args.capture_dir:
        return
    names = set(args.case or [])
    label = args.capture_name or (next(iter(names)) if len(names) == 1 else "all")
    # Docker supplies one timestamp for its IPv4 and IPv6 invocations.
    timestamp = os.environ.get("PCP_TEST_CAPTURE_TIMESTAMP")
    if not timestamp:
        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S.%f")
    capture_name(timestamp)
    label = capture_name(label)
    args.capture_dir = os.path.join(args.capture_dir, f"{timestamp}_{label}")
    os.makedirs(args.capture_dir, exist_ok=True)
    print(f"Capture directory: {args.capture_dir}")


def case_artifact_name(args, case):
    """<family>-<protocol>-<case>: the name of the files and directories a case leaves in the capture
    directory ("/" in a case name becomes "_")."""
    return f"{args.family}-{case['protocol']}-{case['name'].replace('/', '_')}"


def start_packet_capture(args, case):
    if not args.capture_dir:
        return None
    return PacketCapture.start(args.tcpdump, args.capture_interface,
                               case.get("capture_filter", f"udp port {args.port}"), args.capture_dir,
                               case_artifact_name(args, case), args.capture_timeout)


@contextlib.contextmanager
def packet_capture(args, case):
    """A packet capture of the case while it runs, when the run captures (--capture-dir)."""
    capture = start_packet_capture(args, case)
    try:
        yield
    finally:
        stop_packet_capture(capture)


def stop_packet_capture(capture):
    if capture is not None:
        capture.stop()


# The daemon's lease files: where to read them, and the lease_file / state checks of the corpora


class LeaseSource:
    """Where the lease_file steps and the state checks read the daemon's lease files, as lease records.

    files: their paths when the fixture shares them (--state-file, once for lease_file, once for lease_file6);
    command: prints them when the daemon runs elsewhere, a VM (--state-command);
    snapshot_dir: where the create and verify phases keep the lease-file snapshots (--snapshot-dir)."""

    def __init__(self, files=None, command=None, snapshot_dir=None):
        self.files = [files] if isinstance(files, str) else list(files or [])
        self.command = command
        self.snapshot_dir = snapshot_dir

    @classmethod
    def from_args(cls, args):
        return cls(args.state_file, args.state_command, args.snapshot_dir)

    @property
    def file(self):
        """The lease files as one name for the messages, None without --state-file."""
        return " ".join(self.files) or None

    def read_raw(self):
        """The lines of the files as written (a missing file has none)."""
        lines = []
        for path in self.files:
            try:
                with open(path, encoding="utf-8") as handle:
                    lines += handle.read().splitlines()
            except FileNotFoundError:
                pass
        return lines

    def read_file(self):
        return lease_records(self.read_raw())

    def raw_lines(self):
        """The lines as written, from --state-command or the files."""
        if self.command:
            result = subprocess.run(shlex.split(self.command), capture_output=True, text=True, check=False)
            if result.returncode != 0:
                raise AssertionError(f"--state-command failed: {(result.stderr or result.stdout).strip()}")
            return result.stdout.splitlines()
        if not self.files:
            raise AssertionError("a lease_file step needs --state-file or --state-command")
        return self.read_raw()

    def lines(self):
        """The lease records (lease_record) of raw_lines."""
        return lease_records(self.raw_lines())


NO_LEASE = LeaseSource()


# A check of the lease files keeps looking this long before it fails (the daemon expires mappings by itself,
# and a daemon may write its files later than it answers).
LEASE_SAVE_WAIT = 3


def check_state_file(expected, case, spec, variables, lease):
    """Check the daemon's lease files for the mapping of this lifecycle.

    The lease records (lease_record) have one line per mapping (PCP-M, NAT-PMP) or PEER mapping
    (PCP-P). The mapping is found by its internal port, which is unique to this run, and by the
    nonce of a PCP v2 request.
    expected is {line: M|P, mapping: present|absent}."""
    if lease.file is None:
        return
    if expected.get("line", "M") == "P":
        kind = "PCP-P"
    else:
        kind = "NAT-PMP" if case["protocol"] == "natpmp" else "PCP-M"
    selector = {"kind": kind, "internal_port": variables["internal_port"]}
    if case["protocol"] == "pcp" and spec.get("version") == 2:
        selector["nonce"] = variables["nonce"].hex()
    want = expected["mapping"] == "present"
    deadline = time.monotonic() + LEASE_SAVE_WAIT
    while True:
        found = [line for line in lease.read_file() if lease_line_matches(line, selector)]
        if bool(found) == want or time.monotonic() >= deadline:
            break
        time.sleep(0.2)
    assert bool(found) == want, (
        f"lease file {lease.file}: {kind} line for internal port "
        f"{variables['internal_port']} is {'missing' if want else 'still there'}"
        + (f": {found[0]}" if found else ""))


def run_lease_file_step(step, variables, lease):
    """Check the lease records of the daemon's lease files.

    lines: [{kind, family?, internal_port?, nonce?, label?, count?}]; without count, at least one line.
    wait_seconds: keep checking for that long, at least LEASE_SAVE_WAIT (the daemon expires mappings by itself).
    expiry_tolerance: seconds the expiry of a line may differ from the saved one (same_as).
    save: NAME / same_as: NAME keep the matching lines in the snapshot directory and compare them
    after the daemon restart (nonce, created time and expiry have to survive)."""
    deadline = time.monotonic() + max(step.get("wait_seconds", 0), LEASE_SAVE_WAIT)
    while True:
        try:
            matched = match_lease_lines(step["lines"], lease.lines())
            break
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
    for key in ("save", "same_as"):
        if key not in step:
            continue
        if lease.snapshot_dir is None:
            raise AssertionError(f"lease_file {key} needs --snapshot-dir")
        path = os.path.join(lease.snapshot_dir, f"lease-{variables['case_name']}-{step[key]}.txt")
        if key == "save":
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(matched) + "\n")
        else:
            with open(path, encoding="utf-8") as handle:
                saved = handle.read().splitlines()
            assert same_lease_lines(saved, matched, step.get("expiry_tolerance", 0)), (
                "lease file changed over the restart:\n  before: "
                + "\n  before: ".join(saved) + "\n  after:  " + "\n  after:  ".join(matched))


def lease_ports(case):
    """Internal ports a lease-restart case looks at (for the driver's firewall comparison)."""
    ports = set()
    for phase in case["request"]["phases"].values():
        for step in phase:
            for selector in step.get("lines", []):
                if "internal_port" in selector:
                    ports.add(selector["internal_port"])
    return sorted(ports)


# The status report every PCP test writes. The sections and the cases differ from test to test, the
# structure does not: one column per platform (a run updates only its own), the raw results in a JSON
# file beside the report, the sections with a table of cases (case, protocol, family, one status per
# platform, result / note).

STATUS_ORDER = ("PASS", "XFAIL", "FAIL", "SKIP")
PLATFORM_ORDER = ("linux", "freebsd", "debian-iptables")


def markdown_cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def case_key(case):
    return f"{case['protocol']}/{case['name']}"


def repo_root():
    """The repository: this file is <repo>/miniupnpd/tests/common/lib_test.py (in a container that
    only has the test directories mounted, the current directory)."""
    parents = os.path.abspath(__file__).split(os.sep)
    if len(parents) > 5 and parents[-4] == "miniupnpd" and parents[-3] == "tests":
        return os.sep.join(parents[:-4]) or os.sep
    return os.getcwd()


def status_data_path(suite):
    """Where the per-platform results behind the combined report of a test suite (pcp_wire, pcp_e2e)
    are kept: <repo>/.tmp/tests/<suite>/status-data.json. They are not part of the test directories."""
    return os.path.join(repo_root(), ".tmp", "tests", suite, "status-data.json")


def load_status_data(path):
    try:
        with open(path, encoding="utf-8") as data_file:
            data = json.load(data_file)
        if data.get("version") == 1 and isinstance(data.get("platforms"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "platforms": {}}


def merge_status(data, platform, family, run, results, known, keep_if_skipped=()):
    """Put the results of one run in the data of its platform.

    results: {case key: (status, detail)}; run: what the run was, shown in the platform's line;
    known: every case key of the corpus (the others are forgotten); keep_if_skipped: a SKIP whose
    detail starts like this does not replace an earlier result (a run without the fixture must not
    wipe the result of one that had it)."""
    entry = data["platforms"].setdefault(platform, {"results": {}})
    entry["updated"] = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    entry.setdefault("runs", {})[family] = run
    family_results = entry["results"].setdefault(family, {})
    for key, (status, detail) in results.items():
        if status == "SKIP" and key in family_results and detail.startswith(tuple(keep_if_skipped)):
            continue
        family_results[key] = [status, detail]
    for other in data["platforms"].values():
        for results_of_family in other["results"].values():
            for key in [key for key in results_of_family if key not in known]:
                del results_of_family[key]


def render_status(title, data, data_path, sections, extra_lines=()):
    """The combined Markdown report of the data. sections: [{title, description, cases}], each case
    with protocol, name, families and description."""
    platforms = sorted(data["platforms"], key=lambda name: (
        PLATFORM_ORDER.index(name) if name in PLATFORM_ORDER else len(PLATFORM_ORDER), name))
    shown = os.path.relpath(data_path, repo_root()) if os.path.abspath(data_path).startswith(repo_root()) else data_path
    lines = [
        f"# {title} Test Status",
        "",
        "One column per platform; a run updates only its own platform's column "
        "(raw results: `" + shown + "`).",
        "",
        "## Platforms",
        "",
    ]
    for name in platforms:
        counts = dict.fromkeys(STATUS_ORDER, 0)
        for family_results in data["platforms"][name]["results"].values():
            for status, _detail in family_results.values():
                counts[status] += 1
        runs = data["platforms"][name].get("runs", {})
        lines.append(
            f"- **{name}**: **{counts['PASS']} PASS**, **{counts['XFAIL']} XFAIL**, "
            f"**{counts['FAIL']} FAIL**, **{counts['SKIP']} SKIP** "
            f"(updated {data['platforms'][name]['updated']}; "
            + "; ".join(f"{family}: " + ", ".join(f"{key} `{value}`" for key, value in run.items())
                        for family, run in sorted(runs.items()))
            + ")")
    lines.extend(extra_lines)
    lines.extend(("", "## Results by section", ""))

    def cell(name, family, key):
        return data["platforms"][name]["results"].get(family, {}).get(key)

    for section in sections:
        rows = []
        for case in section["cases"]:
            key = case_key(case)
            for family in case["families"]:
                cells = {name: cell(name, family, key) for name in platforms}
                if any(cells.values()):
                    rows.append((case, family, cells))
        if not rows:
            continue
        lines.extend((f"### {markdown_cell(section['title'])}", "",
                      markdown_cell(section["description"]), "",
                      "| Case | Protocol | Family | " + " | ".join(platforms) + " | Result / note |",
                      "|---|---|---|" + "---|" * len(platforms) + "---|"))
        for case, family, cells in rows:
            notes = [f"{name}: {result[1]}" if len(platforms) > 1 else result[1]
                     for name, result in cells.items() if result and result[1] and result[0] != "PASS"]
            lines.append("| " + " | ".join((
                markdown_cell(case["name"]), markdown_cell(case["protocol"]), family,
                *(result[0] if result else "—" for result in cells.values()),
                markdown_cell("; ".join(notes) or case.get("description", "")),
            )) + " |")
        lines.append("")
    return "\n".join(lines)


def write_status(path, title, suite, platform, family, run, results, sections, data_path=None, extra_lines=(),
                 keep_if_skipped=()):
    """Merge one run into the data of the suite (data_path, default status_data_path(suite)) and
    rewrite the report at `path` and the data."""
    data_path = data_path or status_data_path(suite)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(data_path)), exist_ok=True)
    # a Docker and a FreeBSD run can end together: one merge at a time, or a result is lost. Read-only,
    # as a container's root may have made the lock file and the next run be the user on the host
    with os.fdopen(os.open(data_path + ".lock", os.O_RDONLY | os.O_CREAT, 0o644)) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = load_status_data(data_path)
        known = {case_key(case) for section in sections for case in section["cases"]}
        merge_status(data, platform, family, run, results, known, keep_if_skipped)
        report = render_status(title, data, data_path, sections, extra_lines)
        with open(data_path, "w", encoding="utf-8") as data_file:
            json.dump(data, data_file, indent=1)
            data_file.write("\n")
        with open(path, "w", encoding="utf-8") as report_file:
            report_file.write(report)


# The status report of a pcp_wire-style runner (outcomes keyed by protocol and case name)


FILTERED_SKIP_REASONS = frozenset({
    "excluded by --profile filter",
    "excluded by --protocol filter",
    "excluded by --family filter",
    "not selected by --case",
    "not selected for this invocation",
})


def is_filtered_skip(status, detail):
    return status == "SKIP" and detail in FILTERED_SKIP_REASONS


def write_status_report(path, title, suite, platform, family, run, sections, outcomes, data_path=None,
                        extra_lines=(), keep_if_skipped=()):
    """Merge the outcomes of one run of one address family into the per-platform results and rewrite the
    combined report (the format all the PCP tests share, write_status). outcomes: {(protocol, name):
    (status, detail)}; a case left out, or skipped only because the selection left it out, keeps its
    earlier result, and so does a platform without a run."""
    results = {f"{protocol}/{name}": outcome for (protocol, name), outcome in outcomes.items()
               if not is_filtered_skip(*outcome)}
    write_status(path, title, suite, platform, family, run, results, sections, data_path=data_path,
                 extra_lines=extra_lines, keep_if_skipped=keep_if_skipped)


def write_suite_report(args, title, suite, family, sections, outcomes, run=None, **options):
    """The report of one run: what every runner says about it. run: what the report says about the run
    (default its --run-info); options: write_status_report's."""
    write_status_report(args.status_file, title, suite, args.platform, family,
                        key_value_pairs(args.run_info) if run is None else run, sections, outcomes,
                        data_path=args.status_data_file, **options)
    print(f"Status report written to {args.status_file}")


def write_results_tsv(path, family, cases, outcomes):
    """The results file of a run that does not write the report itself: family, section, case, result,
    note, artifacts per line, as the e2e drivers write it."""
    with open(path, "w", encoding="utf-8") as handle:
        for case in cases:
            outcome = outcomes.get((case["protocol"], case["name"]))
            if outcome:
                note = " ".join(str(outcome[1]).split())
                handle.write("\t".join((family, case["section"], case["name"], outcome[0], note, "")) + "\n")


def write_driver_status(results_path, args, title, suite, sections):
    """Merge a results file (write_results_tsv) into the report, one address family at a time. Every
    section is given, also the ones this run did not run, or their results would be forgotten."""
    protocols = {case["name"]: case["protocol"] for section in sections for case in section["cases"]}
    outcomes = {}
    with open(results_path, encoding="utf-8") as handle:
        for line in handle:
            fields = line.rstrip("\n").split("\t")
            if len(fields) < 5 or fields[2] not in protocols:
                continue
            family, _section, name, result, note = fields[:5]
            outcomes.setdefault(family, {})[(protocols[name], name)] = (result, note)
    for family in sorted(outcomes):
        run = dict(key_value_pairs(args.run_info), cases=str(len(outcomes[family])))
        write_suite_report(args, title, suite, family, sections, outcomes[family], run=run)


def check_report_columns(write_report, case, protocol, platforms=("linux", "freebsd")):
    """A self-test of a suite's report: two platforms fill their own columns. write_report(results_path,
    args) is the suite's; case is one of its cases of ipv4, with its section."""
    with tempfile.TemporaryDirectory() as directory:
        results = os.path.join(directory, "results.tsv")
        args = argparse.Namespace(status_file=os.path.join(directory, "status.md"), run_info=["router=test"],
                                  status_data_file=os.path.join(directory, "data", "status-data.json"))
        for platform, status in ((platforms[1], "FAIL"), (platforms[0], "PASS")):
            with open(results, "w", encoding="utf-8") as handle:
                handle.write("\t".join(("ipv4", case["section"], case["name"], status, "a | note", "")) + "\n")
            write_report(results, argparse.Namespace(**vars(args), platform=platform))
        with open(args.status_file, encoding="utf-8") as handle:
            text = handle.read()
    assert f"| Case | Protocol | Family | {platforms[0]} | {platforms[1]} | Result / note |" in text, text
    assert f"| {case['name']} | {protocol} | ipv4 | PASS | FAIL | {platforms[1]}: a \\| note |" in text, text
    print("PASS status report (a column per platform)")


def write_results(path, args, cases, outcomes, corpus_path):
    """Machine-readable counterpart to the status report for branch comparisons."""
    with open(corpus_path, "rb") as corpus_file:
        corpus_sha256 = hashlib.sha256(corpus_file.read()).hexdigest()
    results = {
        "version": 1,
        "family": args.family,
        "profile": args.profile,
        "corpus_sha256": corpus_sha256,
        "cases": [
            {"protocol": case["protocol"], "name": case["name"],
             "status": outcomes[(case["protocol"], case["name"])][0],
             "detail": outcomes[(case["protocol"], case["name"])][1]}
            for case in cases
        ],
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as report:
        json.dump(results, report, indent=2)
        report.write("\n")


# A YAML corpus of cases: reading, checking and selecting its cases (profiles, families, requires, depends_on)


class CorpusError(ValueError):
    """The corpus or the selection is wrong; main() reports it with parser.error."""


REQUEST_KINDS = {"raw", "pcp_header", "pcp_map", "pcp_peer", "pcp_auth", "pcp_auth_sequence", "natpmp", "lifecycle",
                 "protocol_sequence", "lease_restart", "daemon_restart", "wan_renumber", "pcp_bulk"}


EXPECT_KINDS = {"response", "silence", "lifecycle", "auth_sequence", "unsolicited_announce", "mapping_update",
                "lease_restart", "bulk"}


REQUIRES = {"wan-peer", "daemon-restart", "pcp-peer", "wan-renumber", "lease-restart", "lease-file",
            "second-client", "scale"}


def load_corpus(data):
    """Expand the parsed YAML. Returns (corpus, profiles)."""
    corpus = pcp_corpus_expander.expand_corpus(data)
    if corpus.get("version") != 1:
        raise CorpusError("unsupported YAML corpus version")
    profiles = corpus.get("profiles", {"baseline": {}})
    return corpus, profiles


def read_checked_corpus(path, check):
    """(sections, cases, profiles, earlier cases) of a corpus; check(cases, profiles) is validate_cases or
    a suite's own, and returns the cases by protocol/name."""
    corpus, profiles = load_corpus(load_yaml(path))
    sections, cases = read_cases(corpus)
    return sections, cases, profiles, check(cases, profiles)


def read_cases(corpus):
    """The sections and the flat list of cases (each knows its section)."""
    sections = corpus.get("sections")
    if not isinstance(sections, list):
        raise CorpusError("YAML corpus must define readable sections")
    cases = []
    for section in sections:
        if not {"title", "description", "cases"}.issubset(section):
            raise CorpusError("each YAML section needs title, description and cases")
        for case in section["cases"]:
            case["section"] = section["title"]
            cases.append(case)
    return sections, cases


def check_case_shape(case, profiles):
    """The fields, the kinds and the profiles of one case."""
    if not set(case.get("profiles", profiles)).issubset(profiles):
        raise CorpusError(f"{case['name']}: unknown server profile")
    if not {"name", "protocol", "families", "request", "expect"}.issubset(case):
        raise CorpusError("every YAML case needs name, protocol, families, request and expect")
    if case["request"].get("kind") not in REQUEST_KINDS:
        raise CorpusError(f"unsupported request kind in case {case['name']}")
    if case["expect"].get("kind") not in EXPECT_KINDS:
        raise CorpusError(f"unsupported expectation kind in case {case['name']}")
    if case["expect"]["kind"] == "response":
        required = {"version", "opcode", "result"}
        if not required.issubset(case["expect"]) or not ({"length", "min_length"} & set(case["expect"])):
            raise CorpusError(f"response expectation incomplete in case {case['name']}")


def check_dependencies(case, earlier_cases, profiles):
    """The prerequisites (depends_on) of a case are earlier cases which cover its families and profiles,
    and the fixtures it requires exist."""
    dependencies = case.get("depends_on", [])
    if not isinstance(dependencies, list) or any(not isinstance(item, str) for item in dependencies):
        raise CorpusError("depends_on must be a list of protocol/case names")
    for dependency in dependencies:
        if dependency not in earlier_cases:
            raise CorpusError(f"{case['name']}: prerequisite {dependency} must be an earlier case")
        prerequisite = earlier_cases[dependency]
        if not set(case["families"]).issubset(prerequisite["families"]):
            raise CorpusError(f"{case['name']}: prerequisite {dependency} lacks a required family")
        if not set(case.get("profiles", profiles)).issubset(prerequisite.get("profiles", profiles)):
            raise CorpusError(f"{case['name']}: prerequisite {dependency} lacks a required profile")
    if set(case.get("requires", [])) - REQUIRES:
        raise CorpusError(f"{case['name']}: unknown required fixture")


def validate_cases(cases, profiles):
    """Check every case; returns the cases by protocol/name, for their prerequisites."""
    for case in cases:
        check_case_shape(case, profiles)
    identities = [(case["protocol"], case["name"]) for case in cases]
    if len(identities) != len(set(identities)):
        raise CorpusError("duplicate case names in YAML corpus")
    earlier_cases = {}
    for case in cases:
        check_dependencies(case, earlier_cases, profiles)
        earlier_cases[f"{case['protocol']}/{case['name']}"] = case
    return earlier_cases


def filter_reason(case, args, profiles):
    """Why --profile, --protocol or --family leave a case out (the text the report shows), or None."""
    if getattr(args, "profile", "baseline") not in case.get("profiles", profiles):
        return "excluded by --profile filter"
    protocol = getattr(args, "protocol", "both")
    if protocol != "both" and case["protocol"] not in (protocol, "both"):
        return "excluded by --protocol filter"
    if args.family not in case["families"]:
        return "excluded by --family filter"
    return None


def with_dependencies(keys, earlier_cases):
    """The case keys and, recursively, the prerequisites of each."""
    keys = set(keys)
    pending = list(keys)
    while pending:
        for dependency in earlier_cases[pending.pop()].get("depends_on", []):
            if dependency not in keys:
                keys.add(dependency)
                pending.append(dependency)
    return keys


def check_case_names(wanted, cases):
    """A --case of no case is a typo, not an empty selection."""
    unknown = set(wanted or ()) - {case["name"] for case in cases}
    if unknown:
        raise CorpusError("unknown case(s): " + ", ".join(sorted(unknown)))


def select_family_cases(corpus, args, resolve, keep=None):
    """resolve(case) of the cases of --family and --case in an e2e corpus, in corpus order; keep(case)
    narrows them further."""
    cases = flatten_cases(corpus)
    check_case_names(args.case, cases)
    return [resolve(case) for case in cases
            if args.family in case_families(case) and (not args.case or case["name"] in args.case)
            and (keep is None or keep(case))]


def print_case_rows(cases, flag=None):
    """The --list-cases output of a driver: section, case and, with flag(case), a true or false column."""
    for case in cases:
        print("\t".join([case["section"], case["name"]] + ([str(flag(case)).lower()] if flag else [])))


def select_cases(args, cases, profiles, earlier_cases):
    """The cases this invocation runs, with the prerequisites of the selected ones. A runner without
    --protocol, --mutating or the like has what their defaults mean: all of them, an empty selection is fine."""
    mutating = getattr(args, "mutating", True)
    mutating_cases = {case["name"] for case in cases if case.get("mutating")}
    selected = []
    for case in cases:
        if filter_reason(case, args, profiles):
            continue
        if getattr(args, "fixture_only", False) and not (set(case.get("requires", [])) & {"daemon-restart", "wan-renumber"}):
            continue
        if args.case is None or case["name"] in args.case:
            selected.append(case)
    if args.case:
        check_case_names(args.case, cases)
        selected = [case for case in selected if case["name"] in args.case]
        if not selected and not getattr(args, "allow_empty_selection", True):
            raise CorpusError("the requested case does not match --profile/--protocol/--family")
        if not mutating and any(case["name"] in mutating_cases for case in selected):
            raise CorpusError("mapping lifecycle cases require --mutating")
    elif not mutating:
        selected = [case for case in selected if case["name"] not in mutating_cases]

    keys = with_dependencies({f"{case['protocol']}/{case['name']}" for case in selected}, earlier_cases)
    return [case for case in cases if f"{case['protocol']}/{case['name']}" in keys]


def skip_reason(case, args, outcomes):
    """Why a selected case is not run on this invocation, or None."""
    requires = case.get("requires", [])
    if "wan-peer" in requires and not getattr(args, "peer_url", None):
        return "requires wan-peer fixture (--peer-url or PCP_TEST_WAN_PEER=1)"
    unsupported = [item for item in requires if item in getattr(args, "unsupported", ())]
    if unsupported:
        return f"requires {unsupported[0]}, unsupported on this platform"
    if "scale" in requires and not getattr(args, "scale", False):
        return "requires --scale (a long run, not part of the default runs)"
    if "second-client" in requires and not getattr(args, "second_client", None):
        return "requires second-client address (--second-client)"
    if "wan-renumber" in requires and not fixture_supports(args, "wan-renumber"):
        return "requires wan-renumber fixture (--fixture that supports wan-renumber)"
    if "lease-file" in requires and not (getattr(args, "state_file", None) or getattr(args, "state_command", None)):
        return "requires the daemon's lease files (--state-file or --state-command)"
    if "lease-restart" in requires and not getattr(args, "phase", None):
        return "requires lease-restart driver (--phase)"
    if "daemon-restart" in requires and not getattr(args, "fixture", None):
        return "requires daemon-restart fixture (--fixture)"
    blocked = []
    for dependency in case.get("depends_on", []):
        dep_protocol, dep_name = dependency.split("/", 1)
        dep_status = outcomes.get((dep_protocol, dep_name), ("SKIP", ""))[0]
        if dep_status != "PASS":
            blocked.append(f"{dependency} ({dep_status})")
    if blocked:
        return "prerequisite did not pass: " + ", ".join(blocked)
    return None


def unselected_reason(case, args, profiles, selected_ids):
    """Why a case that never ran is reported as SKIP."""
    reason = filter_reason(case, args, profiles)
    if reason:
        return reason
    if args.case and case["name"] not in args.case:
        return "not selected by --case"
    if case.get("mutating") and not args.mutating:
        return "requires --mutating"
    if (case["protocol"], case["name"]) not in selected_ids:
        return "not selected for this invocation"
    return "not run"


# The step engine: running the protocol_sequence, lifecycle and exchange cases of a corpus


def build_lifecycle_request(case, spec, step, variables):
    protocol = case["protocol"]
    lifetime = resolve_value(step["lifetime"], variables)
    if protocol == "pcp":
        client_ip = variables["client_ip"]
        external_port = resolve_value(step["external_port"], variables)
        internal_port = resolve_value(step.get("internal_port", "$internal_port"), variables)
        peer = (None if spec["operation"] == "pcp_map"
                else (spec["peer_port"], spec["peer_address"], spec.get("peer_external_port", 0)))
        return pcp_packet_encoding.pcp_mapping_request(
            spec["version"], spec["opcode"], lifetime, client_ip, spec["protocol_number"],
            internal_port, external_port, variables["nonce"] if spec["version"] != 1 else None, peer=peer)

    public_port = resolve_value(step["public_port"], variables)
    return pcp_packet_encoding.natpmp_packet(spec["opcode"], variables["internal_port"], public_port, lifetime,
                                             version=spec["version"], reserved=spec["reserved"])


def run_lifecycle_step(sock, address, case, spec, step, variables, lease=NO_LEASE):
    step_variables = dict(variables)
    if "nonce_hex" in step:
        step_variables["nonce"] = nonce_of(step)
    request = build_lifecycle_request(case, spec, step, step_variables)
    response = exchange(sock, address, request)
    assert len(response) == spec["response_length"], f"expected {spec['response_length']}-byte lifecycle response, got {len(response)}"
    assert response[spec["version_offset"]] == spec["version"], "unexpected lifecycle response version"
    assert response[spec["opcode_offset"]] == spec["response_opcode"], "unexpected lifecycle response opcode"
    result = response_result(response, case["protocol"], spec["result_offset"])
    expected_results = step.get("result", spec["result"])
    assert result in expected_results, f"unexpected lifecycle result code {result}"
    if case["protocol"] == "pcp" and spec["version"] == 2:
        offset = spec["nonce_offset"]
        nonce = step_variables["nonce"]
        assert response[offset:offset + len(nonce)] == nonce, "lifecycle nonce mismatch"
    values = {field: capture_response(response, capture)
              for field, capture in spec["captures"].items()}
    assert_step_values(values, step.get("assert", {}), variables)
    if "state" in step:
        check_state_file(step["state"], case, spec, step_variables, lease)
    return values


def run_lifecycle(sock, address, case, lease=NO_LEASE):
    spec = dict(case["request"])
    spec.update(case["expect"])
    variables = {
        "internal_port": spec["internal_port_base"] + (os.getpid() % spec["port_range"]),
    }
    if case["protocol"] == "pcp":
        variables["client_ip"] = client_address(sock, address)
        variables["nonce"] = nonce_of(spec, length=spec.get("nonce_length", pcp_packet_encoding.NONCE_LENGTH))
    try:
        for step in spec["steps"]:
            run_lifecycle_step(sock, address, case, spec, step, variables, lease)
    finally:
        cleanup = spec.get("cleanup") or []
        run_cleanup(cleanup if isinstance(cleanup, list) else [cleanup],
                    lambda step: run_lifecycle_step(sock, address, case, spec, step, variables, lease))


def step_socket(sock, step, clients):
    """The socket a step sends from: `from: NAME` picks one of `clients` (another LAN client address of
    the runner, for example second-client), else the case's own socket."""
    name = step.get("from")
    if name is None:
        return sock
    if name not in clients:
        raise AssertionError(f"step sends from {name}, which this run does not have (--{name})")
    return clients[name]


@contextlib.contextmanager
def client_sockets(args):
    """{name: socket} of the extra LAN client addresses of the run (--second-client), bound to them."""
    sockets = {}
    try:
        second = getattr(args, "second_client", None) if args else None
        if second:
            sock = socket.socket(socket_family(args.family), socket.SOCK_DGRAM)
            sockets["second-client"] = sock
            sock.bind((second, 0))
            sock.settimeout(TIMEOUT)
        yield sockets
    finally:
        for sock in sockets.values():
            sock.close()


def run_protocol_step(sock, address, step, variables, peer_url=None, lease=NO_LEASE, clients=None):
    sock = step_socket(sock, step, clients or {})
    if "delay_seconds" in step:
        time.sleep(resolve_value(step["delay_seconds"], variables))
    if step.get("kind") in UPNP_STEP_KINDS:
        run_upnp_step(step, variables, lease)
        return
    if step.get("kind") == "traffic_probe":
        probe_lan_listener(sock, address, step, variables, peer_url)
        return
    if step.get("kind") == "lease_file":
        run_lease_file_step(step, variables, lease)
        return
    request = build_request(sock, address, resolve_request(step["request"], variables))
    sock.sendto(request, address)
    match_responses(sock, request, step["protocol"], list(step.get("responses", [step])), variables)
    if step.get("no_extra_responses"):
        extra = receive_within(sock)
        assert extra is None, f"unexpected extra response ({len(extra)} bytes)"


def run_protocol_sequence(sock, address, case, peer_url=None, lease=NO_LEASE, clients=None):
    """Execute an ordered PCP/NAT-PMP exchange described entirely in YAML."""
    sequence = case["request"]
    variables = {"case_name": case["name"], **case.get("variables", {})}
    try:
        for index, step in enumerate(sequence["steps"], 1):
            try:
                run_protocol_step(sock, address, step, variables, peer_url, lease, clients)
            except (AssertionError, OSError) as error:
                operation = step.get("kind", step.get("request", {}).get("kind", "exchange"))
                raise AssertionError(f"step {index} ({operation}): {error}") from error
    finally:
        run_cleanup(sequence.get("cleanup", []),
                    lambda step: run_protocol_step(sock, address, step, variables, peer_url, lease, clients))


def run_exchange_case(sock, address, case):
    """One request and one response (or silence), checked against the expect of the case."""
    request_spec = case["request"]
    expect = case["expect"]
    request = build_request(sock, address, request_spec)
    if expect["kind"] == "silence":
        expect_silence(sock, address, request)
        return

    response = exchange(sock, address, request)
    expected_length = (None if "min_length" in expect else
                       len(request) if expect["length"] == "request" else expect["length"])
    result = check_response_header(response, case, expect)
    assert result in expect["result"], f"unexpected result code {result}"
    if expected_length is None:
        assert len(response) >= expect["min_length"], f"expected at least {expect['min_length']} response bytes, got {len(response)}"
    else:
        assert len(response) == expected_length, f"expected {expected_length}-byte response, got {len(response)}"
    assert_response_echo(request, response, expect)
    for field in expect.get("fields", []):
        check_field(field["description"], capture_response(response, field), field, {})
    if expect.get("required_options"):
        check_required_options(response, expect)


# The daemon-restart case: the ANNOUNCE packets a cold start sends (RFC 6887 section 14.1.3)


def check_announce_retransmission(name, packets, expect):
    """RFC 6887 section 14.1.3 repeat rules for one interface's ANNOUNCE packets."""
    problems = []
    count = len(packets)
    if count < expect["min_count"] or count > expect["max_count"]:
        return [f"{name}: {count} ANNOUNCE packet(s), expected {expect['min_count']}-{expect['max_count']}"]
    times = [packet[5] for packet in packets]
    gaps_ms = [(later - earlier) * 1000 for earlier, later in zip(times, times[1:])]
    if gaps_ms and gaps_ms[0] < expect["min_first_gap_ms"]:
        problems.append(f"{name}: first gap {gaps_ms[0]:.0f} ms is below {expect['min_first_gap_ms']} ms")
    for index in range(1, len(gaps_ms)):
        if gaps_ms[index] < gaps_ms[index - 1] * expect["min_gap_ratio"]:
            problems.append(f"{name}: gap {index + 1} ({gaps_ms[index]:.0f} ms) does not grow from "
                            f"gap {index} ({gaps_ms[index - 1]:.0f} ms) by {expect['min_gap_ratio']}x")
    epochs = [struct.unpack("!I", packet[4][8:12])[0] for packet in packets]
    if any(later < earlier for earlier, later in zip(epochs, epochs[1:])):
        problems.append(f"{name}: Epoch Time decreased across repeats {epochs}")
    elapsed = int(times[-1] - times[0])
    if epochs[-1] - epochs[0] > elapsed + 1:
        problems.append(f"{name}: Epoch Time advanced {epochs[-1] - epochs[0]} s in {elapsed} s")
    return problems


def lan_announce_problems(directory, names, expect, family):
    """Every LAN capture has to hold the ANNOUNCE packets the expectation describes."""
    problems = []
    for name in names:
        interface = Path(name).stem
        packets = matching_udp_packets(os.path.join(directory, name), expect, family, True)
        if not packets:
            problems.append(f"no ANNOUNCE to {expect['destinations'][family]} on {interface}")
        elif "min_count" in expect:
            problems += check_announce_retransmission(interface, packets, expect)
    return problems


def wan_leak_problems(directory, names, expect, family):
    """No WAN capture may hold an ANNOUNCE to the multicast destination."""
    problems = []
    for name in names:
        leaked = matching_udp_packets(os.path.join(directory, name), expect, family, False)
        if leaked:
            problems.append(f"{len(leaked)} ANNOUNCE packet(s) to {expect['destinations'][family]} "
                            f"leaked on {Path(name).stem}")
    return problems


def run_daemon_restart(case, args):
    """Cold-start the daemon through the fixture and check the unsolicited traffic it records."""
    expect = case["expect"]
    if expect["kind"] != "unsolicited_announce":
        raise AssertionError("daemon_restart needs an unsolicited_announce expectation")
    if not args.fixture:
        raise AssertionError("daemon_restart requires --fixture")
    if args.capture_dir:
        directory = os.path.join(args.capture_dir, case_artifact_name(args, case))
        os.makedirs(directory, exist_ok=True)
        cleanup = None
    else:
        directory = cleanup = tempfile.mkdtemp(prefix="pcp-fixture-")
    try:
        # The fixture contract: restart the daemon from a cold start while recording its outgoing
        # packets, then leave lan-N.pcap and wan-N.pcap (one per interface) in DIRECTORY.
        result = subprocess.run(shlex.split(args.fixture) + ["daemon-restart", directory, args.family],
                                capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise AssertionError("fixture daemon-restart failed: " + (result.stderr or result.stdout).strip())
        lan = sorted(name for name in os.listdir(directory) if re.fullmatch(r"lan-\d+\.pcap", name))
        wan = sorted(name for name in os.listdir(directory) if re.fullmatch(r"wan-\d+\.pcap", name))
        if not lan or not wan:
            raise AssertionError("fixture produced no LAN or WAN capture")
        problems = []
        if expect["lan"] == "every":
            problems += lan_announce_problems(directory, lan, expect, args.family)
        if expect["wan"] == "none":
            problems += wan_leak_problems(directory, wan, expect, args.family)
        assert not problems, "; ".join(problems)
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


# The wan-renumber case: the Mapping Update a server sends after the external address changes
# (RFC 6887 section 14.2)


WAN_RENUMBER_WINDOW = 5.0       # seconds to collect unsolicited MAP responses after the change


def fixture_supports(args, capability):
    """Whether the fixture command of the run provides `capability` (`FIXTURE supports NAME` exits 0)."""
    if not getattr(args, "fixture", None):
        return False
    result = subprocess.run(shlex.split(args.fixture) + ["supports", capability],
                            capture_output=True, text=True, check=False)
    return result.returncode == 0


def run_fixture(args, *arguments):
    """Run one fixture command; returns its standard output, fails the case when it fails."""
    result = subprocess.run(shlex.split(args.fixture) + list(arguments), capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise AssertionError(f"fixture {arguments[0]} failed: " + (result.stderr or result.stdout).strip())
    return result.stdout


def receive_mapping_updates(sock, router, request, window, refresh_after_ms=None):
    """The MAP responses for the mapping of `request` that `router` sends on its own within `window`
    seconds, as [(seconds since the start, datagram)]. With refresh_after_ms the client refreshes the
    mapping that long after the first update; the reply to the refresh is not an update."""
    nonce = request[24:36]
    start = time.monotonic()
    deadline = start + window
    refresh_at = None
    awaiting_reply = False
    updates = []
    previous = sock.gettimeout()
    try:
        while True:
            now = time.monotonic()
            if refresh_at is not None and now >= refresh_at:
                sock.sendto(request, router)
                refresh_at, awaiting_reply = None, True
                continue
            wait = min(deadline, refresh_at) - now if refresh_at is not None else deadline - now
            if wait <= 0:
                return updates
            sock.settimeout(wait)
            try:
                data, source = sock.recvfrom(2048)
            except socket.timeout:
                continue
            if source[:2] != router[:2] or len(data) < pcp_packet_encoding.MAP_REQUEST_SIZE or data[1] != 0x81 \
                    or data[24:36] != nonce:
                continue
            if awaiting_reply:
                awaiting_reply = False
                continue
            updates.append((time.monotonic() - start, data))
            if refresh_after_ms is not None and len(updates) == 1:
                refresh_at = time.monotonic() + refresh_after_ms / 1000
    finally:
        sock.settimeout(previous)


def mapping_update_problems(updates, request, created, expect, source_port):
    """What is wrong with the Mapping Update packets `updates` ([(time, datagram)]) of the mapping that
    `request` created (`created`, its response), against the mapping_update expectation."""
    if not updates:
        return ["no Mapping Update (unsolicited MAP response) after the external address change"]
    problems = []
    count = len(updates)
    if "count" in expect and count != expect["count"]:
        problems.append(f"{count} Mapping Update packet(s), expected {expect['count']}")
    if "max_count" in expect and count > expect["max_count"]:
        problems.append(f"{count} Mapping Update packet(s), expected at most {expect['max_count']}")
    before = pcp_packet_encoding.parse_map_response(created)
    epochs = [struct.unpack("!I", created[8:12])[0]]
    for index, (_seconds, data) in enumerate(updates, 1):
        fields = pcp_packet_encoding.parse_map_response(data)
        label = f"update {index}"
        if source_port != expect.get("source_port", source_port):
            problems.append(f"{label} from port {source_port}")
        if fields["version"] != expect.get("version", 2):
            problems.append(f"{label} version {fields['version']}")
        if fields["result"] not in expect.get("result", [0]):
            problems.append(f"{label} result {pcp_packet_encoding.result_name('pcp', fields['result'])}")
        if expect.get("same_internal_port") and fields["internal_port"] != request[40:42]:
            problems.append(f"{label} has another internal port")
        if expect.get("external_address") == "changed" and fields["external_address"] == before["external_address"]:
            problems.append(f"{label} still has the old external address")
        try:
            options = pcp_packet_encoding.parse_options(data, pcp_packet_encoding.MAP_REQUEST_SIZE, "update option")
        except ValueError as error:
            problems.append(f"{label}: {error}")
            options = []
        for wanted in expect.get("options_present", []):
            if (wanted["code"], bytes.fromhex(wanted.get("data_hex", ""))) not in options:
                problems.append(f"{label} lacks option {wanted['code']}")
        for code in expect.get("options_absent", []):
            if any(found == code for found, _data in options):
                problems.append(f"{label} carries option {code}")
        epochs.append(struct.unpack("!I", data[8:12])[0])
    times = [seconds for seconds, _data in updates]
    gaps = [round((later - earlier) * 1000) for earlier, later in zip(times, times[1:])]
    if "min_first_gap_ms" in expect and gaps and gaps[0] < expect["min_first_gap_ms"]:
        problems.append(f"first gap {gaps[0]} ms, expected at least {expect['min_first_gap_ms']} ms")
    if "second_gap_ms" in expect and len(gaps) > 1 and gaps[1] < 0.9 * expect["second_gap_ms"]:
        problems.append(f"second gap {gaps[1]} ms, expected {expect['second_gap_ms']} ms")
    if expect.get("epoch_nondecreasing") and any(later < earlier for earlier, later in zip(epochs, epochs[1:])):
        problems.append(f"Epoch Time decreased: {epochs}")
    return problems


def run_wan_renumber(case, args):
    """Create a mapping on a fixture router, change its external address, and check the Mapping
    Update the router sends. Fixture contract: `wan-renumber-start DIRECTORY FAMILY` starts a router
    and prints its LAN address (last word of the output), `wan-renumber-change DIRECTORY` changes the
    external address, `wan-renumber-stop DIRECTORY` removes the router and leaves its logs and captures
    in DIRECTORY."""
    expect = case["expect"]
    spec = case["request"]
    if expect["kind"] != "mapping_update":
        raise AssertionError("wan_renumber needs a mapping_update expectation")
    if not fixture_supports(args, "wan-renumber"):
        raise AssertionError("wan_renumber requires a fixture with wan-renumber")
    if args.capture_dir:
        directory = os.path.join(args.capture_dir, case_artifact_name(args, case))
        os.makedirs(directory, exist_ok=True)
        cleanup = None
    else:
        directory = cleanup = tempfile.mkdtemp(prefix="pcp-fixture-")
    try:
        output = run_fixture(args, "wan-renumber-start", directory, args.family).split()
        try:
            if not output:
                raise AssertionError("fixture wan-renumber-start printed no router address")
            router = (output[-1], pcp_packet_encoding.PCP_PORT)
            with socket.socket(socket_family(args.family), socket.SOCK_DGRAM) as sock:
                sock.settimeout(TIMEOUT)
                request = build_request(sock, router, {**spec["mapping"], "kind": "pcp_map",
                                                       "options": spec.get("options", [])})
                created = exchange(sock, router, request)
                if len(created) < pcp_packet_encoding.MAP_REQUEST_SIZE or created[3] != 0:
                    name = pcp_packet_encoding.result_name("pcp", created[3]) if len(created) > 3 else "a short reply"
                    raise AssertionError(f"creating the mapping returned {name}")
                run_fixture(args, "wan-renumber-change", directory)
                updates = receive_mapping_updates(sock, router, request, WAN_RENUMBER_WINDOW,
                                                  spec.get("refresh_after_ms"))
            problems = mapping_update_problems(updates, request, created, expect, router[1])
            assert not problems, "; ".join(problems)
        finally:
            run_fixture(args, "wan-renumber-stop", directory)
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


# The pcp_bulk case: many PCP mappings from one client, with at most `window` requests in flight


BULK_RETRY_AFTER = 3.0          # RFC 6887 section 8.1.1 IRT: seconds before the first resend; doubles each time
BULK_TRIES = 4                  # sends of one request before it counts as lost (3 + 6 + 12 + 24 s)


def bulk_requests(sock, address, spec, lifetime):
    """The `count` requests of a pcp_bulk case for one pass: the template with the pass's lifetime,
    internal port first + index % ports, peer port first + index // ports, and the nonce
    nonce_prefix (8 octets) + index (4 octets)."""
    template = pcp_corpus_expander.expand_request(spec["template"])
    ports = spec["internal_port"]
    port_count = ports.get("count", spec["count"])
    prefix = bytes.fromhex(spec["nonce_prefix"])
    if len(prefix) != 8:
        raise ValueError("pcp_bulk nonce_prefix must be 8 octets")
    requests = []
    for index in range(spec["count"]):
        entry = {**template, "lifetime": lifetime, "internal_port": ports["first"] + index % port_count,
                 "nonce_hex": (prefix + struct.pack("!I", index)).hex()}
        if "peer_port" in spec:
            entry["peer_port"] = spec["peer_port"]["first"] + index // port_count
        requests.append(build_request(sock, address, entry))
    return requests


def send_windowed(sock, address, requests, window, retry_after=BULK_RETRY_AFTER, tries=BULK_TRIES):
    """Send `requests` (PCP requests with distinct nonces) with at most `window` of them unanswered at
    any time; a new one is sent only when an earlier one is answered or lost. A request unanswered for
    `retry_after` seconds is sent again, then after twice that time, and so on (RFC 6887 section 8.1.1,
    without the random factor), `tries` sends in all. Returns ({index: response}, [lost index])."""
    if window < 1:
        raise ValueError("pcp_bulk window must be at least 1")
    by_nonce = {request[24:36]: index for index, request in enumerate(requests)}
    responses, lost = {}, []
    pending = {}                # index -> (deadline, sends so far)
    next_index = 0
    previous = sock.gettimeout()
    try:
        while next_index < len(requests) or pending:
            while next_index < len(requests) and len(pending) < window:
                sock.sendto(requests[next_index], address)
                pending[next_index] = (time.monotonic() + retry_after, 1)
                next_index += 1
            wait = min(deadline for deadline, _sends in pending.values()) - time.monotonic()
            if wait > 0:
                sock.settimeout(wait)
                try:
                    data = sock.recvfrom(2048)[0]
                except socket.timeout:
                    data = None
                if data is not None:
                    index = by_nonce.get(data[24:36]) if len(data) >= 36 and data[1] & 0x80 else None
                    if index in pending:
                        responses[index] = data
                        del pending[index]
                    continue
            now = time.monotonic()
            for index, (deadline, sends) in list(pending.items()):
                if deadline > now:
                    continue
                if sends >= tries:
                    lost.append(index)
                    del pending[index]
                else:
                    sock.sendto(requests[index], address)
                    pending[index] = (now + retry_after * 2 ** sends, sends + 1)
    finally:
        sock.settimeout(previous)
    return responses, sorted(lost)


def run_bulk(sock, address, case):
    """Each pass of a pcp_bulk case (for example create, update, delete) sends all its requests through
    send_windowed and checks that every one is answered with an expected result; a pass with
    same_external_port also checks that each mapping keeps the external port of the pass before."""
    spec, expect = case["request"], case["expect"]
    wanted = expect.get("result", [0])
    problems = []
    previous_ports = {}
    for bulk_pass in spec["passes"]:
        name = bulk_pass["name"]
        requests = bulk_requests(sock, address, spec, bulk_pass["lifetime"])
        while receive_within(sock, 0.5) is not None:
            pass                # late replies of the pass before carry the same nonces
        started = time.monotonic()
        responses, lost = send_windowed(sock, address, requests, spec["window"],
                                        bulk_pass.get("retry_after", BULK_RETRY_AFTER),
                                        bulk_pass.get("tries", BULK_TRIES))
        elapsed = time.monotonic() - started
        refused = {}
        for index, response in responses.items():
            if len(response) < 4 or response[3] not in wanted:
                label = pcp_packet_encoding.result_name("pcp", response[3]) if len(response) >= 4 else "short reply"
                refused.setdefault(label, []).append(index)
        ports = {index: struct.unpack("!H", response[42:44])[0]
                 for index, response in responses.items() if len(response) >= 44}
        print(f"INFO {case['name']} {name}: {len(responses)} of {len(requests)} answered in {elapsed:.1f} s "
              f"(window {spec['window']}), {sum(map(len, refused.values()))} refused, {len(lost)} lost")
        if lost:
            problems.append(f"{name}: {len(lost)} request(s) without a response (first index {lost[0]})")
        for label, indexes in sorted(refused.items()):
            problems.append(f"{name}: {len(indexes)} answered {label} (first index {indexes[0]})")
        if bulk_pass.get("same_external_port"):
            moved = [index for index, port in ports.items()
                     if index in previous_ports and previous_ports[index] != port]
            if moved:
                problems.append(f"{name}: {len(moved)} mapping(s) changed external port (first index {moved[0]})")
        previous_ports = ports
    assert not problems, "; ".join(problems)


# The PCP authentication (PA) sequence case


def expect_no_auth_progress(sock, address, request, previous_response):
    """Reject a sequence error; an identical response is only a valid retransmission."""
    sock.sendto(request, address)
    response = receive_within(sock)
    if response is not None:
        assert response == previous_response, "invalid PA sequence advanced the authentication exchange"


def pa_identity_reply(session_id, eap_identifier, sequence_number, identity):
    """A PCP AUTHENTICATION request carrying an EAP Response/Identity for the PA session."""
    identity_bytes = identity.encode("utf-8")
    eap_length = 5 + len(identity_bytes)
    eap = struct.pack("!BBH", 2, eap_identifier, eap_length) + bytes((1,)) + identity_bytes
    message = bytes((2, 3, 0, 23)) + (b"\x00" * 4) + (b"\x00" * 16)
    message += struct.pack("!II", session_id, sequence_number)
    return message + pcp_option(7, eap)


def run_auth_sequence(sock, address, case):
    """Run a YAML-described PA session and sequence-number probes."""
    spec = case["request"]
    expectation = case["expect"]
    initiation = build_request(sock, address, spec["initiation"])
    response = exchange(sock, address, initiation)
    result, session_id, server_sequence, options = parse_auth_response(response)
    assert result == expectation["initiation_result"], f"unexpected PA-Initiation result {result}"
    assert session_id != 0, "server did not assign a PA session ID"
    assert server_sequence == expectation["initial_server_sequence"], \
        f"initial server sequence was {server_sequence}"
    eap_request = options.get(7)
    assert eap_request and len(eap_request) >= 5, "PA-Server response lacks an EAP request"
    assert eap_request[0] == 1 and eap_request[4] == 1, \
        "test profile requires an EAP Request/Identity from the server"

    followup = expectation["followup"]
    followup_request = pa_identity_reply(session_id, eap_request[1], followup["sequence_number"], followup["identity"])
    if followup["behavior"] == "discard":
        expect_no_auth_progress(sock, address, followup_request, response)
        previous_response = response
    else:
        followup_response = exchange(sock, address, followup_request)
        result, response_session, response_sequence, _ = parse_auth_response(followup_response)
        assert response_session == session_id, "PA response changed the session ID"
        assert result in followup["result_codes"], f"unexpected PA response result {result}"
        assert response_sequence == followup["response_sequence"], \
            f"server sequence was {response_sequence}, expected {followup['response_sequence']}"
        previous_response = followup_response

    replay = expectation.get("replay")
    if replay:
        replay_request = pa_identity_reply(session_id, eap_request[1], replay["sequence_number"], replay["identity"])
        expect_no_auth_progress(sock, address, replay_request, previous_response)


# One case of a corpus, by its kind


def run_case(sock, address, case, mutating=False, peer_url=None, args=None):
    request_spec = case["request"]
    expect = case["expect"]
    lease = LeaseSource.from_args(args) if args else NO_LEASE
    if request_spec["kind"] == "daemon_restart":
        run_daemon_restart(case, args)
        return
    if request_spec["kind"] == "wan_renumber":
        run_wan_renumber(case, args)
        return
    if request_spec["kind"] == "pcp_bulk":
        if not mutating:
            raise AssertionError("pcp_bulk requires --mutating")
        run_bulk(sock, address, case)
        return
    if request_spec["kind"] == "pcp_auth_sequence":
        run_auth_sequence(sock, address, case)
        return
    if request_spec["kind"] == "protocol_sequence":
        if "second-client" not in case.get("requires", []):
            run_protocol_sequence(sock, address, case, peer_url, lease)
            return
        with client_sockets(args) as clients:
            run_protocol_sequence(sock, address, case, peer_url, lease, clients)
        return
    if request_spec["kind"] == "lease_restart":
        # the driver restarts the daemon between the two phases
        phase = args.phase
        run_protocol_sequence(sock, address, {
            "name": case["name"],
            "request": {"steps": request_spec["phases"][phase],
                        "cleanup": request_spec.get("cleanup", []) if phase == "verify" else []}}, peer_url, lease)
        return
    if expect["kind"] == "lifecycle":
        if not mutating:
            raise AssertionError("mapping lifecycle requires --mutating")
        run_lifecycle(sock, address, case, lease)
        return

    run_exchange_case(sock, address, case)


# Running the cases of a run and reporting them: the same lines and outcomes for every runner


def case_label(case):
    return f"{case['protocol']}/{case['name']}"


def run_one_case(case, run, failures=(AssertionError, OSError)):
    """run(case) and print its PASS / XFAIL / FAIL line; a case with known_failure is an XFAIL when it
    fails. Returns (status, detail)."""
    label = case_label(case)
    try:
        run(case)
    except failures as error:
        if case.get("known_failure"):
            print(f"XFAIL {label}: {error} ({case['known_failure']})")
            return "XFAIL", f"{error}; expected: {case['known_failure']}"
        print(f"FAIL {label}: {error}", file=sys.stderr)
        return "FAIL", str(error)
    if case.get("known_failure"):
        print(f"PASS {label}: passes although it has a known_failure")
        return "PASS", "Known-failure case met its expected behavior."
    print(f"PASS {label}")
    return "PASS", ""


def run_on_socket(args, selected, run, around=None, failures=(AssertionError, OSError)):
    """Run the selected cases of a runner that sends to --host and --port: run(sock, address, case)."""
    address = (args.host, args.port)
    with socket.socket(socket_family(args.family), socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        return run_cases(selected, lambda case: run(sock, address, case),
                         skip=lambda case, outcomes: skip_reason(case, args, outcomes),
                         around=around, failures=failures)


def run_cases(cases, run, skip=None, around=None, failures=(AssertionError, OSError), timestamps=False):
    """Run the cases one after the other. Returns {(protocol, name): (status, detail)}.

    run(case) runs one; skip(case, outcomes) gives the reason not to run it, or None; around(case) is
    a context manager around each run (a packet capture); failures are the exceptions that fail a case
    (the others stop the run); timestamps print CASE START / CASE END lines (for the driver's logs)."""
    outcomes = {}
    for case in cases:
        key = (case["protocol"], case["name"])
        reason = skip(case, outcomes) if skip else None
        if reason:
            print(f"SKIP {case_label(case)}: {reason}")
            outcomes[key] = ("SKIP", reason)
            continue
        if timestamps:
            print(f"CASE START {datetime.now(timezone.utc).isoformat(timespec='milliseconds')} {case['name']}",
                  flush=True)
        try:
            with around(case) if around else contextlib.nullcontext():
                outcomes[key] = run_one_case(case, run, failures)
        finally:
            if timestamps:
                print(f"CASE END {datetime.now(timezone.utc).isoformat(timespec='milliseconds')} {case['name']}",
                      flush=True)
    return outcomes


def run_driver_suite(parser, load, write_report, self_test, select, validate, run, flag=None, empty_case_ok=False):
    """The main of a runner a driver runs case by case or family by family: parse, read the corpus, then
    the self-test, the report of a driver run, the list of cases or the cases. load(args) is the corpus;
    select(corpus, args) the cases; run(corpus, args, cases) their outcomes; flag(corpus) gives the third
    column of --list-cases. A CorpusError from them is a usage error. empty_case_ok: a runner the driver
    starts per family runs nothing for a --case of the other family."""
    args = parser.parse_args()
    corpus = load(args)
    if args.self_test:
        self_test(corpus)
        return 0
    if args.write_status:
        write_report(corpus, args.write_status, args)
        return 0
    try:
        cases = select(corpus, args)
        if args.list_cases:
            print_case_rows(cases, flag(corpus) if flag else None)
            return 0
        validate(corpus)
        if not cases and not (empty_case_ok and args.case):
            raise CorpusError("no matching cases")
        outcomes = run(corpus, args, cases)
    except CorpusError as error:
        parser.error(str(error))
    return print_summary(outcomes)


def print_summary(outcomes):
    """The Summary line of a run. Returns its exit status: 1 when a case failed."""
    counts = {status: sum(1 for outcome, _detail in outcomes.values() if outcome == status)
              for status in ("PASS", "FAIL", "XFAIL", "SKIP")}
    filtered = sum(1 for outcome, detail in outcomes.values() if is_filtered_skip(outcome, detail))
    print(f"Summary: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['XFAIL']} expected failures, "
          f"{counts['SKIP'] - filtered} skipped" + (f", {filtered} not in this run" if filtered else ""))
    return int(counts["FAIL"] != 0)


# An e2e corpus: sections of cases, each case run once per address family it lists


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


def case_protocol(case):
    """pcp, natpmp or upnp (joined with + when a case mixes them), from the requests of the case."""
    names = {str(request.get("protocol_family", "PCP")).lower().replace("-", "") for request in case_requests(case)}
    return "+".join(sorted(names))


def status_sections(corpus, protocol_of=None, describe=None):
    """The sections of the corpus as the shared status report (lib_test.write_status) takes them.
    protocol_of(case): the protocol column, by default case_protocol; describe(case): the description."""
    protocol_of = protocol_of or case_protocol
    describe = describe or (lambda case: case.get("description", ""))
    return [{"title": section["name"], "description": section.get("description", ""),
             "cases": [{"protocol": protocol_of(case), "name": case["name"], "families": case_families(case),
                        "description": describe(case)} for case in section["cases"]]}
            for section in corpus["sections"]]


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


def case_requests(case):
    """The requests of a case: `requests`, or the single `request`."""
    return case["requests"] if "requests" in case else [case["request"]]


def case_traffic(case):
    """Every traffic check of a case: before the requests, after them, and in the stages between."""
    expect = case.get("expect", {})
    traffic = list(case.get("before_traffic", []))
    traffic.extend(expect.get("traffic", []))
    traffic.extend(probe for stage in expect.get("traffic_stages", []) for probe in stage.get("traffic", []))
    return traffic


def validate_upnp_request(where, request, family):
    pinhole = request["action"] in UPNP_PINHOLE_ACTIONS
    if family != ("ipv6" if pinhole else "ipv4"):
        raise ValueError(f"{where}: UPnP {'pinholes are IPv6' if pinhole else 'port mappings are IPv4'}-only")
    if request.get("protocol") not in ("tcp", "udp"):
        raise ValueError(f"{where}: invalid UPnP protocol")
    if request["action"] == "DeletePortMappingRange":
        check_port(where, request, "start_port")
        check_port(where, request, "end_port")
    elif not pinhole:
        check_port(where, request, "external_port")
    if request["action"] in UPNP_ADD_ACTIONS or pinhole:
        check_port(where, request, "internal_port")
    for field in ("lease_duration", "lease_time", "wait_after"):
        check_count(where, request, field)


def validate_natpmp_request(where, request, family):
    if family != "ipv4":
        raise ValueError(f"{where}: NAT-PMP is IPv4-only")
    if request.get("opcode") == "PUBLIC_ADDRESS":
        return
    if request.get("opcode") not in ("UDP", "TCP"):
        raise ValueError(f"{where}: invalid NAT-PMP opcode")
    if request.get("protocol") != request["opcode"].lower():
        raise ValueError(f"{where}: NAT-PMP protocol/opcode mismatch")
    check_port(where, request, "private_port", 1)
    check_port(where, request, "public_port", 0)
    if type(request.get("lifetime")) is not int or request["lifetime"] < 0:
        raise ValueError(f"{where}: invalid lifetime")


def validate_pcp_request(where, request, family):
    if request.get("protocol_family", "PCP") != "PCP" or request.get("opcode", "MAP") not in ("MAP", "PEER") \
            or request.get("protocol") not in ("tcp", "udp"):
        raise ValueError(f"{where}: unsupported mapping protocol or opcode")
    check_port(where, request, "internal_port")
    check_port(where, request, "suggested_external_port", 0)
    suggested = request.get("suggested_external_address")
    if suggested and suggested not in ADDRESS_NAMES:
        try:
            ipaddress.ip_address(suggested)
        except ValueError:
            raise ValueError(f"{where}: suggested_external_address {suggested!r} is neither an address "
                             f"nor one of {', '.join(sorted(ADDRESS_NAMES))}") from None
    filters = request.get("filters", [request["filter"]] if request.get("filter") else [])
    for filt in filters:
        prefix = filt.get("prefix_length")
        limit = 32 if family == "ipv4" else 128
        if type(prefix) is not int or not 0 <= prefix <= limit:
            raise ValueError(f"{where}: invalid FILTER prefix")
        repeat = filt.get("repeat", 1)
        if type(repeat) is not int or repeat < 1:
            raise ValueError(f"{where}: invalid FILTER repeat count")
    unknown_options = request.get("unknown_optional_options", 0)
    if type(unknown_options) is not int or unknown_options < 0:
        raise ValueError(f"{where}: invalid optional option count")
    filter_count = sum(filt.get("repeat", 1) for filt in filters)
    size = pcp_packet_encoding.pcp_request_size(request.get("opcode") == "PEER", filter_count,
                                                bool(request.get("prefer_failure")), unknown_options)
    if size > pcp_packet_encoding.PCP_MAX_MESSAGE:
        raise ValueError(f"{where}: PCP request exceeds {pcp_packet_encoding.PCP_MAX_MESSAGE} octets")
    if request.get("opcode") == "PEER":
        if not request.get("remote_peer") or type(request.get("remote_peer_port")) is not int \
                or not 1 <= request["remote_peer_port"] <= 65535:
            raise ValueError(f"{where}: PEER requires remote peer address and port")


REQUEST_VALIDATORS = {"UPnP": validate_upnp_request, "NAT-PMP": validate_natpmp_request}


def validate_corpus(corpus):
    cases = flatten_cases(corpus)
    if not cases:
        raise ValueError("corpus must contain at least one case")
    names = [case.get("name") for case in cases]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise ValueError("case names must be present and unique")
    for case in cases:
        for family in case_families(case):
            where = f"{case['name']} ({family})"
            resolved = case_for_family(case, family)
            requests = resolved.get("requests", [resolved["request"]] if "request" in resolved else [])
            expected = resolved.get("expect", {}).get("results", [resolved.get("expect", {}).get("result")])
            if not requests or len(requests) != len(expected) or any(not code for code in expected):
                raise ValueError(f"{where}: request/result count mismatch")
            for request in requests:
                kind = request.get("protocol_family", "PCP")
                validator = REQUEST_VALIDATORS.get(kind) if isinstance(kind, str) else None
                (validator or validate_pcp_request)(where, request, family)
            for probe_spec in case_traffic(resolved):
                if probe_spec.get("protocol") not in ("tcp", "udp") or probe_spec.get("expect") not in (
                        "delivered", "blocked"):
                    raise ValueError(f"{where}: invalid traffic expectation")
    return len(cases)


# The e2e case: mapping requests (PCP, NAT-PMP, UPnP), then traffic through the router


UPNP_HTTP_PORT = 5000


UPNP_SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:1"


def upnp_soap_body(spec, client):
    """SOAP envelope for an AddPortMapping / DeletePortMapping request."""
    protocol = spec["protocol"].upper()
    arguments = [("NewRemoteHost", ""), ("NewExternalPort", spec["external_port"]),
                 ("NewProtocol", protocol)]
    if spec["action"] == "AddPortMapping":
        arguments += [("NewInternalPort", spec["internal_port"]), ("NewInternalClient", client),
                      ("NewEnabled", 1), ("NewPortMappingDescription", "pcp-e2e upnp"),
                      ("NewLeaseDuration", spec.get("lease_duration", 0))]
    inner = "".join(f"<{name}>{value}</{name}>" for name, value in arguments)
    return ('<?xml version="1.0"?>\r\n'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{spec["action"]} xmlns:u="{UPNP_SERVICE}">{inner}</u:{spec["action"]}>'
            '</s:Body></s:Envelope>\r\n')


UPNP_ADD_ACTIONS = ("AddPortMapping", "AddAnyPortMapping", "AddPinhole")
UPNP_PINHOLE_ACTIONS = ("AddPinhole", "UpdatePinhole", "DeletePinhole")
UPNP_PINHOLE_SERVICE = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1"


def upnp_action_args(spec, client, peer_addresses=None, unique_id=None):
    """The arguments of the e2e UPnP actions other than Add/DeletePortMapping (upnp_soap_body has those)."""
    peers = peer_addresses or {}
    remote = peers.get(spec.get("remote_host", ""), spec.get("remote_host", ""))
    protocol = spec.get("protocol", "udp").upper()
    if spec["action"] == "AddAnyPortMapping":
        return [("NewRemoteHost", remote), ("NewExternalPort", spec["external_port"]), ("NewProtocol", protocol),
                ("NewInternalPort", spec["internal_port"]), ("NewInternalClient", client),
                ("NewEnabled", spec.get("enabled", 1)), ("NewPortMappingDescription", "upnp-e2e"),
                ("NewLeaseDuration", spec.get("lease_duration", 0))]
    if spec["action"] == "DeletePortMappingRange":
        return [("NewStartPort", spec["start_port"]), ("NewEndPort", spec["end_port"]), ("NewProtocol", protocol),
                ("NewManage", spec.get("manage", 1))]
    if spec["action"] == "AddPinhole":
        return [("RemoteHost", remote), ("RemotePort", spec.get("remote_port", 0)), ("InternalClient", client),
                ("InternalPort", spec["internal_port"]), ("Protocol", {"UDP": 17, "TCP": 6}[protocol]),
                ("LeaseTime", spec.get("lease_time", 3600))]
    if spec["action"] == "UpdatePinhole":
        return [("UniqueID", unique_id), ("NewLeaseTime", spec.get("lease_time", 3600))]
    return [("UniqueID", unique_id)]


def upnp_request(router, client, spec, peer_addresses=None, unique_id=None):
    """UPnP IGD SOAP call: ("SUCCESS", external port, UniqueID or None) or ("UPNP_<errorCode>", 0, None)."""
    control = f"http://{host_literal(router)}:{UPNP_HTTP_PORT}"
    if spec["action"] in UPNP_PINHOLE_ACTIONS:
        service, control = spec.get("service", UPNP_PINHOLE_SERVICE), control + "/ctl/IP6FCtl"
    else:
        service, control = spec.get("service", UPNP_SERVICE), control + "/ctl/IPConn"
    if spec["action"] in ("AddPortMapping", "DeletePortMapping") and "remote_host" not in spec and "enabled" not in spec:
        body = upnp_soap_body(spec, client).replace(UPNP_SERVICE, service)
        status, result = soap_call(control, service, spec["action"], raw_body=body)
    elif spec["action"] in ("AddPortMapping", "DeletePortMapping"):
        peers = peer_addresses or {}
        arguments = [("NewRemoteHost", peers.get(spec.get("remote_host", ""), spec.get("remote_host", ""))),
                     ("NewExternalPort", spec["external_port"]), ("NewProtocol", spec["protocol"].upper())]
        if spec["action"] == "AddPortMapping":
            arguments += [("NewInternalPort", spec["internal_port"]), ("NewInternalClient", client),
                          ("NewEnabled", spec.get("enabled", 1)), ("NewPortMappingDescription", "pcp-e2e upnp"),
                          ("NewLeaseDuration", spec.get("lease_duration", 0))]
        status, result = soap_call(control, service, spec["action"], arguments)
    else:
        status, result = soap_call(control, service, spec["action"],
                                   upnp_action_args(spec, client, peer_addresses, unique_id))
    if status == 200:
        if spec["action"] == "AddAnyPortMapping":
            return "SUCCESS", int(result["NewReservedPort"]), None
        if spec["action"] == "AddPinhole":
            return "SUCCESS", spec["internal_port"], result["UniqueID"]
        return "SUCCESS", spec.get("external_port", spec.get("internal_port")), unique_id
    if status != 500 or not isinstance(result, SoapFault) or result.code is None:
        raise AssertionError(f"UPnP {spec['action']} failed with HTTP {status}")
    return f"UPNP_{result.code}", 0, None


v6_address = pcp_packet_encoding.ipv6_bytes


# Names a case may use for an address (remote_peer, FILTER, suggested_external_address); the driver
# passes their addresses in the plan of its fixture with --peer-address NAME=ADDRESS.
ADDRESS_NAMES = frozenset({"allowed-peer", "denied-peer", "third-peer",
                           "client",          # the LAN address of the runner (not the NAT66 ULA)
                           "router-wan",      # the WAN address of the router
                           "unowned-wan"})    # a WAN address the router does not own


E2E_EXTERNAL4, E2E_EXTERNAL6 = "198.51.100.1", "2001:db8:9000::1"


def load_yaml(path):
    """The parsed YAML file; only the code that reads a corpus needs PyYAML."""
    try:
        import yaml
    except ImportError as error:
        raise SystemExit("PyYAML is required (install python3-yaml)") from error
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def add_status_arguments(parser, directory, suite, platform="linux"):
    """The options of the status report, with status.md in `directory`."""
    parser.add_argument("--status-file", default=os.path.join(directory, "status.md"),
                        help="the combined Markdown report (default: status.md beside the runner)")
    parser.add_argument("--status-data-file",
                        help=f"the per-platform results behind the report (default: .tmp/tests/{suite}/status-data.json "
                             "in the repository)")
    parser.add_argument("--platform", default=platform, help="the column of the report this run fills")
    parser.add_argument("--run-info", action="append", default=[], metavar="KEY=VALUE",
                        help="what the run was, shown in the platform's line of the report")


def add_corpus_arguments(parser, corpus, list_help="print the cases of this run, then exit",
                         self_test_help="check the corpus and the report, no daemon needed"):
    """The options of a runner with a driver: its corpus, what it does without a daemon."""
    parser.add_argument("--cases", default=corpus)
    parser.add_argument("--self-test", action="store_true", help=self_test_help)
    parser.add_argument("--list-cases", action="store_true", help=list_help)
    parser.add_argument("--write-status", metavar="RESULTS", help="merge the results of a driver run and exit")


def add_target_arguments(parser, host_help="the address of the daemon"):
    """The options of a runner that sends to one address of the daemon."""
    parser.add_argument("--host", default="127.0.0.1", help=host_help)
    parser.add_argument("--port", type=int, default=5351, help="PCP / NAT-PMP UDP port (default: 5351)")
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    parser.add_argument("--case", action="append", help="run one named case; may be repeated")


def add_e2e_arguments(parser):
    """The options of a runner in the e2e fixture (e2e_start_runner passes them)."""
    parser.add_argument("--router", default="172.28.41.1")
    parser.add_argument("--client-address", default="172.28.41.2")
    parser.add_argument("--external-address", default=E2E_EXTERNAL4)
    parser.add_argument("--family", choices=("ipv4", "ipv6"), default="ipv4")
    parser.add_argument("--agent", action="append", default=[], metavar="NAME=URL")
    parser.add_argument("--peer-address", action="append", default=[], metavar="NAME=ADDRESS")
    parser.add_argument("--case", action="append")
    parser.add_argument("--router-call-dir",
                        help="the directory the driver watches: after each request it snapshots the daemon "
                             "(lib_test.router_call)")
    parser.add_argument("--route-through-router", action="store_true",
                        help="route the WAN subnet through the router (replies of the LAN echo service)")


def prepare_e2e_run(args):
    """What the cases of an e2e run need of the options; the agents {name: URL}. Routes the WAN subnet of
    the fixture (of any slot: the /24 or /64 of the router's external address) through the router."""
    if args.family == "ipv6" and args.external_address == E2E_EXTERNAL4:
        args.external_address = E2E_EXTERNAL6
    if args.route_through_router:
        wan = wan_network(args.external_address)
        subprocess.run(["ip"] + (["-6"] if wan.version == 6 else []) + ["route", "replace", str(wan),
                        "via", args.router], check=True)
    args.peer_addresses = key_value_pairs(args.peer_address)
    args.socket_family = socket_family(args.family)
    return key_value_pairs(args.agent)


def e2e_socket(args):
    """The PCP / NAT-PMP socket of an e2e run, on the client address."""
    sock = socket.socket(args.socket_family, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.bind((args.client_address, 0))
    return sock


ROUTER_CALL_TIMEOUT = 60


def router_call(directory, command, timeout=ROUTER_CALL_TIMEOUT):
    """The output of a driver command; the runner and the driver share `directory`
    (e2e_serve_router_calls in e2e_lib.sh)."""
    if not directory:
        raise AssertionError("this case needs the driver (--router-call-dir)")
    name = os.path.join(directory, f"{os.getpid()}-{time.monotonic_ns()}")
    with open(name + ".tmp", "w", encoding="utf-8") as request:
        request.write(command)
    os.rename(name + ".tmp", name + ".req")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(name + ".resp"):
            with open(name + ".resp", encoding="utf-8", errors="replace") as response:
                text = response.read()
            os.unlink(name + ".resp")
            return text
        time.sleep(0.05)
    raise AssertionError(f"the driver did not answer {command!r}")


def lose_firewall_rules(directory):
    """Remove the rules of the daemon behind its back, as a firewall reload does. The driver answers
    with the number of rules before and after, so a wipe which removed nothing fails the case."""
    answer = router_call(directory, "lose-rules")
    counts = answer.split()
    if len(counts) != 2 or not all(count.isdigit() for count in counts):
        raise AssertionError(f"lose-rules answered {answer!r}")
    if int(counts[0]) == 0 or int(counts[1]) != 0:
        raise AssertionError(f"lose-rules: {counts[0]} rules before, {counts[1]} after")


def wan_network(external_address):
    """The WAN subnet of a fixture: the /24 (IPv4) or /64 (IPv6) of the router's external address."""
    address = ipaddress.ip_address(external_address)
    return ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 64}", strict=False)


def suggested_address_of(spec, peer_addresses):
    """The suggested external address of a request, its name resolved; None without one."""
    value = spec.get("suggested_external_address")
    return peer_addresses.get(value, value) if value else None


def build_map_packet(client, spec, peer_addresses, nonce=None):
    nonce = nonce or os.urandom(pcp_packet_encoding.NONCE_LENGTH)
    suggested_address = suggested_address_of(spec, peer_addresses)
    opcode = pcp_packet_encoding.PCP_OPCODES[spec.get("opcode", "MAP")]
    peer = None
    if opcode == pcp_packet_encoding.PCP_OPCODES["PEER"]:
        peer = (spec["remote_peer_port"], peer_addresses.get(spec["remote_peer"], spec["remote_peer"]))
    packet = pcp_packet_encoding.pcp_mapping_request(
        2, opcode, spec["lifetime"], client, pcp_packet_encoding.PROTOCOLS[spec["protocol"].upper()],
        spec["internal_port"], spec["suggested_external_port"], nonce,
        v6_address(suggested_address) if suggested_address else None, peer)
    body = packet[24:60]
    filters = spec.get("filters")
    if filters is None:
        filters = [spec["filter"]] if spec.get("filter") else []
    for filt in filters:
        peer = peer_addresses.get(filt["remote_peer"], filt["remote_peer"])
        remote_port = filt.get("remote_port", 0)
        if remote_port == "any":
            remote_port = 0
        packet += (pcp_packet_encoding.pcp_filter_for_peer(filt["prefix_length"], remote_port, peer)
                   * filt.get("repeat", 1))
    if spec.get("prefer_failure"):
        packet += pcp_packet_encoding.pcp_option(pcp_packet_encoding.OPTIONS["PREFER_FAILURE"])
    packet += pcp_packet_encoding.pcp_option(pcp_packet_encoding.OPTION_UNKNOWN_OPTIONAL) * spec.get("unknown_optional_options", 0)
    if len(packet) > pcp_packet_encoding.PCP_MAX_MESSAGE:
        raise ValueError(f"PCP request exceeds {pcp_packet_encoding.PCP_MAX_MESSAGE}-octet limit ({len(packet)} octets)")
    return packet, nonce, body


def map_request(sock, router, client, spec, peer_addresses, nonce=None):
    packet, nonce, body = build_map_packet(client, spec, peer_addresses, nonce)
    response = exchange(sock, (router, pcp_packet_encoding.PCP_PORT), packet)
    opcode = {"MAP": 1, "PEER": 2}[spec.get("opcode", "MAP")]
    response_opcode = 0x80 | opcode
    minimum_length = (pcp_packet_encoding.PEER_REQUEST_SIZE if opcode == 2
                      else pcp_packet_encoding.MAP_REQUEST_SIZE)
    if len(response) < minimum_length or response[:2] != bytes((2, response_opcode)):
        raise AssertionError(f"malformed PCP {spec.get('opcode', 'MAP')} response ({len(response)} bytes)")
    fields = pcp_packet_encoding.parse_map_response(response)
    result = pcp_packet_encoding.result_name("pcp", fields["result"])
    if result == "SUCCESS":
        if fields["nonce"] != nonce:
            raise AssertionError("PCP response did not echo the MAP nonce")
        if fields["protocol"] != body[12] or fields["internal_port"] != body[16:18]:
            raise AssertionError("PCP response changed the mapped protocol or internal port")
        if ipaddress.ip_address(client).version == 6:
            expected_address = suggested_address_of(spec, peer_addresses) or client
            if fields["external_address"] != v6_address(expected_address):
                actual = socket.inet_ntop(socket.AF_INET6, fields["external_address"])
                raise AssertionError(f"PCP response external IPv6 address expected "
                                     f"{expected_address}, got {actual}")
        if opcode == 2:
            peer = peer_addresses.get(spec["remote_peer"], spec["remote_peer"])
            if fields["remote_port"] != struct.pack("!H", spec["remote_peer_port"]):
                raise AssertionError("PCP PEER response changed the remote peer port")
            if fields["remote_address"] != v6_address(peer):
                raise AssertionError("PCP PEER response changed the remote peer address")
            suggested_address = suggested_address_of(spec, peer_addresses)
            if suggested_address and fields["external_address"] != v6_address(suggested_address):
                raise AssertionError("PCP PEER response did not honor the suggested external address")
    return result, fields["external_port"], nonce


def natpmp_request(sock, router, spec):
    opcode = spec["opcode"]
    if opcode == "PUBLIC_ADDRESS":
        packet = bytes((0, 0))
        expected_opcode = 128
    else:
        protocol_opcode = {"udp": 1, "tcp": 2}[spec["protocol"]]
        packet = pcp_packet_encoding.natpmp_packet(protocol_opcode, spec["private_port"],
                                        spec["public_port"], spec["lifetime"])
        expected_opcode = 128 + protocol_opcode
    response = exchange(sock, (router, pcp_packet_encoding.PCP_PORT), packet)
    expected_length = 12 if opcode == "PUBLIC_ADDRESS" else 16
    if len(response) != expected_length or response[:2] != bytes((0, expected_opcode)):
        raise AssertionError(f"malformed NAT-PMP {opcode} response ({len(response)} bytes)")
    fields = pcp_packet_encoding.parse_natpmp_response(response)
    result = pcp_packet_encoding.result_name("natpmp", fields["result"])
    if result == "SUCCESS" and opcode == "PUBLIC_ADDRESS":
        return result, fields["address"], None
    if result == "SUCCESS":
        if fields["private_port"] != spec["private_port"]:
            raise AssertionError("NAT-PMP response changed the private port")
        if spec["lifetime"] and spec["public_port"] and fields["public_port"] != spec["public_port"]:
            raise AssertionError("NAT-PMP response changed the requested public port")
        return result, fields["public_port"], None
    return result, 0, None


def send_mapping_request(sock, router, client, spec, peer_addresses, nonce=None):
    if spec.get("protocol_family", "PCP") == "NAT-PMP":
        return natpmp_request(sock, router, spec)
    if spec.get("protocol_family") == "UPnP":
        return upnp_request(router, client, spec, peer_addresses, nonce)
    return map_request(sock, router, client, spec, peer_addresses, nonce)


PROBE_TIMEOUT = 1.0     # seconds a WAN agent waits for its probe to arrive


def probe(agent, host, port, transport, expect, source_port=None):
    probe_and_check(agent, transport, host, port, expect, source_port=source_port, timeout=PROBE_TIMEOUT)


PCP_ONLY_FIELDS = ("filter", "filters", "prefer_failure", "unknown_optional_options")


def cleanup_request(original, port=None):
    """The request that deletes the mapping `original` made (on external `port`), or None when nothing can."""
    family = original.get("protocol_family")
    if family == "UPnP" and original["action"] in UPNP_PINHOLE_ACTIONS:
        return dict(original, action="DeletePinhole")
    if family == "UPnP":
        return dict(original, action="DeletePortMapping", external_port=port or original["external_port"])
    if family == "NAT-PMP":
        return dict(original, public_port=0, lifetime=0)
    delete = dict(original, lifetime=0)
    for field in PCP_ONLY_FIELDS:
        delete.pop(field, None)
    return delete


class CaseRun:
    """One case on one address family: sends its requests, runs its traffic, removes its mappings."""

    def __init__(self, case, args, agents, pcp_sock):
        self.case = case
        self.args = args
        self.agents = agents
        self.pcp_sock = pcp_sock
        self.requests = case_requests(case)
        self.expected = case["expect"].get("results", [case["expect"].get("result", "SUCCESS")])
        self.active = {}        # (protocol, internal port) -> (request, external port, nonce)
        self.peer_flows = {}
        self.listeners = {}
        # A ULA client is masqueraded (NAT66); a GUA client is routed unchanged.
        ula = ipaddress.ip_address(args.client_address) in ipaddress.ip_network("fc00::/7")
        self.peer_external_address = (args.client_address if args.family == "ipv6" and not ula
                                      else args.external_address)

    def send(self, spec, nonce=None):
        return send_mapping_request(self.pcp_sock, self.args.router, self.args.client_address, spec,
                                    self.args.peer_addresses, nonce)

    def cleanup(self):
        """Delete every mapping, whatever happens to one of them; then report the ones that failed."""
        problems = []
        for (protocol, internal_port), (original, port, nonce) in self.active.items():
            delete = cleanup_request(original, port)
            if delete is None:
                continue
            label = f'{original.get("protocol_family", "PCP")} {protocol}/{internal_port}'
            try:
                result, _assigned, _ = self.send(delete, nonce)
            except (AssertionError, OSError) as error:
                result = error
            if result != "SUCCESS":
                problems.append(f"cleanup of {label} returned {result}")
        if problems:
            raise AssertionError("; ".join(problems))

    def open_peer_flow(self, traffic, spec):
        peer = self.args.peer_addresses.get(spec["remote_peer"], spec["remote_peer"])
        return PeerFlow(traffic["from"], peer, spec["remote_peer_port"], spec["protocol"],
                        self.args.client_address, spec["internal_port"])

    def run_peer_traffic(self, traffic):
        spec = next(request for request in self.requests
                    if request.get("opcode") == "PEER" and request["protocol"] == traffic["protocol"])
        key = (spec["protocol"], spec["internal_port"])
        if traffic["mode"] == "peer-implicit":
            flow = self.open_peer_flow(traffic, spec)
            self.peer_flows[key] = (flow, flow.exchange())
        elif traffic["mode"] == "peer-existing":
            flow, observed = self.peer_flows[key]
            flow.check_mapping(self.peer_external_address, self.active[key][1], observed)
        else:
            flow = self.open_peer_flow(traffic, spec)
            try:
                flow.check_mapping(self.peer_external_address, self.active[key][1], flow.exchange())
            finally:
                flow.close()

    def run_probe(self, traffic):
        service_port = traffic.get("service_port")
        if service_port is None:
            service_port = self.requests[0].get("internal_port")
        if service_port is None:
            service_port = next(iter(self.active.values()))[0]["internal_port"]
        external_port = traffic.get("external_port")
        if external_port is None:
            mapping = self.active.get((traffic["protocol"], service_port))
            external_port = mapping[1] if mapping else self.requests[0]["suggested_external_port"]
        # listen: true on a blocked probe, or it passes even when the router forwards (nothing to reach)
        if traffic["expect"] == "delivered" or traffic.get("listen"):
            key = (traffic["protocol"], service_port)
            if key not in self.listeners:
                self.listeners[key] = LanEcho(self.args.socket_family, self.args.client_address,
                                              service_port, traffic["protocol"])
        time.sleep(0.1)
        probe_host = (self.args.external_address if self.args.family == "ipv4"
                      else self.args.client_address)
        probe(self.agents[traffic["from"]], probe_host, external_port,
              traffic["protocol"], traffic["expect"], traffic.get("source_port"))

    def run_traffic(self, traffic_items):
        for traffic in traffic_items:
            if traffic.get("mode") in ("peer", "peer-implicit", "peer-existing"):
                self.run_peer_traffic(traffic)
            else:
                self.run_probe(traffic)

    def run_request(self, request_index, spec, wanted):
        protocol = spec.get("protocol", "address")
        internal_port = spec.get("internal_port", spec.get("private_port", request_index))
        key = (protocol, internal_port)
        prior = self.active.get(key)
        result, port, nonce = self.send(spec, prior[2] if prior else None)
        if self.args.router_call_dir:
            router_call(self.args.router_call_dir, f"snapshot:{request_index}")
        if result != wanted:
            raise AssertionError(f"{spec.get('protocol_family', 'PCP')} response expected {wanted}, got {result}")
        if (result == "SUCCESS" and spec.get("opcode") == "PUBLIC_ADDRESS"
                and port != self.args.external_address):
            raise AssertionError(f"NAT-PMP public address expected {self.args.external_address}, got {port}")
        if result == "SUCCESS" and (spec.get("lifetime", 0) or spec.get("action") in UPNP_ADD_ACTIONS):
            self.active[key] = (spec, port, nonce)
        elif result == "SUCCESS" and spec.get("action") == "DeletePortMappingRange":
            for other in [other for other, (added, assigned, _id) in self.active.items()
                          if added.get("action") in ("AddPortMapping", "AddAnyPortMapping")
                          and other[0] == protocol and spec["start_port"] <= assigned <= spec["end_port"]]:
                self.active.pop(other)
        elif result == "SUCCESS" and spec.get("action") != "UpdatePinhole":
            self.active.pop(key, None)
        for stage in self.case["expect"].get("traffic_stages", []):
            if stage["after_request"] == request_index:
                self.run_traffic(stage.get("traffic", []))
                if stage.get("lose_rules"):
                    lose_firewall_rules(self.args.router_call_dir)
        if spec.get("wait_after"):
            time.sleep(spec["wait_after"])
            if 0 < spec.get("lease_duration", spec.get("lease_time", 0)) <= spec["wait_after"]:
                self.active.pop(key, None)      # the lease expired by itself

    def close(self):
        for listener in self.listeners.values():
            listener.close()
        for flow, _observed in self.peer_flows.values():
            flow.close()

    def run(self):
        if len(self.requests) != len(self.expected):
            raise AssertionError("requests/results lengths differ")
        failed = True
        try:
            self.run_traffic(self.case.get("before_traffic", []))
            for request_index, (spec, wanted) in enumerate(zip(self.requests, self.expected), 1):
                self.run_request(request_index, spec, wanted)
            self.run_traffic(self.case["expect"].get("traffic", []))
            failed = False
        finally:
            self.close()
            try:
                self.cleanup()
            except AssertionError:
                if not failed:      # else it would replace the failure of the case
                    raise


# The UPnP IGD client: SSDP, HTTP, the description and SCPD documents, SOAP control and GENA eventing
# (UPnP Device Architecture 1.1 §1-§4), and the UPnP steps of a corpus (kind: ssdp, ssdp-listen, http,
# soap, subscribe, notify-wait, restart, upnp-lease). None of it needs a daemon; the unit tests run it
# against loopback servers.


SSDP_PORT = 1900
SSDP_GROUPS = {"ipv4": "239.255.255.250", "ipv6": "ff02::c"}
SOAP_ENVELOPE_NS = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP_ENCODING = "http://schemas.xmlsoap.org/soap/encoding/"
UPNP_CONTROL_NS = "urn:schemas-upnp-org:control-1-0"
UPNP_DEVICE_NS = "urn:schemas-upnp-org:device-1-0"
UPNP_SERVICE_NS = "urn:schemas-upnp-org:service-1-0"
UPNP_EVENT_NS = "urn:schemas-upnp-org:event-1-0"
SoapFault = collections.namedtuple("SoapFault", "code description")


def host_literal(address):
    """An address as the host part of a URL or a HOST header ([...] for IPv6)."""
    return f"[{address}]" if ":" in str(address) else str(address)


def url_parts(url):
    """(host, port, path with query) of an http URL."""
    parts = urllib.parse.urlsplit(url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return parts.hostname, parts.port or 80, path


# SSDP (UDA-1.1 §1)


def ssdp_host(family):
    return f"{host_literal(SSDP_GROUPS[family])}:{SSDP_PORT}"


def parse_ssdp(datagram):
    """(start line, {header name in lower case: value}) of an SSDP message; ValueError when it is not one."""
    text = datagram.decode("utf-8", "replace")
    head = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0]
    lines = re.split(r"\r?\n", head)
    if not lines or not lines[0].strip():
        raise ValueError("empty SSDP message")
    headers = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        name, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"malformed SSDP header line {line!r}")
        headers[name.strip().lower()] = value.strip()
    return lines[0].strip(), headers


def msearch_message(st, mx=1, man='"ssdp:discover"', host=None, family="ipv4", extra_headers=()):
    """An M-SEARCH request; None for st, mx, man or host leaves that header out (host=None: the group)."""
    lines = ["M-SEARCH * HTTP/1.1", f"HOST: {host or ssdp_host(family)}"]
    if host is False:
        lines.pop()
    if man is not None:
        lines.append(f"MAN: {man}")
    if mx is not None:
        lines.append(f"MX: {mx}")
    if st is not None:
        lines.append(f"ST: {st}")
    lines.extend(f"{name}: {value}" for name, value in extra_headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def msearch_wait(mx):
    """How long to collect responses: MX (at most 5, UDA-1.1 §1.3.3) plus one second; 1 s without a number."""
    try:
        return min(max(int(mx), 0), 5) + 1
    except (TypeError, ValueError):
        return 1


def receive_ssdp(sock, seconds, accept=None):
    """The SSDP messages received within `seconds`: [{start, headers, source}] (accept filters them)."""
    deadline = time.monotonic() + seconds
    messages = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return messages
        readable, _, _ = select.select([sock], [], [], remaining)
        if not readable:
            return messages
        data, source = sock.recvfrom(65535)
        try:
            start, headers = parse_ssdp(data)
        except ValueError:
            continue
        if accept is None or accept(start, headers):
            messages.append({"start": start, "headers": headers, "source": source[0]})


def ssdp_msearch(sock, target, st, mx=1, extra_headers=(), man='"ssdp:discover"', host=None, raw=None, wait=None):
    """Send an M-SEARCH to `target` and return the responses received within MX+1 s (msearch_wait)."""
    family = "ipv6" if sock.family == socket.AF_INET6 else "ipv4"
    message = raw if raw is not None else msearch_message(st, mx, man, host, family, extra_headers)
    sock.sendto(message.encode() if isinstance(message, str) else message, target)
    return receive_ssdp(sock, msearch_wait(mx) if wait is None else wait,
                        lambda start, _headers: start.upper().startswith("HTTP/"))


def ssdp_notify_listener(iface_addr, family="ipv4", ifindex=0):
    """A UDP socket on port 1900 that has joined the SSDP group (239.255.255.250 or ff02::c) on the
    interface of iface_addr (IPv4) or ifindex (IPv6), for the NOTIFY messages of the daemon."""
    sock = socket.socket(socket_family(family), socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if family == "ipv4":
        sock.bind(("", SSDP_PORT))
        membership = socket.inet_aton(SSDP_GROUPS["ipv4"]) + socket.inet_aton(iface_addr)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    else:
        sock.bind(("::", SSDP_PORT))
        membership = socket.inet_pton(socket.AF_INET6, SSDP_GROUPS["ipv6"]) + struct.pack("@I", ifindex)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)
    return sock


# HTTP (UDA-1.1 §2.1, RFC 9112)


def read_http_response(reader, head_only=False):
    """One response from a binary file object: {version, status, reason, headers, body}, None at EOF."""
    status_line = reader.readline(65537)
    if not status_line:
        return None
    parts = status_line.decode("iso-8859-1").rstrip("\r\n").split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise AssertionError(f"malformed HTTP status line {status_line[:80]!r}")
    headers = {}
    while True:
        line = reader.readline(65537)
        if line in (b"\r\n", b"\n", b""):
            break
        name, _, value = line.decode("iso-8859-1").partition(":")
        headers[name.strip().lower()] = value.strip()
    status = int(parts[1])
    body = b""
    if head_only or status in (204, 304) or 100 <= status < 200:
        pass
    elif "chunked" in headers.get("transfer-encoding", "").lower():
        while True:
            size = int(reader.readline(1024).split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while reader.readline(1024) not in (b"\r\n", b"\n", b""):
                    pass
                break
            body += reader.read(size)
            reader.readline(1024)
    elif "content-length" in headers:
        body = reader.read(int(headers["content-length"]))
    else:
        body = reader.read()
    return {"version": parts[0], "status": status, "reason": parts[2] if len(parts) > 2 else "",
            "headers": headers, "body": body}


def http_exchange(host, port, data, count=1, timeout=5, family=None):
    """Send exact bytes on one TCP connection and read up to `count` responses. Returns (responses,
    closed): closed when the server closed the connection before (or right after) the last one."""
    address_family = family or (socket.AF_INET6 if ":" in host else socket.AF_INET)
    responses = []
    closed = False
    with socket.socket(address_family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        if data:
            sock.sendall(data)
        reader = sock.makefile("rb")
        try:
            for _ in range(count):
                response = read_http_response(reader)
                if response is None:
                    closed = True
                    break
                responses.append(response)
        except (socket.timeout, ConnectionResetError):
            closed = not responses or closed
        finally:
            reader.close()
    return responses, closed


def http_raw(host, port, data, timeout=5):
    """The first response to exact bytes (malformed requests): (status, headers, body), status None when
    the server closed the connection without answering."""
    responses, _closed = http_exchange(host, port, data, 1, timeout)
    if not responses:
        return None, {}, b""
    return responses[0]["status"], responses[0]["headers"], responses[0]["body"]


def http_request(url, method="GET", body=None, headers=None, timeout=5):
    """A well-formed request with http.client: (status, {lower-case header: value}, body)."""
    host, port, path = url_parts(url)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        return response.status, {name.lower(): value for name, value in response.getheaders()}, response.read()
    finally:
        connection.close()


# The description and SCPD documents (UDA-1.1 §2.3, §2.5)


def xml_text(element, path, namespaces):
    found = element.find(path, namespaces)
    return found.text.strip() if found is not None and found.text else None


def parse_description(body, location):
    """The device description: {spec_version, udn, udns, device_types, services: [{type, id, scpd, control,
    event}] (absolute URLs), device (the tree: type, udn, friendly_name, services, devices)}."""
    root = ET.fromstring(body)
    ns = {"d": UPNP_DEVICE_NS}
    if root.tag != f"{{{UPNP_DEVICE_NS}}}root":
        raise AssertionError(f"description root element is {root.tag}")
    base = xml_text(root, "d:URLBase", ns) or location
    services, device_types, udns = [], [], []

    def device(element):
        tree = {"type": xml_text(element, "d:deviceType", ns), "udn": xml_text(element, "d:UDN", ns),
                "friendly_name": xml_text(element, "d:friendlyName", ns), "services": [], "devices": []}
        device_types.append(tree["type"])
        udns.append(tree["udn"])
        for service in element.findall("d:serviceList/d:service", ns):
            entry = {"type": xml_text(service, "d:serviceType", ns), "id": xml_text(service, "d:serviceId", ns)}
            for key, tag in (("scpd", "SCPDURL"), ("control", "controlURL"), ("event", "eventSubURL")):
                value = xml_text(service, f"d:{tag}", ns)
                entry[key] = urllib.parse.urljoin(base, value) if value else None
            tree["services"].append(entry)
            services.append(entry)
        for child in element.findall("d:deviceList/d:device", ns):
            tree["devices"].append(device(child))
        return tree

    top = root.find("d:device", ns)
    if top is None:
        raise AssertionError("description has no root device")
    tree = device(top)
    major, minor = xml_text(root, "d:specVersion/d:major", ns), xml_text(root, "d:specVersion/d:minor", ns)
    return {"spec_version": f"{major}.{minor}", "udn": tree["udn"], "udns": udns, "device_types": device_types,
            "services": services, "device": tree}


def fetch_description(location, timeout=5):
    status, _headers, body = http_request(location, timeout=timeout)
    if status != 200:
        raise AssertionError(f"GET {location} returned HTTP {status}")
    return parse_description(body, location)


def parse_scpd(body):
    """A service description: {spec_version, actions: {name: [{name, direction, variable}]}, variables:
    {name: {type, evented}}}."""
    root = ET.fromstring(body)
    ns = {"s": UPNP_SERVICE_NS}
    if root.tag != f"{{{UPNP_SERVICE_NS}}}scpd":
        raise AssertionError(f"SCPD root element is {root.tag}")
    actions = {}
    for action in root.findall("s:actionList/s:action", ns):
        actions[xml_text(action, "s:name", ns)] = [
            {"name": xml_text(argument, "s:name", ns), "direction": xml_text(argument, "s:direction", ns),
             "variable": xml_text(argument, "s:relatedStateVariable", ns)}
            for argument in action.findall("s:argumentList/s:argument", ns)]
    variables = {}
    for variable in root.findall("s:serviceStateTable/s:stateVariable", ns):
        variables[xml_text(variable, "s:name", ns)] = {
            "type": xml_text(variable, "s:dataType", ns), "evented": variable.get("sendEvents", "yes") == "yes"}
    major, minor = xml_text(root, "s:specVersion/s:major", ns), xml_text(root, "s:specVersion/s:minor", ns)
    return {"spec_version": f"{major}.{minor}", "actions": actions, "variables": variables}


def fetch_scpd(url, timeout=5):
    status, _headers, body = http_request(url, timeout=timeout)
    if status != 200:
        raise AssertionError(f"GET {url} returned HTTP {status}")
    return parse_scpd(body)


# SOAP control (UDA-1.1 §3)


def xml_escape(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def soap_envelope(service_type, action, args=()):
    """The SOAP request of an action; args are (name, value) pairs (or a dict), in their order."""
    pairs = args.items() if isinstance(args, dict) else args
    inner = "".join(f"<{name}>{xml_escape(value)}</{name}>" for name, value in pairs)
    return ('<?xml version="1.0"?>\r\n'
            f'<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}" s:encodingStyle="{SOAP_ENCODING}"><s:Body>'
            f'<u:{action} xmlns:u="{service_type}">{inner}</u:{action}>'
            '</s:Body></s:Envelope>\r\n')


def parse_soap_response(body):
    """A SoapFault, the out arguments of a response ({"name": value}, the response element in
    "_element"), or None when the body is not a SOAP envelope."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    soap_body = root.find(f"{{{SOAP_ENVELOPE_NS}}}Body")
    if root.tag != f"{{{SOAP_ENVELOPE_NS}}}Envelope" or soap_body is None or len(soap_body) == 0:
        return None
    first = soap_body[0]
    if first.tag == f"{{{SOAP_ENVELOPE_NS}}}Fault":
        error = first.find(f".//{{{UPNP_CONTROL_NS}}}UPnPError")
        if error is None:
            return SoapFault(None, xml_text(first, "faultstring", {}))
        code = xml_text(error, f"{{{UPNP_CONTROL_NS}}}errorCode", {})
        return SoapFault(int(code) if code and code.isdigit() else code,
                         xml_text(error, f"{{{UPNP_CONTROL_NS}}}errorDescription", {}))
    out = {"_element": first.tag.rsplit("}", 1)[-1]}
    for child in first:
        out[child.tag.rsplit("}", 1)[-1]] = (child.text or "") if len(child) == 0 else ET.tostring(child, "unicode")
    return out


def soap_call(control_url, service_type, action, args=(), soapaction=None, raw_body=None, headers=None, timeout=5):
    """POST an action to a control URL. Returns (HTTP status, result): result is a SoapFault, the out
    arguments (parse_soap_response), or None. soapaction overrides the SOAPAction header (False leaves it
    out); raw_body replaces the envelope."""
    body = raw_body if raw_body is not None else soap_envelope(service_type, action, args)
    request_headers = {"Content-Type": 'text/xml; charset="utf-8"'}
    if soapaction is not False:
        request_headers["SOAPAction"] = soapaction if soapaction is not None else f'"{service_type}#{action}"'
    request_headers.update(headers or {})
    status, _response_headers, response_body = http_request(
        control_url, "POST", body.encode() if isinstance(body, str) else body, request_headers, timeout)
    return status, parse_soap_response(response_body)


# GENA eventing (UDA-1.1 §4)


def gena_request(event_url, method, headers, timeout=5):
    """One SUBSCRIBE / UNSUBSCRIBE: (status, SID, TIMEOUT header)."""
    host, port, path = url_parts(event_url)
    lines = [f"{method} {path} HTTP/1.1", f"HOST: {host_literal(host)}:{port}"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    responses, _closed = http_exchange(host, port, ("\r\n".join(lines) + "\r\n\r\n").encode(), 1, timeout)
    if not responses:
        return None, None, None
    response = responses[0]
    return response["status"], response["headers"].get("sid"), response["headers"].get("timeout")


def gena_subscribe(event_url, callback, timeout="Second-1800"):
    headers = [("CALLBACK", f"<{callback}>"), ("NT", "upnp:event")]
    if timeout:
        headers.append(("TIMEOUT", timeout))
    return gena_request(event_url, "SUBSCRIBE", headers)


def gena_renew(event_url, sid, timeout="Second-1800"):
    return gena_request(event_url, "SUBSCRIBE", [("SID", sid)] + ([("TIMEOUT", timeout)] if timeout else []))


def gena_unsubscribe(event_url, sid):
    return gena_request(event_url, "UNSUBSCRIBE", [("SID", sid)])


def parse_propertyset(body):
    """{variable: value} of a GENA propertyset."""
    root = ET.fromstring(body)
    values = {}
    for prop in root.findall(f"{{{UPNP_EVENT_NS}}}property"):
        for child in prop:
            values[child.tag.rsplit("}", 1)[-1]] = child.text or ""
    return values


class EventListener:
    """An HTTP server on the client address that collects the NOTIFY messages of GENA subscriptions:
    [{sid, seq, nt, nts, properties}] in `events`."""

    def __init__(self, address, port=0):
        self.events = []
        self.condition = threading.Condition()
        listener = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_NOTIFY(self):  # noqa: N802 (the HTTP method)
                body = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
                try:
                    properties = parse_propertyset(body)
                except ET.ParseError:
                    properties = None
                seq = self.headers.get("SEQ")
                event = {"sid": self.headers.get("SID"), "seq": int(seq) if seq and seq.isdigit() else seq,
                         "nt": self.headers.get("NT"), "nts": self.headers.get("NTS"), "properties": properties}
                with listener.condition:
                    listener.events.append(event)
                    listener.condition.notify_all()
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        server_class = type("Server", (http.server.ThreadingHTTPServer,),
                            {"address_family": socket.AF_INET6 if ":" in address else socket.AF_INET})
        self.server = server_class((address, port), Handler)
        self.address = address
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://{host_literal(self.address)}:{self.port}/"

    def wait(self, sid=None, seq=None, timeout=5, after=0):
        """The first event (from index `after`) of the SID (and SEQ); None when none came within timeout."""
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                for event in self.events[after:]:
                    if (sid is None or event["sid"] == sid) and (seq is None or event["seq"] == seq):
                        return event
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self.condition.wait(remaining)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# The UPnP steps of a corpus. A step runs one exchange, and its `expect` checks the values the exchange
# produced (check_upnp_values: the rules of check_field, plus matches, contains, not_contains, one_of and
# present). The context of a run comes in the variables: router (the address of the daemon's LAN side),
# client, family, ifindex, http_port, and _resources (a list the runner closes after the case).


UPNP_STEP_KINDS = {"ssdp", "ssdp-listen", "http", "soap", "subscribe", "notify-wait", "restart", "upnp-lease"}


def check_upnp_values(values, checks, variables):
    """The expect of a UPnP step: {field: rules}; a field is a key of `values`. "$name" values (also in
    lists) are the variables."""
    for field, rules in checks.items():
        if not isinstance(rules, dict):
            rules = {"equals": rules}
        rules = resolve_request(rules, variables)
        actual = values.get(field)
        if "present" in rules:
            assert (actual is not None) == rules["present"], (
                f"{field} is {'missing' if rules['present'] else 'present: ' + repr(actual)}")
            if actual is None:
                continue
        if "matches" in rules:
            assert actual is not None and re.search(rules["matches"], str(actual)), (
                f"{field} {actual!r} does not match {rules['matches']!r}")
        for item in ensure_list(rules.get("contains", [])):
            item = resolve_value(item, variables)
            assert actual is not None and item in actual, f"{field} {actual!r} does not contain {item!r}"
        for item in ensure_list(rules.get("not_contains", [])):
            item = resolve_value(item, variables)
            assert actual is None or item not in actual, f"{field} {actual!r} contains {item!r}"
        if "one_of" in rules:
            assert actual in [resolve_value(item, variables) for item in rules["one_of"]], (
                f"{field} was {actual!r}, expected one of {rules['one_of']!r}")
        rest = {key: value for key, value in rules.items()
                if key not in ("present", "matches", "contains", "not_contains", "one_of")}
        if rest:
            check_field(field, actual, rest, variables)


def ensure_list(value):
    return value if isinstance(value, list) else [value]


def upnp_base_url(variables):
    return f"http://{host_literal(variables['router'])}:{variables.get('http_port', UPNP_HTTP_PORT)}"


def upnp_url(variables, path):
    path = resolve_value(path, variables)
    return path if str(path).startswith("http") else upnp_base_url(variables) + path


def ssdp_values(messages):
    values = {"count": len(messages), "sts": sorted({m["headers"].get("st", "") for m in messages}),
              "nts": sorted({m["headers"].get("nt", "") for m in messages}),
              "ntss": sorted({m["headers"].get("nts", "") for m in messages}),
              "usns": sorted({m["headers"].get("usn", "") for m in messages}),
              "locations": sorted({m["headers"].get("location", "") for m in messages}),
              "sources": sorted({m["source"] for m in messages})}
    if messages:
        values["start"] = messages[0]["start"]
        values.update({f"header.{name}": value for name, value in messages[0]["headers"].items()})
    return values


def check_each(messages, rules, variables):
    """`each`: the rules every message (its headers by lower-case name, and start) has to meet."""
    for index, message in enumerate(messages):
        values = dict({f"header.{name}": value for name, value in message["headers"].items()},
                      start=message["start"])
        try:
            check_upnp_values(values, rules, variables)
        except AssertionError as error:
            raise AssertionError(f"message {index + 1} ({message['headers'].get('st') or message['headers'].get('nt')}):"
                                 f" {error}") from error


def run_ssdp_step(step, variables):
    """An M-SEARCH: multicast to the group (target: multicast, the default) or unicast to the router."""
    family = variables["family"]
    request = resolve_request({key: value for key, value in step.items() if key not in ("expect", "each")},
                              variables)
    with socket.socket(socket_family(family), socket.SOCK_DGRAM) as sock:
        sock.bind((variables["client"], 0))
        if request.get("target", "multicast") == "multicast":
            if family == "ipv4":
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(variables["client"]))
                target = (SSDP_GROUPS["ipv4"], SSDP_PORT)
            else:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 2)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, variables.get("ifindex", 0))
                target = (SSDP_GROUPS["ipv6"], SSDP_PORT, 0, variables.get("ifindex", 0))
        else:
            target = (variables["router"], SSDP_PORT)
        host = request.get("host")
        if host is None and request.get("target") == "unicast":
            host = f"{host_literal(variables['router'])}:{SSDP_PORT}"
        messages = ssdp_msearch(sock, target, request.get("st"), request.get("mx", 1),
                                [tuple(item) for item in request.get("headers", [])],
                                request.get("man", '"ssdp:discover"'), host, request.get("raw"), request.get("wait"))
    check_each(messages, step.get("each", {}), variables)
    return ssdp_values(messages)


def run_restart(variables, timeout=120):
    """Have the driver restart the daemon (its router_call command restart answers "restarted")."""
    answer = router_call(variables.get("router_call_dir"), "restart", timeout)
    if "restarted" not in answer:
        raise AssertionError(f"the driver did not restart the daemon: {answer}")


def run_ssdp_listen_step(step, variables):
    """The NOTIFY messages of the daemon on the group within `seconds` (with restart: around a daemon restart)."""
    family = variables["family"]
    with ssdp_notify_listener(variables["client"], family, variables.get("ifindex", 0)) as sock:
        if step.get("restart"):
            run_restart(variables)
        messages = receive_ssdp(sock, step.get("seconds", 5),
                                lambda start, headers: start.upper().startswith("NOTIFY")
                                and headers.get("nts") in step.get("nts", ["ssdp:alive", "ssdp:byebye"]))
    check_each(messages, step.get("each", {}), variables)
    values = ssdp_values(messages)
    for nts in ("ssdp:alive", "ssdp:byebye"):
        values[f"count.{nts}"] = sum(1 for m in messages if m["headers"].get("nts") == nts)
    return values


def http_values(responses, closed):
    values = {"responses": len(responses), "closed": closed, "statuses": [r["status"] for r in responses]}
    if responses:
        first = responses[0]
        values.update({"status": first["status"], "version": first["version"],
                       "body": first["body"].decode("utf-8", "replace"), "body_length": len(first["body"])})
        values.update({f"header.{name}": value for name, value in first["headers"].items()})
    return values


def description_values(body, location):
    description = parse_description(body, location)
    urls = [service[key] for service in description["services"] for key in ("scpd", "control", "event")]
    return {"desc.spec_version": description["spec_version"], "desc.udn": description["udn"],
            "desc.udns": description["udns"], "desc.device_types": description["device_types"],
            "desc.service_types": [service["type"] for service in description["services"]],
            "desc.urls": urls, "desc.services": description["services"],
            "desc.friendly_name": description["device"]["friendly_name"]}


def scpd_values(body):
    scpd = parse_scpd(body)
    values = {"scpd.spec_version": scpd["spec_version"], "scpd.actions": sorted(scpd["actions"]),
              "scpd.variables": sorted(scpd["variables"]),
              "scpd.evented": sorted(name for name, var in scpd["variables"].items() if var["evented"])}
    for action, arguments in scpd["actions"].items():
        values[f"scpd.args.{action}"] = [argument["name"] for argument in arguments]
    return values


def run_http_step(step, variables):
    """A request: exact bytes (raw, with {host} for the router's host:port; repeat sends it again on the same
    connection) or a well-formed one (method, path, headers, body). parse: description | scpd adds
    their values; check_urls fetches every URL of the description."""
    request = resolve_request({key: value for key, value in step.items() if key != "expect"}, variables)
    host, port = variables["router"], variables.get("http_port", UPNP_HTTP_PORT)
    if "raw" in request:
        data = request["raw"].replace("{host}", f"{host_literal(host)}:{port}")
        if "pad_header" in request:     # an oversized header line of that many bytes
            data = data.replace("{pad}", "X-Pad: " + "a" * request["pad_header"])
        data = data.encode() * request.get("repeat", 1)
        responses, closed = http_exchange(host, port, data, request.get("count", request.get("repeat", 1)),
                                          request.get("timeout", 5))
        values = http_values(responses, closed)
    else:
        url = upnp_url(variables, request.get("path", "/rootDesc.xml"))
        status, headers, body = http_request(url, request.get("method", "GET"), request.get("body"),
                                             request.get("headers"), request.get("timeout", 5))
        values = http_values([{"status": status, "version": "HTTP/1.1", "headers": headers, "body": body}], False)
        if status == 200 and request.get("parse") == "description":
            values.update(description_values(body, url))
            if request.get("check_urls"):
                broken = []
                for service in values["desc.services"]:
                    for key, method in (("scpd", "GET"), ("control", "POST"), ("event", None)):
                        if service[key] is None:
                            broken.append(f"{service['type']} has no {key} URL")
                        elif method == "GET" and http_request(service[key])[0] != 200:
                            broken.append(f"GET {service[key]} failed")
                        elif key != "scpd" and urllib.parse.urlsplit(service[key]).hostname is None:
                            broken.append(f"{service[key]} is not absolute")
                values["desc.broken_urls"] = broken
        elif status == 200 and request.get("parse") == "scpd":
            values.update(scpd_values(body))
    return values


def run_soap_step(step, variables):
    """A SOAP action on a service of the build: service is a key of the `services` variable ({name:
    {type, control}}); args are pairs or a dict; soapaction / raw_body / path / service_type override."""
    request = resolve_request({key: value for key, value in step.items() if key != "expect"}, variables)
    service = variables.get("services", {}).get(request.get("service", "WANIPConnection"), {})
    service_type = request.get("service_type", service.get("type"))
    control = upnp_url(variables, request.get("path", service.get("control")))
    args = request.get("args", [])
    if isinstance(args, dict):
        args = list(args.items())
    args = [(name, "" if value is None else value) for name, value in args]
    raw_body = request.get("raw_body")
    if raw_body is not None:
        raw_body = raw_body.replace("{service_type}", str(service_type)).replace("{action}", request["action"])
        raw_body = raw_body.replace("{pad}", "a" * request.get("pad", 0))
    status, result = soap_call(control, service_type, request["action"], args, request.get("soapaction"),
                               raw_body, request.get("headers"), request.get("timeout", 5))
    values = {"status": status, "fault": None, "fault_description": None, "parsed": result is not None}
    if isinstance(result, SoapFault):
        values.update(fault=result.code, fault_description=result.description)
    elif result:
        values["element"] = result.get("_element")
        values.update({f"out.{name}": value for name, value in result.items() if name != "_element"})
        values["out"] = sorted(name for name in result if name != "_element")
    return values


def upnp_listener(variables):
    """The EventListener of the case (one, started on the first subscribe)."""
    if variables.get("_listener") is None:
        variables["_listener"] = EventListener(variables["client"])
        variables.setdefault("_resources", []).append(variables["_listener"])
    return variables["_listener"]


def run_subscribe_step(step, variables):
    """mode: subscribe (CALLBACK to the case's listener), renew, unsubscribe, or raw (headers as given;
    {callback} is the listener's URL). service names the event URL in `services`, or path gives it."""
    request = resolve_request({key: value for key, value in step.items() if key != "expect"}, variables)
    service = variables.get("services", {}).get(request.get("service", "WANIPConnection"), {})
    event_url = upnp_url(variables, request.get("path", service.get("event")))
    mode = request.get("mode", "subscribe")
    if mode == "subscribe":
        listener = upnp_listener(variables)
        variables["_events_before"] = len(listener.events)
        status, sid, timeout = gena_subscribe(event_url, request.get("callback", listener.url),
                                              request.get("timeout", "Second-1800"))
    elif mode == "renew":
        status, sid, timeout = gena_renew(event_url, request["sid"], request.get("timeout", "Second-1800"))
    elif mode == "unsubscribe":
        status, sid, timeout = gena_unsubscribe(event_url, request["sid"])
    else:
        listener = upnp_listener(variables)
        headers = [(name, str(value).replace("{callback}", listener.url)) for name, value in request["headers"]]
        status, sid, timeout = gena_request(event_url, request.get("method", "SUBSCRIBE"), headers)
    return {"status": status, "sid": sid, "timeout": timeout}


def run_notify_wait_step(step, variables):
    """The next NOTIFY of a SID (and SEQ) on the case's listener, within timeout; count: the events seen."""
    request = resolve_request({key: value for key, value in step.items() if key != "expect"}, variables)
    listener = upnp_listener(variables)
    event = listener.wait(request.get("sid"), request.get("seq"), request.get("timeout", 5),
                          request.get("after", 0))
    values = {"received": event is not None,
              "count": sum(1 for item in listener.events if request.get("sid") in (None, item["sid"]))}
    if event:
        values.update(seq=event["seq"], sid=event["sid"], nt=event["nt"], nts=event["nts"],
                      properties=sorted(event["properties"] or {}))
        values.update({f"prop.{name}": value for name, value in (event["properties"] or {}).items()})
    return values


def run_upnp_lease_step(step, variables, lease):
    """The lines of the daemon's UPnP lease file (PROTO:eport:iaddr:iport:timestamp:description) that
    match `match` (a regular expression after resolving variables); wait_seconds as for lease_file."""
    pattern = resolve_value(step.get("match", ""), variables)
    deadline = time.monotonic() + step.get("wait_seconds", 0)
    while True:
        lines = [line for line in (lease.raw_lines() if lease.file or lease.command else []) if line.strip()]
        matched = [line for line in lines if re.search(pattern, line)]
        values = {"count": len(matched), "lines": matched, "all": len(lines)}
        if matched:
            values["line"] = matched[0]
        try:
            check_upnp_values(values, step.get("expect", {}), variables)
            return None
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)


UPNP_STEPS = {"ssdp": run_ssdp_step, "ssdp-listen": run_ssdp_listen_step, "http": run_http_step,
              "soap": run_soap_step, "subscribe": run_subscribe_step, "notify-wait": run_notify_wait_step}


def run_upnp_step(step, variables, lease=NO_LEASE):
    """One UPnP step: run it, check its expect, keep the values its `capture` names ({variable: field})."""
    kind = step["kind"]
    if kind == "restart":
        run_restart(variables, step.get("timeout", 120))
        return
    if kind == "upnp-lease":
        run_upnp_lease_step(step, variables, lease)
        return
    values = UPNP_STEPS[kind](step, variables)
    # captured first (a field without a value is not), so the cleanup can undo what the step made even
    # when its checks fail; a later "$name" of a missing capture fails that step
    for name, field in step.get("capture", {}).items():
        if values.get(field) is not None:
            variables[name] = values[field]
    check_upnp_values(values, step.get("expect", {}), variables)


# Build variants of a UPnP corpus (igd1, igd2): a case lists its builds as it lists its families


def case_builds(case, builds):
    """The builds a case runs on (default: every build of the corpus)."""
    listed = case.get("builds", sorted(builds))
    if not isinstance(listed, list) or not listed:
        raise ValueError(f"{case.get('name', '<unnamed>')}: invalid builds list")
    return listed


def resolve_variant(value, choices, chosen):
    """A value with every {choice: value} dict (its keys exactly `choices`) replaced by the chosen value,
    as resolve_family does for {ipv4, ipv6}."""
    if isinstance(value, dict):
        if value and set(value) == set(choices):
            return resolve_variant(value[chosen], choices, chosen)
        return {key: resolve_variant(item, choices, chosen) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_variant(item, choices, chosen) for item in value]
    return value


# WAN exposure: what a WAN peer reaches of the daemon's UPnP side (SSDP, HTTP, SOAP)


def check_wan_exposure(agent, protocol, host, port, payload, timeout=1.0):
    """A WAN peer (its traffic agent) sends `payload` to host:port. The router must neither answer it
    (UDP) nor accept the connection (TCP): the agent's probe then ends with an error (a timeout, a refused
    connection); an answer of any kind, or an accepted connection, ends without one."""
    outcome = traffic_agent.request_probe(agent, protocol, host, port, payload.encode().hex(), timeout=timeout)
    if "error" not in outcome:
        raise AssertionError(f"{protocol} {host_literal(host)}:{port} answered a WAN peer ({outcome})")

"""PCP (RFC 6887) and NAT-PMP (RFC 6886) names and packet encoding shared by the test tools."""

import ipaddress
import socket
import struct

PCP_PORT = 5351
PCP_MAX_MESSAGE = 1100          # RFC 6887 section 7: a request is at most 1100 octets
MAP_REQUEST_SIZE = 60           # header 24 + MAP body 36
PEER_REQUEST_SIZE = 80          # MAP request + remote peer port/reserved/address (20)
FILTER_OPTION_SIZE = 24         # option header 4 + reserved/prefix/port 4 + address 16
NONCE_LENGTH = 12               # RFC 6887 section 11.1: the MAP / PEER mapping nonce
DEFAULT_NONCE = b"\x42" * NONCE_LENGTH

PCP_OPCODES = {"ANNOUNCE": 0, "MAP": 1, "PEER": 2, "AUTHENTICATION": 3}
NATPMP_OPCODES = {"PUBLIC_ADDRESS": 0, "MAP_UDP": 1, "MAP_TCP": 2}
PROTOCOLS = {"UDP": 17, "TCP": 6}
OPTIONS = {"THIRD_PARTY": 1, "PREFER_FAILURE": 2, "FILTER": 3, "NONCE": 4, "PORT_SET": 130}
OPTION_UNKNOWN_OPTIONAL = 224   # optional range, private use (RFC 6887 section 19.4); 128 is DESCRIPTION
RESULTS = {
    "pcp": {"SUCCESS": 0, "UNSUPP_VERSION": 1, "NOT_AUTHORIZED": 2, "MALFORMED_REQUEST": 3,
            "UNSUPP_OPCODE": 4, "UNSUPP_OPTION": 5, "MALFORMED_OPTION": 6, "NETWORK_FAILURE": 7,
            "NO_RESOURCES": 8, "UNSUPP_PROTOCOL": 9, "USER_EX_QUOTA": 10,
            "CANNOT_PROVIDE_EXTERNAL": 11, "ADDRESS_MISMATCH": 12, "EXCESSIVE_REMOTE_PEERS": 13},
    "natpmp": {"SUCCESS": 0, "UNSUPP_VERSION": 1, "NOT_AUTHORIZED": 2, "NETWORK_FAILURE": 3,
               "OUT_OF_RESOURCES": 4, "UNSUPP_OPCODE": 5},
}
RESPONSE_OPCODES = {
    "pcp": {name + "_RESPONSE": 128 + code for name, code in PCP_OPCODES.items()},
    "natpmp": {name + "_RESPONSE": 128 + code for name, code in NATPMP_OPCODES.items()},
}


def names_by_code(table):
    """Invert a name -> code table."""
    return {code: name for name, code in table.items()}


_RESULT_NAMES = {protocol: names_by_code(table) for protocol, table in RESULTS.items()}


def result_name(protocol, code):
    """Name of a result code ("pcp" or "natpmp"), or UNKNOWN(<code>)."""
    return _RESULT_NAMES[protocol].get(code, f"UNKNOWN({code})")


def parse_map_response(response):
    """Fields of a PCP MAP/PEER response (the caller checks the length); `remote_*` only for PEER."""
    fields = {"version": response[0], "opcode": response[1], "result": response[3],
              "nonce": response[24:36], "protocol": response[36], "internal_port": response[40:42],
              "external_port": struct.unpack("!H", response[42:44])[0], "external_address": response[44:60]}
    if response[1] & 0x7f == PCP_OPCODES["PEER"] and len(response) >= PEER_REQUEST_SIZE:
        fields["remote_port"] = response[60:62]
        fields["remote_address"] = response[64:80]
    return fields


def parse_natpmp_response(response):
    """Fields of a NAT-PMP response: result code and epoch, plus the address or the port/lifetime fields."""
    fields = {"version": response[0], "opcode": response[1], "result": struct.unpack("!H", response[2:4])[0]}
    if len(response) >= 8:
        fields["epoch"] = struct.unpack("!I", response[4:8])[0]
    if response[1] == 128:
        fields["address"] = socket.inet_ntop(socket.AF_INET, response[8:12])
    elif len(response) >= 16:
        fields["private_port"], fields["public_port"], fields["lifetime"] = struct.unpack("!HHI", response[8:16])
    return fields


def ipv6_bytes(value):
    """16-byte form of an IPv4 (as ::ffff:a.b.c.d) or IPv6 address string."""
    address = ipaddress.ip_address(value)
    if address.version == 4:
        return socket.inet_pton(socket.AF_INET6, f"::ffff:{address}")
    return address.packed


def pcp_header(version, opcode, lifetime, client, reserved=0):
    """PCP common request header; `client` is an address string or 16 raw bytes."""
    if isinstance(client, str):
        client = ipv6_bytes(client)
    return struct.pack("!BBHI", version, opcode, reserved, lifetime) + client


def pcp_map_body(protocol, internal_port, external_port, external_address=b"\0" * 16, nonce=None):
    """MAP opcode body; PCP version 1 (draft) has no nonce."""
    return ((nonce or b"") + bytes((protocol, 0, 0, 0)) + struct.pack("!HH", internal_port, external_port)
            + external_address)


def pcp_peer_tail(remote_port, remote_address, reserved=0):
    """The PEER-specific fields that follow a MAP body."""
    if isinstance(remote_address, str):
        remote_address = ipv6_bytes(remote_address)
    return struct.pack("!HH", remote_port, reserved) + remote_address


def pcp_mapping_request(version, opcode, lifetime, client, protocol, internal_port, external_port,
                        nonce=None, external_address=None, peer=None, options=b"", reserved=0):
    """A MAP or PEER request: header, MAP body (with the nonce when given), the PEER tail when
    `peer` = (port, address[, reserved]) is given, then the already encoded options."""
    request = pcp_header(version, opcode, lifetime, client, reserved)
    request += pcp_map_body(protocol, internal_port, external_port, external_address or b"\0" * 16, nonce)
    if peer is not None:
        request += pcp_peer_tail(*peer)
    return request + options


def pcp_option(code, data=b""):
    """One option, padded to a 4-octet boundary."""
    return struct.pack("!BBH", code, 0, len(data)) + data + b"\0" * (-len(data) % 4)


def pcp_filter_option(prefix_length, remote_port, remote_address):
    """FILTER option; `prefix_length` is the on-the-wire (IPv6-mapped) prefix length."""
    if isinstance(remote_address, str):
        remote_address = ipv6_bytes(remote_address)
    return pcp_option(OPTIONS["FILTER"], bytes((0, prefix_length)) + struct.pack("!H", remote_port)
                      + remote_address)


def pcp_filter_for_peer(prefix_length, remote_port, remote_address):
    """FILTER option for a peer address string; an IPv4 prefix length counts in the IPv4-mapped form (+96)."""
    if prefix_length and ipaddress.ip_address(remote_address).version == 4:
        prefix_length += 96
    return pcp_filter_option(prefix_length, remote_port, remote_address)


def pcp_request_size(peer=False, filter_count=0, prefer_failure=False, unknown_options=0):
    """Octets of a PCP MAP / PEER request with its options (FILTER 24 each, PREFER_FAILURE and every unknown
    optional option 4)."""
    size = PEER_REQUEST_SIZE if peer else MAP_REQUEST_SIZE
    return size + filter_count * FILTER_OPTION_SIZE + (4 if prefer_failure else 0) + unknown_options * 4


def parse_options(data, offset, what="option"):
    """The options of a PCP message from `offset` on, as [(code, payload)]: each is a 4-octet header
    (code, reserved, length) and its payload padded to a multiple of 4. Raises ValueError, naming
    `what`, when an option is cut short."""
    options = []
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError(f"truncated {what} header")
        code, _reserved, length = struct.unpack("!BBH", data[offset:offset + 4])
        start, end = offset + 4, offset + 4 + length
        if end > len(data):
            raise ValueError(f"truncated {what} {code}")
        options.append((code, data[start:end]))
        offset = end + (-length % 4)
    return options


def natpmp_packet(opcode, private_port=0, public_port=0, lifetime=0, version=0, reserved=0):
    """NAT-PMP mapping request (or the same layout with another opcode)."""
    return struct.pack("!BBHHHI", version, opcode, reserved, private_port, public_port, lifetime)


def parse_auth_response(response):
    """(result, session id, sequence number, {option code: data}) of a PCP AUTHENTICATION response.
    Raises ValueError on a short or wrong response."""
    if len(response) < 32:
        raise ValueError(f"short PCP AUTHENTICATION response: {len(response)} bytes")
    if response[0] != 2 or response[1] != RESPONSE_OPCODES["pcp"]["AUTHENTICATION_RESPONSE"]:
        raise ValueError("expected PCP AUTHENTICATION response")
    session_id, sequence_number = struct.unpack("!II", response[24:32])
    options = dict(parse_options(response, 32, "PCP authentication option"))
    return response[3], session_id, sequence_number, options

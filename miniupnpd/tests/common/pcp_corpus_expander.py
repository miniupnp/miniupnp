"""Human-readable PCP / NAT-PMP packet definitions for pcp-wire-cases.yaml.

Cases are written with symbolic names; `expand_corpus` turns them into the
low-level request/expect dictionaries that run_pcp_wire_cases.py builds packets from.

Request forms (anything containing `kind:` is passed through unchanged):

  pcp: MAP | PEER | AUTHENTICATION      full opcode packet
      protocol: UDP | TCP | <number>    (MAP/PEER)
      nonce: <24 hex digits>
      options: [PREFER_FAILURE, {PORT_SET: '0001c73900'}, {code: 99, data_hex: ''}]
      port_set: <size> | {size: N, first: P, parity: true}
                                        PORT_SET option (first defaults to internal_port)
      a key set to null removes its default
      defaults: version 2, client source, external_address '::', external_port 0
  header: ANNOUNCE | MAP | <number>     common header only (malformed-packet tests)
  natpmp: PUBLIC_ADDRESS | MAP_UDP | MAP_TCP | <name>_RESPONSE | <number>
      truncate_to: N                    send only the first N bytes (raw datagram)
      defaults: version 0, reserved 0 (null omits)
  use: <name>                           start from `defs.packets.<name>`; keys
                                        given next to `use` override the template

A `lease_restart` request has `phases: {create: [steps], verify: [steps]}` (and a `cleanup`) of the
same steps; the driver runs the phases around a daemon restart (pcp_wire/run-docker.sh).

Steps of a `protocol_sequence` request (and its `cleanup`) can also use:

  use: <name>            start from `defs.steps.<name>`; keys next to `use` are
                         deep-merged over the template (a `null` value deletes a key)
  each: [<override>...]  expand to one step per override, each merged over the
                         template / step body
  verify: mapping | port-set-mapping | natpmp-mapping
                         fill in the standard MAP response `captures` and `assert`
                         values derived from the request (internal port, nonce,
                         protocol, lifetime and, for port-set-mapping, the PORT_SET
                         option); explicit `captures` / `assert` entries override
  cleanup: auto          delete every distinct successful PCP/NAT-PMP MAP the steps created
                         (order not significant)

Options: `{PORT_SET: {size: 4, first: 51001, parity: true}}` encodes the RFC 7753
option data; a hex string is used as is.

Expectations: `result` lists use result names and response `opcode` values use
names such as MAP_RESPONSE; plain numbers are always accepted.
"""

import copy
import struct

from pcp_packet_encoding import (NATPMP_OPCODES, natpmp_packet, OPTIONS, PCP_OPCODES, PROTOCOLS, RESPONSE_OPCODES,  # noqa: E402
                      RESULTS)

# symbolic field -> low-level field
MAP_RENAMES = {"nonce": "nonce_hex", "peer": "peer_address"}
MAP_DEFAULTS = {"version": 2, "client": "source", "external_address": "::", "external_port": 0}
NATPMP_DEFAULTS = {"version": 0, "reserved": 0}


def _lookup(table, value, what):
    if isinstance(value, int):
        return value
    if value not in table:
        raise ValueError(f"unknown {what} {value!r}")
    return table[value]


def expand_option(option):
    if isinstance(option, str):
        return {"code": _lookup(OPTIONS, option, "option")}
    if isinstance(option, dict) and "code" not in option and "raw_hex" not in option:
        (name, data), = option.items()
        if isinstance(data, dict):
            if name != "PORT_SET":
                raise ValueError(f"option {name} has no structured form")
            data = struct.pack("!HHB", data["size"], data["first"], 1 if data.get("parity") else 0).hex()
        return {"code": _lookup(OPTIONS, name, "option"), "data_hex": data}
    return dict(option)


def expand_request(spec):
    """Expand one symbolic request; low-level (`kind:`) requests pass through."""
    if "kind" in spec:
        return spec
    spec = dict(spec)
    if "pcp" in spec:
        name = spec.pop("pcp")
        opcode = _lookup(PCP_OPCODES, name, "PCP opcode")
        out = {"kind": {1: "pcp_map", 2: "pcp_peer", 3: "pcp_auth"}[opcode], "opcode": opcode}
        if opcode != 3:
            out.update(MAP_DEFAULTS)
        for key, value in spec.items():
            if key == "protocol":
                out["protocol_number"] = _lookup(PROTOCOLS, value, "protocol")
            elif key == "options":
                out["options"] = [expand_option(item) for item in value]
            elif key == "port_set":
                continue
            else:
                out[MAP_RENAMES.get(key, key)] = value
        if "port_set" in spec:
            if "options" in spec:
                raise ValueError("port_set cannot be combined with options")
            size = spec["port_set"]
            port_set = size if isinstance(size, dict) else {"size": size}
            out["options"] = [expand_option({"PORT_SET": {"first": out["internal_port"], **port_set}})]
        return {key: value for key, value in out.items() if value is not None}
    if "header" in spec:
        out = {"kind": "pcp_header", "version": 2,
               "opcode": _lookup(PCP_OPCODES, spec.pop("header"), "PCP opcode")}
        out.update(spec)
        return out
    if "natpmp" in spec:
        out = {"kind": "natpmp", **NATPMP_DEFAULTS,
               "opcode": _lookup({**NATPMP_OPCODES, **RESPONSE_OPCODES["natpmp"]}, spec.pop("natpmp"),
                                 "NAT-PMP opcode")}
        out.update(spec)
        if "truncate_to" in out:
            # a deliberately short datagram: sent as raw bytes
            packet = natpmp_packet(
                out["opcode"], out.get("private_port", 0), out.get("public_port", 0), out.get("lifetime", 0),
                version=out["version"], reserved=out["reserved"])
            return {"kind": "raw", "hex": packet[:out["truncate_to"]].hex()}
        return {key: value for key, value in out.items() if value is not None}
    raise ValueError(f"request has no pcp/header/natpmp/kind key: {sorted(spec)}")


def expand_expect(expect, protocol):
    if not isinstance(expect, dict) or protocol not in RESULTS:
        return expect
    expect = dict(expect)
    if isinstance(expect.get("result"), list):
        expect["result"] = [_lookup(RESULTS[protocol], item, "result") for item in expect["result"]]
    if isinstance(expect.get("opcode"), str):
        expect["opcode"] = _lookup(RESPONSE_OPCODES[protocol], expect["opcode"], "response opcode")
    return expect


def _apply_use(request, packets):
    if isinstance(request, dict) and "use" in request:
        request = dict(request)
        template = copy.deepcopy(packets[request.pop("use")])
        template.update(request)
        return template
    return request


def _walk(node, protocol, packets):
    if isinstance(node, list):
        return [_walk(item, protocol, packets) for item in node]
    if not isinstance(node, dict):
        return node
    protocol = node.get("protocol", protocol) if node.get("protocol") in RESULTS else protocol
    out = {}
    for key, value in node.items():
        if key == "request" and isinstance(value, dict):
            value = expand_request(_apply_use(value, packets))
        elif key == "expect":
            value = expand_expect(value, protocol)
        if key in ("request", "expect"):
            out[key] = _walk_children(value, protocol, packets)
        else:
            out[key] = _walk(value, protocol, packets)
    return out


def _walk_children(node, protocol, packets):
    # `steps` / `cleanup` inside a protocol_sequence request carry their own protocol.
    if isinstance(node, dict):
        return {key: (_walk(value, protocol, packets) if key in ("steps", "cleanup") else value)
                for key, value in node.items()}
    return node


HEADER_SIZE = 24
MAP_FIELDS = {"nonce": HEADER_SIZE, "protocol": HEADER_SIZE + 12, "internal": HEADER_SIZE + 16,
              "external": HEADER_SIZE + 18, "external_address": HEADER_SIZE + 20}
MAPPING_CAPTURES = {
    "internal": {"offset": MAP_FIELDS["internal"], "type": "u16"},
    "external": {"offset": MAP_FIELDS["external"], "type": "u16"},
    "lifetime": {"offset": 4, "type": "u32"},
    "nonce": {"offset": MAP_FIELDS["nonce"], "type": "hex", "length": 12},
    "protocol_reserved": {"offset": MAP_FIELDS["protocol"], "type": "u32"},
    "external_address": {"offset": MAP_FIELDS["external_address"], "type": "address"}}
PORT_SET_CAPTURES = {
    "option_header": {"offset": 60, "type": "u32"}, "size": {"offset": 64, "type": "u16"},
    "first": {"offset": 66, "type": "u16"}, "flags": {"offset": 68, "type": "u8"},
    "padding_first": {"offset": 69, "type": "u8"}, "padding": {"offset": 70, "type": "u16"}}
PORT_SET_OPTION_HEADER = 0x82000005


def deep_merge(base, over):
    """Merge `over` into a copy of `base`; dicts merge, `None` deletes, the rest replaces."""
    out = copy.deepcopy(base)
    for key, value in over.items():
        if value is None:
            out.pop(key, None)
        elif isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _override(derived, explicit):
    """Per-key replacement of derived entries; a `null` entry removes the key."""
    out = {**copy.deepcopy(derived), **copy.deepcopy(explicit)}
    return {key: value for key, value in out.items() if value is not None}


def derive_natpmp_checks(request):
    """Captures and asserts for a NAT-PMP mapping response to `request`."""
    captures = {"private_port": {"offset": 8, "type": "u16"}, "external_port": {"offset": 10, "type": "u16"},
                "lifetime": {"offset": 12, "type": "u32"}}
    lifetime = request["lifetime"]
    checks = {"private_port": {"equals": request["private_port"]},
              "external_port": {"equals": 0} if lifetime == 0 else {"nonzero": True},
              "lifetime": {"equals": 0} if lifetime == 0 else {"min": 1, "max": lifetime}}
    return captures, checks


def derive_checks(mode, request):
    """Standard captures and asserts for a MAP response to `request`."""
    if mode == "natpmp-mapping":
        return derive_natpmp_checks(request)
    captures = copy.deepcopy(MAPPING_CAPTURES)
    checks = {"internal": {"equals": request["internal_port"]},
              "nonce": {"equals": request["nonce_hex"]},
              "protocol_reserved": {"equals": request["protocol_number"] << 24},
              "lifetime": {"equals": 0} if request["lifetime"] == 0 else {"min": 1, "max": 600}}
    if mode == "port-set-mapping":
        data = next(bytes.fromhex(o["data_hex"]) for o in request["options"] if o["code"] == 130)
        size, first = struct.unpack("!HH", data[:4])
        captures.update(copy.deepcopy(PORT_SET_CAPTURES))
        checks.update({"option_header": {"equals": PORT_SET_OPTION_HEADER}, "size": {"equals": size},
                       "first": {"equals": first}, "flags": {"max": 1},
                       "padding_first": {"equals": 0}, "padding": {"equals": 0}})
    elif mode != "mapping":
        raise ValueError(f"unknown verify mode {mode!r}")
    return captures, checks


def expand_step(step, case_protocol, templates):
    if "use" in step:
        step = deep_merge(templates[step["use"]], {k: v for k, v in step.items() if k != "use"})
    step = dict(step)
    protocol = step.get("protocol", case_protocol)
    if isinstance(step.get("request"), dict):
        step["request"] = expand_request(step["request"])
    if "expect" in step:
        step["expect"] = expand_expect(step["expect"], protocol)
    if "verify" in step:
        captures, checks = derive_checks(step.pop("verify"), step["request"])
        step["captures"] = _override(captures, step.get("captures", {}))
        step["assert"] = _override(checks, step.get("assert", {}))
    return step


def auto_cleanup(steps):
    """Delete each distinct successful MAP created by `steps`."""
    out, seen = [], set()
    for step in steps:
        request = step.get("request", {})
        if (request.get("kind") == "natpmp" and request.get("opcode") in (1, 2)
                and isinstance(request.get("lifetime"), int) and request["lifetime"] > 0
                and step.get("expect", {}).get("result") == [0]):
            key = ("natpmp", request["opcode"], request["private_port"])
            if key not in seen:
                seen.add(key)
                out.append({"protocol": "natpmp", "request": dict(request, lifetime=0, public_port=0),
                            "expect": {"version": 0, "opcode": 128 + request["opcode"],
                                       "result": [0], "length": 16}})
            continue
        if (request.get("kind") != "pcp_map" or not isinstance(request.get("lifetime"), int)
                or request["lifetime"] <= 0 or step.get("expect", {}).get("result") != [0]):
            continue
        key = (request["nonce_hex"], request["protocol_number"], request["internal_port"])
        if key in seen:
            continue
        seen.add(key)
        delete = dict(request, lifetime=0, external_port=0)
        optional = any(o.get("code") == 130 and len(bytes.fromhex(o.get("data_hex", ""))) >= 4
                       for o in request.get("options", []))
        step_out = {"protocol": step["protocol"], "request": delete,
                    "expect": {"version": 2, "opcode": 129, "result": [0],
                               "length": [60, 72] if optional else 60}}
        captures, checks = derive_checks("mapping", delete)
        step_out["captures"], step_out["assert"] = captures, checks
        out.append(step_out)
    return out


def expand_sequence(request, case_protocol, templates):
    request = dict(request)
    for key in ("steps", "cleanup"):
        if key == "cleanup" and request.get(key) == "auto":
            continue
        expanded = []
        for step in request.get(key, []):
            if "each" in step:
                body = {k: v for k, v in step.items() if k != "each"}
                for override in step["each"]:
                    expanded.append(expand_step(deep_merge(body, override), case_protocol, templates))
            else:
                expanded.append(expand_step(step, case_protocol, templates))
        if key in request:
            request[key] = expanded
    if request.get("cleanup") == "auto":
        request["cleanup"] = auto_cleanup(request["steps"])
    return request


def _expand_case_steps(case, templates):
    request = case.get("request")
    if isinstance(request, dict) and request.get("kind") == "protocol_sequence":
        case = dict(case, request=expand_sequence(request, case.get("protocol"), templates))
    elif isinstance(request, dict) and request.get("kind") == "lease_restart":
        # phases: {create: [steps], verify: [steps]}, run by the driver around a daemon restart
        protocol = case.get("protocol")
        expanded = dict(request, phases={
            name: expand_sequence({"steps": steps}, protocol, templates)["steps"]
            for name, steps in request["phases"].items()})
        if "cleanup" in request:
            expanded["cleanup"] = expand_sequence({"cleanup": request["cleanup"]}, protocol, templates)["cleanup"]
        case = dict(case, request=expanded)
    return case


def expand_corpus(corpus):
    """Return a corpus with all symbolic requests/expectations expanded."""
    packets = corpus.get("defs", {}).get("packets", {})
    templates = corpus.get("defs", {}).get("steps", {})
    out = {key: value for key, value in corpus.items() if key != "defs"}
    sections = []
    for section in corpus["sections"]:
        section = dict(section)
        section["cases"] = [_walk(_expand_case_steps(case, templates), case.get("protocol"), packets)
                            for case in section["cases"]]
        sections.append(section)
    out["sections"] = sections
    return out


# ---------------------------------------------------------------------------
# pcp-e2e-cases.yaml: requests are described to the e2e runner (run_pcp_e2e_cases.py), which
# builds the packet bytes itself.  `expand_e2e_corpus` turns the named form
#
#   request:
#     pcp: MAP | PEER                  (PEER also takes remote_peer / remote_peer_port)
#     lifetime: 120
#     protocol: udp
#     internal_port: 41006
#     suggested_external_port: 41006
#     options:                         FILTERs first, then PREFER_FAILURE, then
#       - FILTER: allowed-peer         UNKNOWN_OPTIONAL (the order run_pcp_e2e_cases.py sends them)
#       - {FILTER: {remote_peer: denied-peer, remote_port: 42000, prefix_length: 24}}
#       - PREFER_FAILURE
#       - {UNKNOWN_OPTIONAL: 1}
#   request: {natpmp: UDP | TCP | PUBLIC_ADDRESS, private_port: .., public_port: .., lifetime: ..}
#   request: {upnp: AddPortMapping | DeletePortMapping, protocol: udp, internal_port: ..,
#             external_port: .., lease_duration: .., wait_after: seconds}   (IPv4, UPnP IGD)
#   request: {upnp: AddAnyPortMapping | DeletePortMappingRange (start_port, end_port) | AddPinhole |
#             UpdatePinhole | DeletePinhole (remote_host, remote_port, lease_time; IPv6), ...}
#
# into the keys run_pcp_e2e_cases.py reads (opcode, filter/filters, prefer_failure,
# unknown_optional_options, protocol_family).  A FILTER given only a peer name
# matches that exact address (prefix /32 for IPv4, /128 for IPv6) on any port;
# `prefix_length: exact` is that same default.  `defs.packets` + `use:` work as above.
# ---------------------------------------------------------------------------

E2E_EXACT_PREFIX = {"ipv4": 32, "ipv6": 128}


def _expand_e2e_filter(value):
    filt = {"remote_peer": value} if isinstance(value, str) else dict(value)
    filt.setdefault("remote_port", 0)
    if filt.get("prefix_length", "exact") == "exact":
        filt["prefix_length"] = dict(E2E_EXACT_PREFIX)
    return filt


def expand_e2e_request(spec):
    if "upnp" in spec:
        spec = dict(spec)
        action = spec.pop("upnp")
        if action not in ("AddPortMapping", "DeletePortMapping", "AddAnyPortMapping", "DeletePortMappingRange",
                          "AddPinhole", "UpdatePinhole", "DeletePinhole"):
            raise ValueError(f"unknown UPnP action {action!r}")
        return {"protocol_family": "UPnP", "action": action, **spec}
    if "natpmp" in spec:
        spec = dict(spec)
        opcode = spec.pop("natpmp")
        if opcode not in ("UDP", "TCP", "PUBLIC_ADDRESS"):
            raise ValueError(f"unknown NAT-PMP opcode {opcode!r}")
        out = {"protocol_family": "NAT-PMP", "opcode": opcode}
        if opcode != "PUBLIC_ADDRESS":
            out["protocol"] = opcode.lower()
        out.update(spec)
        return out
    if "pcp" not in spec:
        return dict(spec)
    spec = dict(spec)
    out = {"opcode": spec.pop("pcp")}
    options = spec.pop("options", [])
    out.update(spec)
    filters, order = [], []
    for option in options:
        if isinstance(option, str):
            name, value = option, None
        else:
            (name, value), = option.items()
        order.append(name)
        if name == "FILTER":
            filters.append(_expand_e2e_filter(value))
        elif name == "PREFER_FAILURE":
            out["prefer_failure"] = True
        elif name == "UNKNOWN_OPTIONAL":
            out["unknown_optional_options"] = value
        else:
            raise ValueError(f"unknown option {name!r}")
    rank = {"FILTER": 0, "PREFER_FAILURE": 1, "UNKNOWN_OPTIONAL": 2}
    if order != sorted(order, key=rank.__getitem__):
        raise ValueError("options must be listed as FILTERs, PREFER_FAILURE, UNKNOWN_OPTIONAL")
    if len(filters) == 1:
        out["filter"] = filters[0]
    elif filters:
        out["filters"] = filters
    return out


def expand_e2e_corpus(corpus):
    packets = corpus.get("defs", {}).get("packets", {})
    out = {key: value for key, value in corpus.items() if key != "defs"}
    sections = []
    for section in corpus["sections"]:
        cases = []
        for case in section["cases"]:
            case = dict(case)
            for key in ("request", "requests"):
                if key in case:
                    items = case[key] if key == "requests" else [case[key]]
                    items = [expand_e2e_request(_apply_use(item, packets)) for item in items]
                    case[key] = items if key == "requests" else items[0]
            cases.append(case)
        sections.append(dict(section, cases=cases))
    out["sections"] = sections
    return out

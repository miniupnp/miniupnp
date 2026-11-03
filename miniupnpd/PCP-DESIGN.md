# PCP / NAT-PMP in miniupnpd: high-level design

Scope: the `enable_pcp_pmp` part of miniupnpd (NAT-PMP and PCP), as on branch `feat/pcp-peer-filter`.

## 1. Standards

| Standard | Status in the code |
|---|---|
| RFC 6886 NAT-PMP | Implemented (`natpmp.c`): external address, UDP/TCP mapping, public address change notification. |
| RFC 6887 PCP (version 2) | Implemented (`pcpserver.c`): ANNOUNCE, MAP, PEER (needs `--pcp-peer`), THIRD_PARTY, PREFER_FAILURE and FILTER options, epoch time, unsolicited ANNOUNCE on multicast 224.0.0.1 / ff02::1 port 5350. Both IPv4 NAT mappings and IPv6 firewall pinholes (a pinhole cannot translate the internal port). |
| PCP version 1 (draft) | MAP/PEER v1 message sizes are parsed (`PCP_MAP_V1_SIZE`, `PCP_PEER_V1_SIZE`). |
| RFC 7220 (DESCRIPTION option) | Only the lease file has a `label` column. The option is **not parsed** from requests yet, so the label is empty in practice. |
| RFC 7652 (authentication) | Option codes are reserved in `pcp_msg_struct.h`. Not implemented. |
| `SADSCP` opcode, `FLOWP` option | Compile-time options (`PCP_SADSCP`, `PCP_FLOWP`), off by default. Use `pcplearndscp.c`. |

## 2. Subsystems and files

```mermaid
flowchart TB
    subgraph clients["LAN clients"]
        C1["PCP client<br/>UDP 5351"]
        C2["NAT-PMP client<br/>UDP 5351"]
    end

    subgraph daemon["miniupnpd process (single select() loop)"]
        MAIN["miniupnpd.c<br/>main loop, sockets, signals,<br/>timers, startup/shutdown"]
        OPT["options.c / options.h<br/>miniupnpd.conf<br/>enable_pcp_pmp, min_lifetime / max_lifetime,<br/>pcp_allow_thirdparty,<br/>pcp_min_lifetime_override, lease_file"]
        NATPMP["natpmp.c<br/>NAT-PMP RFC 6886<br/>also receives and dispatches<br/>PCP packets (version byte)"]
        PCP["pcpserver.c<br/>PCP RFC 6887<br/>ANNOUNCE / MAP / PEER<br/>option parsing, ACL, lifetimes"]
        MSG["pcp_msg_struct.h<br/>wire formats, opcodes,<br/>result codes, options"]
        FILT["pcp_filter.c / .h<br/>FILTER option policy:<br/>merge, mask, equal<br/>+ backend contract"]
        PEERL["peer_lease.c / .h<br/>PEER mapping expiry,<br/>60 s retry"]
        LEASE["pcp_lease.c / .h<br/>PCP lease file<br/>save / load / owns"]
        UPNP["UPnP IGD side<br/>upnpredirect.c, lease file<br/>(UPnP leases)"]
        DSCP["pcplearndscp.c<br/>(optional SADSCP)"]
    end

    subgraph backend["Firewall backend (one per build)"]
        NFT["netfilter_nft/<br/>nftnlrdr.c, nftpinhole.c"]
        PF["pf/<br/>obsdrdr.c, pfpcp.c,<br/>pfpinhole.c, pfrules.c"]
        IPT["netfilter/ (iptables)<br/>iptcrdr.c, iptpinhole.c<br/>no FILTER / lease support"]
    end

    KERNEL[("Kernel: nftables / pf / iptables<br/>NAT, forward and pinhole rules")]
    FS[("lease_file<br/>lease_file.pcp")]

    C1 --> MAIN
    C2 --> MAIN
    MAIN --> NATPMP
    NATPMP -->|"version 2"| PCP
    OPT --> MAIN
    PCP --- MSG
    NATPMP --- MSG
    PCP --> FILT
    PCP --> PEERL
    PCP --> LEASE
    NATPMP --> LEASE
    PCP --> DSCP
    MAIN -->|"timer: expire, save"| LEASE
    MAIN -->|"timer: expire peers"| PEERL
    MAIN -->|"startup: reload"| LEASE
    PCP -->|"add / delete / get rules"| backend
    NATPMP -->|"add / delete rules"| backend
    FILT --> backend
    PEERL --> backend
    LEASE -->|"list rules<br/>pcp_lease_maps"| backend
    LEASE <--> FS
    UPNP <--> FS
    UPNP --> backend
    backend --> KERNEL
```

### File roles

| File | Role |
|---|---|
| `miniupnpd.c` | `select()` loop. Opens the NAT-PMP/PCP sockets (IPv4 per listening address, one IPv6), calls `ProcessIncomingNATPMPPacket` or `ProcessIncomingPCPPacket`, sends the announce on start and on public IP change, expires mappings, calls `pcp_lease_load()` at startup and `pcp_lease_save()` after changes. |
| `natpmp.c` | Receives packets on the shared port. A version 0 packet is handled here (NAT-PMP). A version 2 packet goes to `pcpserver.c`. |
| `pcpserver.c` | PCP request parsing and validation, ACL (`upnppermissions`), lifetime limits (`min_lifetime` / `max_lifetime`, `pcp_min_lifetime_override`), MAP / PEER / ANNOUNCE handling, response building, epoch time. Backend-neutral. |
| `pcp_msg_struct.h` | Wire structures, opcodes, result codes, option codes. |
| `pcp_filter.c/.h` | Shared FILTER policy code (merge, mask, equality). `pcp_filter.h` documents the begin / finish / delete / get contract that each backend implements. |
| `peer_lease.c/.h` | Expiry of PEER mappings. The rule is in the firewall, the lifetime is kept here. |
| `pcp_lease.c/.h` | The PCP lease file `<lease_file>.pcp`. Hashed state with an index on the PCP-F lines. |
| `options.c`, `miniupnpd.conf` | Configuration. |
| `netfilter_nft/`, `pf/` | Backends with FILTER, PEER and the PCP lease file. |
| `netfilter/` (iptables) | Backend without FILTER and lease-file support (`PCP_FILTER_SUPPORTED` / `PCP_LEASE_SUPPORTED` are defined only for nft and pf in `pcp_filter.h`). |

### Code shared with the UPnP IGD side

PCP and NAT-PMP do not have their own mapping engine. `pcpserver.c` and `natpmp.c` call the UPnP functions, so both protocols work on the same firewall state.

| Area | Shared code | Used by PCP / NAT-PMP for |
|---|---|---|
| IPv4 mappings | `upnpredirect.c`: `upnp_redirect_internal()`, `_upnp_delete_redir()` | MAP create, renew, delete (lifetime 0), NAT-PMP mappings |
| IPv6 pinholes | `upnppinhole.c`: `upnp_add / update / find / delete_inboundpinhole()` | MAP and PEER for IPv6 |
| ACL | `upnppermissions.c`: `check_upnp_rule_against_permissions()` | `allow` / `deny` rules checked on MAP |
| Globals and config | `upnpglobalvars.c`, `options.c` | interfaces, addresses, `lease_file`, lifetimes, enable flags |
| Time | `upnputils.c`: `upnp_time()` | lifetimes, epoch |
| Main loop | `miniupnpd.c` | sockets, timers, expiry, startup and shutdown |

Consequences:

- A PCP mapping and a UPnP mapping are the same kind of firewall rule. They compete for the same external port. A UPnP client can read any PCP or NAT-PMP mapping (`GetSpecificPortMappingEntry`, `GetGenericPortMappingEntry`) and can delete one with `DeletePortMapping`; with `secure_mode=yes` only when it is the internal host of the mapping. The PCP nonce is not checked on the UPnP side. The owner is only visible in the rule description (`PCP MAP <24 hex>`, `NAT-PMP <eport> <proto>`).
- The pinhole unique ID is the UPnP one. A PCP IPv6 mapping (MAP or PEER) is found by address, port and protocol, plus the remote endpoint for a PEER (`upnp_find_inboundpinhole()`), not by its own ID.
- The ACL is the UPnP ACL, so one `allow` / `deny` set governs all protocols.
- The two lease files are separate (`lease_file` for UPnP, `<lease_file>.pcp` for PCP / NAT-PMP) but both are switched on by `ENABLE_LEASEFILE` and use the same base name.
- Not shared: PCP parsing and responses (`pcpserver.c`), FILTER (`pcp_filter.c`), PEER expiry (`peer_lease.c`), the PCP lease file (`pcp_lease.c`), DSCP learning (`pcplearndscp.c`).

## 3. Build-time and run-time switches

```mermaid
flowchart LR
    CFG["configure"] -->|"always"| EPCP["ENABLE_PCP"]
    CFG -->|"--pcp-peer"| PEER["PCP_PEER"]
    CFG -->|"--leasefile"| LF["ENABLE_LEASEFILE"]
    CFG -->|"nft or pf"| SUP["PCP_FILTER_SUPPORTED<br/>PCP_LEASE_SUPPORTED<br/>(defined in pcp_filter.h)"]
    EPCP --> RUN["Run time: enable_pcp_pmp=yes"]
    LF --> LEASEOK["pcp_lease.c active only if<br/>ENABLE_PCP + ENABLE_LEASEFILE<br/>+ PCP_LEASE_SUPPORTED"]
    SUP --> LEASEOK
```

Config keys that affect PCP/NAT-PMP: `enable_pcp_pmp` (also `enable_natpmp`), `min_lifetime`, `max_lifetime`, `pcp_allow_thirdparty`, `pcp_min_lifetime_override`, `lease_file`, `lease_file6`, `listening_ip`, `ext_ifname`, `allow`/`deny` rules (ACL).

## 4. Request flow: PCP MAP with FILTER

```mermaid
sequenceDiagram
    participant C as PCP client
    participant N as natpmp.c
    participant P as pcpserver.c
    participant F as pcp_filter (backend)
    participant B as firewall backend
    participant L as pcp_lease.c

    C->>N: UDP 5351 request (version 2, MAP + FILTER)
    N->>P: ProcessIncomingPCPPacket
    P->>P: validate header, options, ACL, lifetime,<br/>THIRD_PARTY, PREFER_FAILURE
    alt invalid or refused
        P-->>C: error response, notice-level reject log
    else accepted
        P->>F: pcp_filter_begin(addr, port, proto, ifname, filters)
        F->>B: merge with current peers, install rules
        P->>B: add / renew mapping (or pinhole for IPv6)
        alt everything succeeded
            P->>F: pcp_filter_finish(update, commit)
            P->>L: pcp_lease_note_map(nonce, ...)
            P->>L: pcp_lease_changed()
            P-->>C: success, assigned external port, lifetime
        else failure
            P->>F: pcp_filter_finish(update, rollback)
            P-->>C: error response
        end
    end
```

On error the previous peers are restored, so a filtered mapping never exists without its filters.

## 5. Mapping lifecycle and the lease file

```mermaid
stateDiagram-v2
    [*] --> Active: MAP / PEER / NAT-PMP request
    Active --> Active: renewal (same nonce keeps "since")
    Active --> Active: new FILTER peers merged
    Active --> Deleted: lifetime 0 request
    Active --> Expired: lifetime elapsed
    Deleted --> [*]: rules removed, lease file rewritten
    Expired --> [*]: rules removed, lease file rewritten
    Active --> Restored: daemon restart, pcp_lease_load()
    Restored --> Active: rules recreated with their peers
```

### Where each kind of state lives

```mermaid
flowchart LR
    subgraph kernel["Firewall (source of truth for rules)"]
        R1["MAP rules (NAT / pinhole)"]
        R2["FILTER peer rules"]
        R3["PEER rules"]
    end
    subgraph mem["Daemon memory"]
        M1["peer_lease: PEER expiry"]
        M2["pcp_lease: nonce, since,<br/>prefer_failure, label"]
    end
    subgraph disk["Disk"]
        D1["lease_file / lease_file6<br/>UPnP mappings only"]
        D2["lease_file.pcp<br/>PCP and NAT-PMP mappings"]
    end
    kernel -->|"listed by backend<br/>pcp_lease_maps"| M2
    M2 -->|"pcp_lease_save"| D2
    D2 -->|"pcp_lease_load at start"| kernel
    M1 --> kernel
    D1 -.->|"pcp_lease_owns() keeps PCP / NAT-PMP<br/>entries out of this file"| D2
```

### PCP lease file format (`PCP-LEASE 1`)

The file is `<lease_file>.pcp`. The UPnP lease file has one line per mapping and cannot hold the PCP options (FILTER peers, nonce, PREFER_FAILURE) or PEER mappings, so mappings made by PCP and NAT-PMP are kept here instead. A mapping owned by PCP / NAT-PMP is recognised by its firewall description (`PCP MAP <24 hex>` or `NAT-PMP <eport> <proto>`).

- The first line is the header `PCP-LEASE 1`. Then one line per record.
- Every line has the same 15 fields, so the columns are the same for all kinds of line.
- Fields are separated by `|` (IPv6 addresses contain `:`). A field that does not apply is `NA`.
- The first field is the kind of line: `PCP-M`, `NAT-PMP`, `PCP-F` or `PCP-P`.
- The file is rewritten after a PCP or NAT-PMP request or an expiry changed something, at most once every `PCP_LEASE_SAVE_DELAY` (2) seconds: `pcp_lease_changed()` writes it at once if the last save is that old, else marks a save pending, which the main loop writes when it is due (`pcp_lease_flush()`). A pending save is also written at shutdown. A crash loses at most the changes of the last 2 seconds, which the clients renew.
- At startup `pcp_lease_load()` recreates the mappings from it, once the PCP and NAT-PMP sockets are open: a request that comes during the restore waits in the socket instead of being refused.

```
kind|proto|eport|family|iaddr|iport|ifname|nonce|prefer_failure|since|expiry|eaddr|raddr|rport|label
```

| # | Field | `PCP-M` / `NAT-PMP` | `PCP-F` | `PCP-P` |
|---|---|---|---|---|
| 1 | kind | `PCP-M` or `NAT-PMP` | `PCP-F` | `PCP-P` |
| 2 | proto | `TCP` or `UDP` | same | same |
| 3 | eport | External port. For an IPv6 pinhole it equals `iport`. | same | same |
| 4 | family | `IPv4` or `IPv6`  | same | same |
| 5 | iaddr | Internal address | same | same |
| 6 | iport | Internal port | same | same |
| 7 | ifname | External interface, `NA` if unknown | `NA` | same as MAP |
| 8 | nonce | The 24 hex digits sent on the wire. `NA` for NAT-PMP. | Same as MAP | same as MAP |
| 9 | prefer_failure | `1` if PREFER_FAILURE was present, else `0` | `NA` | same as MAP |
| 10 | since | Unix time the mapping was first created. A renewal with the same nonce keeps it. | `NA` | same as MAP |
| 11 | expiry | Unix time of expiry, `0` for none | `NA` | same as MAP |
| 12 | eaddr | External address when the line was written: the external interface address (or `use_ext_ip_addr`) for IPv4, the internal address for an IPv6 pinhole (no translation). For the user to read, not used to restore. | `NA` | IPv4: translated address, `NA` if unknown (the address of the external interface is used). IPv6: the internal address (a pinhole, no translation). |
| 13 | raddr | `NA` | Allowed source as `addr/prefix` (IPv4 prefix 0-32, IPv6 prefix 1-128) | Remote peer address |
| 14 | rport | `NA` | Allowed source port, `0` for any | Remote peer port |
| 15 | label | DESCRIPTION option (RFC 7220), `NA` if none. Always the last field. | `NA` | same as MAP |

- A `PCP-F` line is one FILTER peer of the filtered MAP that has the same nonce. A filtered MAP is never created without its `PCP-F` lines.
- The label is escaped: `\\`, `\|`, `\n`, `\r`, `\xHH` for other control characters. A label that is really `NA` is written `\x4EA`, so it is not taken for none.

Example (values illustrative):

```
PCP-LEASE 1
PCP-M|TCP|40001|IPv4|192.168.1.10|22|eth1|00112233445566778899aabb|0|1730600000|1730603600|198.51.100.1|NA|NA|ssh
PCP-F|TCP|40001|IPv4|192.168.1.10|22|NA|00112233445566778899aabb|NA|NA|NA|NA|203.0.113.0/24|0|NA
NAT-PMP|UDP|40002|IPv4|192.168.1.11|5060|eth1|NA|0|1730600100|1730601900|198.51.100.1|NA|NA|NA
```

## 5b. Client recovery (RFC 6887 section 8.5, RFC 6886 section 3.3)

Clients detect that the server lost its state through the epoch time, and then renew their mappings ("fast recovery"). Both PCP and NAT-PMP carry the epoch (seconds since the server started or lost state) in every response and in the announce.

- A client compares the epoch with its own estimate. If the server's epoch went backwards or advanced too little, the server restarted or lost state, and the client sends renewals for all its mappings at once, without waiting for half the lifetime.
- The daemon resets the epoch when the external address changes (`PCPPublicAddressChanged`, RFC 6887 section 8.5) and sends an unsolicited ANNOUNCE on 224.0.0.1 / ff02::1 port 5350 at startup and on that change. That triggers the clients' renewals.
- A renewal with the same nonce is treated as a renewal, so `since` is kept. A renewal for a mapping that does not exist is created as a new one.

So the lease file and client recovery overlap: the lease file restores mappings (with FILTER peers and PEER mappings, which a client renewal would only rebuild from the request options), and fast recovery covers whatever the lease file did not restore. After a restart the clients' renewals re-send the FILTER options, so the peers converge to the clients' view (merged per RFC 6887 section 13.3).

## 6. Backend contract

Each backend (nft, pf) provides the same functions, used through the `pcp_filter_*` names:

| Function | Purpose |
|---|---|
| `pcp_filter_begin / finish` | Apply FILTER options to a mapping or pinhole, two-phase with commit or rollback. |
| `pcp_filter_delete` | Forget the peers of a deleted mapping. |
| `pcp_filter_get` | Read the peers (none means any source is allowed). |
| `pcp_lease_maps` / `pcp_lease_peers` | List the firewall mappings, or the IPv4 PEER mappings, for the lease file, in one pass over the rules. |
| `pcp_find_map` / `pcp_find_peer` | One-pass lookup of an IPv4 mapping or PEER mapping. |
| PEER add / delete | PEER rules, with expiry through `peer_lease.c`. |

Backend differences: nft implements IPv4 mappings and IPv6 pinholes, with an interface-aware FILTER. A filtered mapping has a regular chain of its own (an accept per peer, then a drop); one base chain per IP version on the forward hook (`pcp-filter-v4`, `pcp-filter-v6`, priority -1) dispatches to it with a verdict map on `daddr . l4proto . dport` (`pcp-filter-map4`, `pcp-filter-map6`), so a forwarded packet costs one lookup whatever the number of filtered mappings. pf has pinholes in `pfpinhole.c`, and its PCP code is in `pfpcp.c` (on 15.x, PEER NAT rules in an anchor are ignored by pf, see the KNOWN LIMITATION in the source).

## 6b. Scaling: indexes and caches

Every lookup used to walk the whole ruleset (a netlink dump on nft, one ioctl per rule on pf), and the lease file was rewritten after each request, so the cost per request grew with the number of mappings. These are the structures that keep it flat:

| Data | Where | Kind | Beyond its size |
|---|---|---|---|
| PCP lease state (nonce, since, prefer_failure, label) | `pcp_lease.c` | hash, 4,096 buckets, chained | chains grow: about 2.4 entries per bucket at 10k mappings |
| Duplicate rules during a save | `pcp_lease.c` (`save_ctx`) | open addressing, resized to at least 2 x N | stays O(1) |
| PEER lease expiry | `peer_lease.c` | hash, 4,096 buckets, chained, on the two endpoints | as above |
| FILTER policies | `nftnlrdr_misc.c` | hash, 1,024 buckets, chained; read from the kernel once, then authoritative | about 10 per bucket at 10k filtered mappings |
| Timestamps during `nft_pcp_lease_maps()` | `nftnlrdr.c` | open addressing, built once per walk | stays O(1) |
| Rule cache (`head_redirect`, `head_filter`, `head_peer`) | `nftnlrdr_misc.c` | linked lists, kept valid when a rule is added | O(N) walk in memory per lookup, no index yet |
| `timestamp_list` (`get_timestamp()`) | `nftnlrdr.c` | linked list | O(N) walk, outside the lease save |
| Pinhole uids | `pf/pfpinhole.c` | bitmap of the 65,536 uids, built by one walk | exact |
| FILTER dispatch on the packet path | kernel (nft) | verdict map (hash) | one lookup per packet |

Notes:

- A chained table compares the full key, so going beyond its number of buckets never gives a wrong match: it only makes the chains longer. The fixed tables degrade slowly and only hurt around 100k entries.
- The nft rule cache is no longer invalidated by an added rule: the rule is sent with `NLM_F_ECHO` and the kernel's copy (with its handle) goes into the cache. A delete, an error or a missing echo still invalidate it, and the next lookup dumps the chain again. The packet and byte counters in the cache are refreshed only then.
- After a failed netlink transaction `send_batch()` reads the rest of the kernel's answers, so the next request on the shared socket does not take them for its own.
- A save of the lease file is one pass over the rules (`pcp_lease_maps()`, `pcp_lease_peers()`), with the external address looked up once, and at most one save every 2 seconds.
- pf: the rules of a filtered mapping are deleted, and a pinhole group renewed or deleted, in one walk, the rules being removed from the last index (not yet tested on FreeBSD).
- Measured on Linux (nft, Docker), 500 flows with 40 FILTER peers each: 0.7 s to create them, 0.7 s to restore 6,680 peers at startup, 1 to 6 s for the clients to be answered again after a restart. Before: 1,209 of 2,000 flows in 900 s.

## 7. Testing layout

| Level | Location |
|---|---|
| Unit-style programs | `testportinuse`, `testnftnlrdr`, `testobsdrdr`, `testpfpinhole`, `testiptcrdr_peer`, and others per backend. |
| Protocol suite (Docker) | `tests/pcp_pmp/` (`run_pcp_natpmp_cases.py`, the lease restart and expiry scripts). |
| End to end | `tests/pcp_e2e/` (`run-docker.sh` for nft, `run-freebsd.sh` for pf). |

The `tests/` directories are local to the development checkout and not in the repository yet. The end-to-end cases set `pcp_min_lifetime_override` to a few seconds to see mappings expire quickly.

## 8. Known gaps

- DESCRIPTION option (RFC 7220) is not parsed.
- The IPv6 PEER is a pinhole to the remote endpoint (no NAT66). It is kept in the PCP lease file as a `PCP-P` line with family `IPv6`, and lifetime 0 deletes it. Checked end to end with nft and with pf on FreeBSD 14.5.
- `CreatePCPPeer()` in `pcpserver.c` has a `TODO` for a UPnP-side function for PEER; PEER filtering has no shared function yet.
- Reject-reason logging is not yet in the same format as the UPnP / NAT-PMP logs.
- `get_pinhole_uid_by_index` is a stub on nft and absent on pf.
- The iptables backend has no FILTER and no PCP lease file.
- FreeBSD 15.x pf ignores anchored NAT, so PCP PEER NAT fails there. The NAT66 PEER case fails on 14.5 too.

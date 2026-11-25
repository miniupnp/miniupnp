# miniupnpd fuzz targets

In-process fuzz targets for the request parsers that a LAN client can reach. They complement the
integration suites (`pcp_wire`, `upnp_wire`, ...): those check behaviour against the RFCs, these
look for memory-safety and undefined-behaviour bugs with coverage-guided fuzzing under
AddressSanitizer and UndefinedBehaviorSanitizer.

| Target | Code under test | Input |
|---|---|---|
| [`fuzz_http`](fuzz_http.c) | `upnphttp.c` (request line, headers, chunked bodies, SUBSCRIBE/UNSUBSCRIBE), `upnpsoap.c` (every IGD action), `upnpreplyparse.c`, `minixml.c`, `upnpdescgen.c` | Raw bytes sent to the HTTP port |
| [`fuzz_pcpnatpmp`](fuzz_pcpnatpmp.c) | `pcpserver.c` (MAP, PEER, ANNOUNCE, SADSCP, options), `natpmp.c` | Byte 0 picks NAT-PMP / PCP over IPv4 / PCP over IPv6 and allow_third_party, the rest is the UDP payload |

The real request handlers run unchanged. Only the back-ends are replaced:
[`fuzz_stubs.c`](fuzz_stubs.c) stubs the firewall, interface and event functions with a small fixed
table of mappings and pinholes, and `fuzz_http` wraps `recv`/`send`/`close` (GNU ld `--wrap`) so
`Process_upnphttp()` reads its input from memory. `FUZZ_CHUNK=n` makes `recv()` return at most n
bytes per call, to exercise partial reads.

## Build

Linux, clang with libFuzzer. Run from the `miniupnpd` directory:

```sh
./configure --igd2 --ipv6 --leasefile --vendorcfg --pcp-peer --portinuse --firewall=iptables
tests/fuzz/build.sh                       # CC=clang by default
CC=afl-clang-fast tests/fuzz/build.sh     # AFL++
```

Build dependencies are those of miniupnpd (`libuuid`, OpenSSL, the iptables headers for `configure`).
Define `PCP_SADSCP` in `config.h` to also fuzz the SADSCP opcode.

## Run

```sh
cd tests/fuzz
out/fuzz_http -dict=out/fuzz_http.dict corpus-http/ corpus/http
out/fuzz_pcpnatpmp -dict=out/fuzz_pcpnatpmp.dict corpus-pcp/ corpus/pcp
```

The first directory collects new inputs; `corpus/` holds the seeds: one request per IGD action,
eventing and description requests, a chunked request, and NAT-PMP / PCP MAP, PEER, ANNOUNCE and
SADSCP packets with options. To reproduce a crash without libFuzzer:

```sh
FUZZ_DEBUG=1 out/fuzz_http_repro crash-file          # FUZZ_DEBUG prints the HTTP reply
out/fuzz_pcpnatpmp_repro crash-file
```

## OSS-Fuzz

`build.sh` uses `CC`, `CFLAGS`, `SANITIZER_FLAGS`, `OUT` and `LIB_FUZZING_ENGINE` from the
environment when they are set, so it can be called from an OSS-Fuzz `build.sh`.

See [status.md](status.md) for the latest results.

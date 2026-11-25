#!/bin/sh
# Build the miniupnpd fuzz targets. Run from the miniupnpd directory after ./configure:
#   ./configure --igd2 --ipv6 --leasefile --vendorcfg --pcp-peer --portinuse --firewall=iptables
#   tests/fuzz/build.sh
# Outputs in tests/fuzz/out/:
#   fuzz_http, fuzz_pcpnatpmp              libFuzzer + ASan + UBSan (CC=clang, default)
#   fuzz_http_repro, fuzz_pcpnatpmp_repro  ASan + UBSan, run on files (no libFuzzer)
# AFL++: CC=afl-clang-fast tests/fuzz/build.sh (afl-clang-fast accepts -fsanitize=fuzzer).
# OSS-Fuzz: CC, CFLAGS and LIB_FUZZING_ENGINE from the environment are used when set.
# Linux only: recv/send/close are wrapped with GNU ld --wrap.
set -e
CC=${CC:-clang}
D=tests/fuzz
OUT=${OUT:-$D/out}
mkdir -p "$OUT"
SAN=${SANITIZER_FLAGS:--fsanitize=address,undefined -fno-sanitize-recover=undefined}
ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}
CF="${CFLAGS:--g -O1} -D_GNU_SOURCE -I. -Wno-unused-parameter"
HTTP_SRC="upnphttp.c upnpsoap.c upnpreplyparse.c minixml.c upnputils.c upnpglobalvars.c upnppermissions.c upnpdescgen.c"
PCP_SRC="pcpserver.c natpmp.c pcplearndscp.c upnputils.c upnpglobalvars.c upnppermissions.c"
WRAP="-Wl,--wrap=recv,--wrap=send,--wrap=close"
LIBS="-luuid -lssl -lcrypto"

$CC $CF $SAN $ENGINE $HTTP_SRC $D/fuzz_stubs.c $D/fuzz_http.c $WRAP $LIBS -o "$OUT/fuzz_http"
$CC $CF $SAN $ENGINE $PCP_SRC $D/fuzz_stubs.c $D/fuzz_pcpnatpmp.c $LIBS -o "$OUT/fuzz_pcpnatpmp"
if [ -z "$LIB_FUZZING_ENGINE" ]; then
	$CC $CF $SAN $HTTP_SRC $D/fuzz_stubs.c $D/fuzz_http.c $D/standalone_main.c $WRAP $LIBS -o "$OUT/fuzz_http_repro"
	$CC $CF $SAN $PCP_SRC $D/fuzz_stubs.c $D/fuzz_pcpnatpmp.c $D/standalone_main.c $LIBS -o "$OUT/fuzz_pcpnatpmp_repro"
fi
cp $D/http.dict "$OUT/fuzz_http.dict"
cp $D/pcp.dict "$OUT/fuzz_pcpnatpmp.dict"
echo "built in $OUT"

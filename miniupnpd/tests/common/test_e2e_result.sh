#!/bin/sh
# The self-test of e2e_result: the result always, the total of the one column when a report is given.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
. "$HERE/e2e_lib.sh"
cat >"$WORK/status.md" <<'REPORT'
- **linux-igd1**: **9 PASS**, **0 XFAIL**, **9 FAIL**, **9 SKIP** (updated 2026; branch `a`)
- **freebsd**: **74 PASS**, **29 XFAIL**, **8 FAIL**, **207 SKIP** (updated 2026; ipv4: target `b`)
REPORT
expect() { [ "$1" = "$2" ] || { echo "$3: expected $2, got $1" >&2; exit 1; }; }

expect "$(e2e_result 0)" "Result: passed" "passed"
expect "$(e2e_result 1)" "Result: FAILED" "failed"
expect "$(e2e_result 1 "$WORK/status.md" freebsd)" "Total: 74 PASS, 29 XFAIL, 8 FAIL, 207 SKIP
Result: FAILED" "total"
expect "$(e2e_result 0 "$WORK/status.md" absent)" "Result: passed" "no such column"
echo "PASS e2e_result"

#!/bin/sh
# The self-test of reserve_slot: a held slot is skipped, a released one is free again, a slot with
# its subnet or a busy resource is not free. Docker is replaced by a stub reporting $SUBNETS.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export PCP_E2E_LOCK_DIR="$WORK/locks"
cat >"$WORK/docker" <<'STUB'
#!/bin/sh
case "$2" in ls) echo stub ;; inspect) echo "${SUBNETS:-}" ;; esac
STUB
chmod +x "$WORK/docker"
export DOCKER="$WORK/docker"
export HERE

reserve() { sh -c '. "$HERE/e2e_lib.sh"
  plan() { e2e_address_plan "$1"; [ "$1" != "${BUSY:-}" ] || SLOT_BUSY=busy; }
  reserve_slot plan "${1:-}" ${3:-} 2>/dev/null; echo "$SLOT"; [ -z "${2:-}" ] || cat "$2"' sh "$@"; }
expect() { [ "$1" = "$2" ] || { echo "$3: expected $2, got $1" >&2; exit 1; }; }

expect "$(reserve)" 1 "first free slot"
mkfifo "$WORK/hold"
{ reserve "" "$WORK/hold" >"$WORK/held"; } &
holder=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  [ -s "$WORK/held" ] && break
  sleep 0.1
done
expect "$(cat "$WORK/held")" 1 "the holder"
expect "$(reserve)" 2 "held slot skipped"
if reserve 1 >/dev/null 2>&1; then echo "a held slot was given out" >&2; exit 1; fi
: >"$WORK/hold"
wait "$holder"
expect "$(reserve)" 1 "released slot"
expect "$(SUBNETS=6.18.1.0/24 reserve)" 2 "slot with its subnet skipped"
expect "$(SUBNETS=6.18.1.0/24 reserve 1 "" nocheck)" 1 "nocheck takes it"
expect "$(BUSY=1 reserve)" 2 "busy resource skipped"
expect "$(SUBNETS=172.28.1.0/24 reserve)" 2 "slot with its LAN subnet skipped"

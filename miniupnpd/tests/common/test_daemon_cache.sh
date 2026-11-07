#!/bin/sh
# The self-test of e2e_image and e2e_build_daemon: the same source is compiled once, also by runs side
# by side, and other source or flags get a directory of their own. Docker is replaced by a stub which
# counts its builds.
set -eu

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export PCP_E2E_LOCK_DIR="$WORK/locks"
export COUNTS="$WORK/counts"
mkdir "$COUNTS" "$WORK/images"
mkdir -p "$WORK/tree/miniupnpd/tests" "$WORK/context"
echo one >"$WORK/tree/miniupnpd/source.c"
echo FROM >"$WORK/context/Dockerfile"
cat >"$WORK/docker" <<'STUB'
#!/bin/sh
case "$1" in
image) [ -e "$COUNTS/image" ] ;;
build) sleep 0.2; [ ! -e "$COUNTS/image" ] || echo "built twice" >>"$COUNTS/errors"; echo >>"$COUNTS/image" ;;
run)
  cat >/dev/null
  sleep 0.2
  echo >>"$COUNTS/daemon"
  out=$(for a in "$@"; do case "$a" in *:/out) echo "${a%:/out}" ;; esac; done)
  [ "${FAIL_BUILD:-0}" = 0 ] || { echo "the compiler said no"; exit 1; }
  : >"$out/miniupnpd"; chmod +x "$out/miniupnpd"
  ;;
esac
STUB
chmod +x "$WORK/docker"
export DOCKER="$WORK/docker" ROOT="$WORK/tree" HERE WORK

build() { sh -c 'set -eu; . "$HERE/e2e_lib.sh"
  e2e_image test-image "$WORK/context/Dockerfile"; e2e_build_daemon "$@"; echo "$DAEMON_DIR"' sh "$@" 2>>"$WORK/log"; }
expect() { [ "$1" = "$2" ] || { echo "$3: expected $2, got $1" >&2; exit 1; }; }
count() { wc -l <"$COUNTS/$1" | tr -d ' '; }

first=$(build)
expect "$(count daemon)" 1 "first build"
expect "$(build)" "$first" "same source"
expect "$(count daemon)" 1 "same source is compiled once"
expect "$(build)" "$first" "output in the tree does not count"
touch "$WORK/tree/miniupnpd/source.o" "$WORK/tree/miniupnpd/tests/new" "$WORK/tree/miniupnpd/source.c"
expect "$(build)" "$first" "objects, tests and a new mtime do not count"
expect "$(count daemon)" 1 "nothing to compile after those"

flags=$(build --other)
[ "$flags" != "$first" ] || { echo "other flags share a daemon" >&2; exit 1; }
expect "$(build '')" "$(build '')" "empty flags are flags"

echo two >"$WORK/tree/miniupnpd/source.c"
second=$(build)
[ "$second" != "$first" ] || { echo "other source shares a daemon" >&2; exit 1; }

# runs side by side: one image and one daemon between them
rm -f "$COUNTS/image" "$COUNTS/daemon"
echo three >"$WORK/tree/miniupnpd/source.c"
for n in 1 2 3 4; do build >"$WORK/side-$n" & done
wait
expect "$(count image)" 1 "side by side: image"
expect "$(count daemon)" 1 "side by side: daemon"
expect "$(sort -u "$WORK"/side-* | wc -l | tr -d ' ')" 1 "side by side: directory"
[ ! -e "$COUNTS/errors" ] || { cat "$COUNTS/errors" >&2; exit 1; }

# a failed build is reported and leaves nothing to reuse
echo four >"$WORK/tree/miniupnpd/source.c"
if FAIL_BUILD=1 build >/dev/null; then echo "a failed build passed" >&2; exit 1; fi
grep -q 'the compiler said no' "$WORK/log" || { echo "the compiler output is not shown" >&2; exit 1; }
[ -x "$(build)/miniupnpd" ] || { echo "no daemon after the retry" >&2; exit 1; }

echo "PASS daemon cache"

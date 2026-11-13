#!/bin/sh
# FreeBSD counterpart of run-docker.sh: the router is a FreeBSD QEMU VM running
# miniupnpd with pf; the LAN client and the three WAN traffic agents are Linux
# Docker containers on LAN/WAN subnets of their own.
#
# Fixture slots: runs side by side (and beside run-docker.sh). --slot N or
# PCP_E2E_SLOT=N (1-128; default the first free one, slot 1 for a kept fixture) picks the address plan (e2e_address_plan in
# ../common/e2e_lib.sh: LAN 172.28.N.0/24 + 2001:db8:1:N::/64, WAN 6.18.N.0/24 +
# 2001:db8:9000:N::/64), the SSH port (2230+N), the fixture name (slotN) and the Docker names.
#
# No root is needed. A relay container (freebsd/qemu_docker_l2_relay.py) sits on both Docker
# bridges and forwards raw Ethernet frames to the VM over QEMU stream netdevs
# (vtnet1 = LAN, vtnet2 = WAN), so the VM is just another host on each bridge.
#
# Requires: docker, qemu-system-x86_64 (>= 7.2), qemu-img, xz, curl, ssh, xorriso
# (or genisoimage/mkisofs).
#
# Environment: PCP_TEST_FREEBSD_VERSION (or --freebsd-version; default the newest release),
# PCP_TEST_FREEBSD_CACHE, PCP_TEST_FREEBSD_MEMORY, PCP_TEST_FREEBSD_SSH_PORT (as for
# ../common/freebsd_vm.sh, whose cached prepared image is shared; the VM steps are those of
# ../common/vm_lib.sh),
# PCP_E2E_KEEP=1, PCP_E2E_ARTIFACT_DIR, E2E_STATUS_FILE (default status.md
# beside this script: the freebsd column of the report run-docker.sh fills the linux
# column of), DOCKER.
#
# Keeping the fixture between runs (the VM, the Docker networks, the relay and the
# peers, and the build tree in the VM), so a later run copies in only what changed:
#
#   run-freebsd.sh up              start the fixture and the router, then stop
#   run-freebsd.sh [run] --reuse   use the fixture of `up` (or start one), copy in the
#                                  changes, rebuild incrementally, restart the daemon from
#                                  a clean state, run the cases and leave the fixture up
#   run-freebsd.sh [run] --keep-vm start a fresh fixture, run, and leave it up
#   run-freebsd.sh status | ssh [command] | down
#
#   --slot N                                 fixture slot 1-128 (see above)
#   --from sync|build|daemon|cases|restart   start at that stage (default with --reuse: sync)
#   --rebuild                                configure again and rebuild everything
#   --no-build                               do not copy or build, use the tree in the VM
#   --reset                                  go back to the checkpoint of the first start (the
#                                            tree built, the router up) before the stages
#   --no-restart | --only-restart            skip / only run the restart check
#
# The fixture lives in $PCP_TEST_FREEBSD_CACHE/e2e-vm/$PCP_E2E_VM_NAME (default name
# "slotN"; SSH port PCP_E2E_FREEBSD_SSH_PORT, default 2230+N, so it does not clash with
# the VM of ../common/freebsd_vm.sh from 2401). Without these options a run is
# fresh and leaves nothing behind.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
DIR=$ROOT/miniupnpd/tests/pcp_e2e
PMP=$ROOT/miniupnpd/tests/pcp_wire
COMMON=$ROOT/miniupnpd/tests/common
DOCKER=${DOCKER:-docker}
SUFFIX=$$
LAN=pcp-e2e-fbsd-lan-$SUFFIX
WAN=pcp-e2e-fbsd-wan-$SUFFIX
RELAY=pcp-e2e-fbsd-relay-$SUFFIX
ALLOW=pcp-e2e-fbsd-allow-$SUFFIX
DENY=pcp-e2e-fbsd-deny-$SUFFIX
THIRD=pcp-e2e-fbsd-third-$SUFFIX
RUNNER=pcp-e2e-fbsd-runner-$SUFFIX
KEEP=${PCP_E2E_KEEP:-0}
# the router daemon runs with enable_upnp=yes, so the UPnP cases can run
E2E_UPNP=1
ARTIFACTS=${PCP_E2E_ARTIFACT_DIR:-$ROOT/.tmp/pcp-e2e}
STATUS_FILE=${E2E_STATUS_FILE:-$DIR/status.md}
E2E_PLATFORM=freebsd
RUN_ID=$(date -u +%Y-%m-%dT%H-%M-%SZ)
case "$ARTIFACTS" in /*) ;; *) ARTIFACTS=$ROOT/$ARTIFACTS ;; esac
CACHE=${PCP_TEST_FREEBSD_CACHE:-"$HOME/.cache/miniupnpd-pcp-test"}
MEMORY=${PCP_TEST_FREEBSD_MEMORY:-2048}
# The router of the fixture. run-debian-iptables.sh sets debian-iptables.
ROUTER=${PCP_E2E_ROUTER:-freebsd-pf}
ROUTER_SCRIPT=miniupnpd/tests/pcp_e2e/freebsd/pf-router.sh
VM_USER=freebsd
LAN_IF=vtnet1
WAN_IF=vtnet2
PREPARE=$COMMON/freebsd/prepare.sh
if [ "$ROUTER" = debian-iptables ]; then
  ROUTER_SCRIPT=miniupnpd/tests/pcp_e2e/debian/iptables-router.sh
  VM_USER=debian
  LAN_IF=lan0
  WAN_IF=wan0
  VERSION=13
  PREPARE=$DIR/debian/prepare.sh
  E2E_PLATFORM=debian-iptables
fi
# the name of the router in the report, once VERSION is known (the boot looks up the newest)
set_router_name() {
  if [ "$ROUTER" = debian-iptables ]; then ROUTER_NAME="Debian $VERSION iptables"; else ROUTER_NAME="FreeBSD $VERSION pf"; fi
}
STATUS=0
EXECUTED=0
KEY=

. "$ROOT/miniupnpd/tests/common/e2e_lib.sh"
# ssh may be interactive: its prompts have no newline for the timestamp filter to see
for arg in "$@"; do
  case "$arg" in ssh) PCP_E2E_TIMESTAMPS=0 ;; esac
done
e2e_timestamp_output "$@"

COMMAND=run
REUSE=${PCP_E2E_REUSE:-0}
SLOT=${PCP_E2E_SLOT:-}
KEEP_VM=${PCP_E2E_KEEP_VM:-0}
FROM=
REBUILD=0
NO_BUILD=0
RESET=0
SSH_ARGS=
argc=$#
while [ "$argc" -gt 0 ]; do
  arg=$1; shift; argc=$((argc - 1))
  case "$arg" in
    up|down|status) COMMAND=$arg ;;
    ssh) COMMAND=ssh; SSH_ARGS="$*"; set --; argc=0 ;;
    run) ;;
    --reuse) REUSE=1 ;;
    --slot)
      [ "$argc" -ge 1 ] || { echo "--slot requires a number (1-128)" >&2; exit 2; }
      SLOT=$1; shift; argc=$((argc - 1))
      ;;
    --keep-vm) KEEP_VM=1 ;;
    --rebuild) REBUILD=1 ;;
    --no-build) NO_BUILD=1 ;;
    --reset) RESET=1 ;;
    --no-restart) PCP_E2E_RESTART=0 ;;
    --only-restart) PCP_E2E_ONLY_RESTART=1 ;;
    --from)
      [ "$argc" -ge 1 ] || { echo "--from requires a stage" >&2; exit 2; }
      FROM=$1; shift; argc=$((argc - 1))
      case "$FROM" in sync|build|daemon|cases|restart) ;; *) echo "unknown stage: $FROM" >&2; exit 2 ;; esac
      ;;
    *) set -- "$@" "$arg" ;;
  esac
done
e2e_parse_args "$@"
# --freebsd-version or PCP_TEST_FREEBSD_VERSION; empty: the newest (vmlib_freebsd_image)
[ "$ROUTER" = debian-iptables ] || VERSION=${PCP_TEST_FREEBSD_VERSION:-}
# shellcheck disable=SC1091
. "$COMMON/vm_lib.sh"

# Keep mode: the fixture outlives the script and is found again by a later run.
KEEP_MODE=0
if [ "$COMMAND" != run ] || [ "$REUSE" = 1 ] || [ "$KEEP_VM" = 1 ]; then KEEP_MODE=1; fi
# A fresh run takes a free slot; a kept fixture is named by its slot and may hold its own networks.
if [ "$KEEP_MODE" = 1 ]; then
  reserve_slot e2e_address_plan "${SLOT:-1}" nocheck
else
  reserve_slot e2e_address_plan "$SLOT"
fi
e2e_image miniupnpd-pcp-e2e-peer "$DIR/freebsd/Dockerfile.peer"
SSH_PORT=${PCP_E2E_FREEBSD_SSH_PORT:-$SLOT_SSH_PORT}
FIXTURE_READY=0
KEEP_LAN_PORT=
KEEP_WAN_PORT=
DETACH=
MONITOR=
set_names() {
  LAN=pcp-e2e-fbsd-lan-$SUFFIX
  WAN=pcp-e2e-fbsd-wan-$SUFFIX
  RELAY=pcp-e2e-fbsd-relay-$SUFFIX
  ALLOW=pcp-e2e-fbsd-allow-$SUFFIX
  DENY=pcp-e2e-fbsd-deny-$SUFFIX
  THIRD=pcp-e2e-fbsd-third-$SUFFIX
  RUNNER=pcp-e2e-fbsd-runner-$SUFFIX
}
if [ "$KEEP_MODE" = 1 ]; then
  VM_NAME=${PCP_E2E_VM_NAME:-slot$SLOT}
  [ "$ROUTER" = freebsd-pf ] || VM_NAME=${PCP_E2E_VM_NAME:-$ROUTER-slot$SLOT}
  case "$VM_NAME" in *[!A-Za-z0-9_.-]*|'') echo "invalid PCP_E2E_VM_NAME: $VM_NAME" >&2; exit 2 ;; esac
  STATE=$CACHE/e2e-vm/$VM_NAME
  mkdir -p "$STATE"
  SUFFIX=$VM_NAME
  set_names
  DETACH=setsid
  MONITOR="-monitor unix:$STATE/mon.sock,server=on,wait=off"
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$STATE/lock"
    flock -n 9 || { echo "another run uses the fixture $VM_NAME" >&2; exit 1; }
  fi
fi

vmlib_tools "$DOCKER" qemu-system-x86_64 qemu-img xz curl ssh ssh-keygen

RUN_DIR=$ARTIFACTS/freebsd-$RUN_ID-slot$SLOT
mkdir -p "$RUN_DIR"
if [ "$KEEP_MODE" = 1 ]; then WORK=$STATE; else WORK=$(mktemp -d); fi
QEMU_PID=
# Remove the whole fixture: the VM, the Docker side and the state directory.
teardown_all() {
  [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null || true
  "$DOCKER" rm -f "$RUNNER" "$ALLOW" "$DENY" "$THIRD" "$RELAY" >/dev/null 2>&1 || true
  "$DOCKER" network rm "$LAN" "$WAN" >/dev/null 2>&1 || true
  if [ "$KEEP_MODE" = 1 ]; then
    rm -f "$STATE/state.env" "$STATE/mon.sock" "$STATE/disk.qcow2" "$STATE/seed.iso" "$STATE/console.log" "$STATE/qemu.log"
    rm -rf "$STATE/seed"
  else
    rm -rf "${WORK:?}"
  fi
}
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ "$KEEP_MODE" = 1 ]; then
    "$DOCKER" rm -f "$RUNNER" >/dev/null 2>&1 || true
    # a fixture which did not get ready is not worth keeping
    if [ "$FIXTURE_READY" != 1 ] && [ "$COMMAND" != down ] && [ "$COMMAND" != status ] && [ "$COMMAND" != ssh ]; then
      teardown_all
    fi
  elif [ "$KEEP" != 1 ]; then
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null || true
    "$DOCKER" rm -f "$RUNNER" "$ALLOW" "$DENY" "$THIRD" "$RELAY" >/dev/null 2>&1 || true
    "$DOCKER" network rm "$LAN" "$WAN" >/dev/null 2>&1 || true
    rm -rf "${WORK:?}"
  else
    echo "Retaining fixture: VM pid ${QEMU_PID:-none} (ssh -p $SSH_PORT -i $KEY $VM_USER@127.0.0.1), work dir $WORK, $LAN $WAN $RELAY $ALLOW $DENY $THIRD" >&2
  fi
  exit "$result"
}
trap cleanup EXIT HUP
trap 'exit 130' INT
trap 'exit 143' TERM

published_port() { "$DOCKER" port "$RELAY" "$1/tcp" | head -n 1 | sed 's/.*://'; }

# ---- Docker side: peers and relay ---------------------------------------
docker_up() {
  "$DOCKER" rm -f "$RUNNER" "$ALLOW" "$DENY" "$THIRD" "$RELAY" >/dev/null 2>&1 || true
  "$DOCKER" network rm "$LAN" "$WAN" >/dev/null 2>&1 || true
  "$DOCKER" network create --driver bridge --ipv6 \
    --subnet "$LAN4.0/24" --gateway "$LAN4.254" \
    --subnet "${LAN6}/64" --gateway "${LAN6}ffff" "$LAN" >/dev/null
  "$DOCKER" network create --driver bridge --ipv6 \
    --opt com.docker.network.bridge.gateway_mode_ipv6=routed \
    --subnet "$WAN4.0/24" --gateway "$WAN4.254" \
    --subnet "${WAN6}/64" --gateway "${WAN6}ffff" "$WAN" >/dev/null

  # One relay process per bridge; the host reaches them through published ports.
  "$DOCKER" create --name "$RELAY" --network "$LAN" --ip "$LAN4.253" --ip6 "${LAN6}253" \
    --cap-add NET_RAW --volume "$DIR/freebsd:/relay:ro" \
    -p "127.0.0.1:${KEEP_LAN_PORT}:7001" -p "127.0.0.1:${KEEP_WAN_PORT}:7002" --entrypoint sh "$IMAGE" -c '
      iface() { ip -o -4 address | awk -v a="$1" "index(\$4, a) == 1 { print \$2; exit }"; }
      python3 /relay/qemu_docker_l2_relay.py --listen 7001 --control-port 7002 --iface "$(iface "$1")" &
      python3 /relay/qemu_docker_l2_relay.py --listen 7002 --control-port 7001 --iface "$(iface "$2")" &
      wait' pcp-e2e-relay "$LAN4.253/" "$WAN4.253/" >/dev/null
  "$DOCKER" network connect --ip "$WAN4.253" --ip6 "${WAN6}253" "$WAN" "$RELAY"
  "$DOCKER" start "$RELAY" >/dev/null
  LAN_PORT=$(published_port 7001)
  WAN_PORT=$(published_port 7002)

  start_agent() {
    name=$1; lan4=$2; lan6=$3; wan4=$4; wan6=$5
    "$DOCKER" create --name "$name" --network "$LAN" --ip "$lan4" --ip6 "$lan6" \
      --cap-add NET_ADMIN --volume "$ROOT/miniupnpd/tests/common:/common:ro" \
      --entrypoint python3 "$IMAGE" \
      /common/traffic_agent.py --host 0.0.0.0 --source4 "$wan4" \
      --source6 "$wan6" --route6 "${LAN6}/64" --gateway6 "${WAN6}1" \
      --route6 fd42:1::/64 --gateway6 "${WAN6}1" --peer-port 42100 >/dev/null
    "$DOCKER" network connect --ip "$wan4" --ip6 "$wan6" "$WAN" "$name"
    "$DOCKER" start "$name" >/dev/null
  }
  start_agent "$ALLOW" "$LAN4.12" "${LAN6}12" "$WAN4.2" "${WAN6}2"
  start_agent "$DENY" "$LAN4.13" "${LAN6}13" "$WAN4.130" "${WAN6}130"
  start_agent "$THIRD" "$LAN4.14" "${LAN6}14" "$WAN4.200" "${WAN6}200"
}

# ---- The router VM: image, seed, prepared image, boot (../common/vm_lib.sh) ----
vm_boot() {
  if [ "$ROUTER" = debian-iptables ]; then
    IMAGE_NAME=debian-$VERSION-generic-amd64.qcow2
    echo "Using Debian $VERSION"
    vmlib_lock
    if [ ! -f "$CACHE/$IMAGE_NAME" ]; then
      curl -fL --retry 3 -o "$CACHE/$IMAGE_NAME.part" \
        "https://cloud.debian.org/images/cloud/trixie/latest/$IMAGE_NAME"
      mv "$CACHE/$IMAGE_NAME.part" "$CACHE/$IMAGE_NAME"
    fi
    vmlib_unlock
  else
    vmlib_freebsd_image
  fi
  set_router_name
  vmlib_seed miniupnpd-pcp-test
  # the FreeBSD image is the one of ../common/freebsd_vm.sh: one prepared image for both
  if [ "$ROUTER" = freebsd-pf ]; then
    vmlib_prepared "$PREPARE" "prepared-$VERSION"
  else
    vmlib_prepared "$PREPARE" "prepared-$ROUTER-$VERSION"
  fi
  qemu-img create -q -f qcow2 -F qcow2 -b "$PREPARED" "$WORK/disk.qcow2" 10G
  # vtnet1 (LAN) and vtnet2 (WAN): QEMU stream netdevs to the relay container
  vmlib_boot "$WORK/disk.qcow2" \
    -netdev "stream,id=lan,addr.type=inet,addr.host=127.0.0.1,addr.port=$LAN_PORT,server=off,reconnect-ms=1000" \
    -device virtio-net-pci,netdev=lan,mac=52:54:00:41:00:01 \
    -netdev "stream,id=wan,addr.type=inet,addr.host=127.0.0.1,addr.port=$WAN_PORT,server=off,reconnect-ms=1000" \
    -device virtio-net-pci,netdev=wan,mac=52:54:00:09:00:01
  # lets a later run tell this VM from the one of ../common/freebsd_vm.sh
  TOKEN=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
  $SSH "$PRIV sh -c 'echo $TOKEN > /root/.pcp-e2e-token'"
  QEMU_START=$(ps -o lstart= -p "$QEMU_PID" 2>/dev/null || true)
}

vm() { $SSH "cd /root/miniupnp && $PRIV $*"; }

# ---- Copy the checkout into the VM ---------------------------------------
set_vm_clock() {
  [ "$ROUTER" = freebsd-pf ] || return 0
  $SSH "$PRIV date -u $(date -u +%Y%m%d%H%M.%S)" >/dev/null 2>&1 || true
}

sync_tree() {
  set_vm_clock
  # Tracked and unignored files, plus the e2e fixture files themselves: a local
  # exclude rule (e.g. .git/info/exclude ignoring miniupnpd/tests/) must not drop
  # freebsd/*.sh from the copy.
  checkout_files() {
    (cd "$ROOT" && git ls-files -co --exclude-standard -z
     cd "$ROOT" && find miniupnpd/tests/pcp_e2e/freebsd miniupnpd/tests/pcp_e2e/debian miniupnpd/tests/pcp_e2e/run-freebsd.sh miniupnpd/tests/common/freebsd_lib.sh \
       -type f ! -name '*.pyc' -print0) | sort -z -u
  }
  vmlib_copy "$ROOT" checkout_files -rlpc
}

# ---- Build miniupnpd and start the router --------------------------------
build_router() {
  # --rebuild: configure again, which also cleans
  if [ "$REBUILD" = 1 ]; then vm rm -f miniupnpd/.e2e-configure.stamp; fi
  vm sh $ROUTER_SCRIPT build
  $SSH "$PRIV cat /tmp/pcp-e2e/build.log" >"$RUN_DIR/daemon-build.log" 2>&1 || true
}

# The addresses and the main pf ruleset only when the VM does not have them yet (a fresh
# VM), then the daemon from a clean state.
start_router() {
  if ! vm sh $ROUTER_SCRIPT has-net "$LAN4" 2>/dev/null; then
    vm sh $ROUTER_SCRIPT net "$LAN4" "$LAN6" "$WAN4" "$WAN6"
  fi
  vm sh $ROUTER_SCRIPT start
}

# ---- Wait for the peers --------------------------------------------------
wait_for_peers() {
  # Wait until the VM and the Linux peers reach each other through the relay
  # (the VM pings out, which pf's stateful pass-out rule allows).
  ready=0
  for _attempt in $(seq 1 30); do
    if vm ping -c1 -t1 "$WAN4.2" >/dev/null 2>&1 &&
       vm ping -c1 -t1 "$LAN4.12" >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 1
  done
  [ "$ready" = 1 ] || { echo "$ROUTER_NAME router unreachable from the Linux peers (relay/QEMU netdev problem)" >&2; exit 1; }
}

# ---- The fixture: state file, liveness, stages ----------------------------
save_state() {
  {
    echo "QEMU_PID='$QEMU_PID'"
    echo "QEMU_START='$QEMU_START'"
    echo "SSH_PORT='$SSH_PORT'"
    echo "LAN_PORT='$LAN_PORT'"
    echo "WAN_PORT='$WAN_PORT'"
    echo "SUFFIX='$SUFFIX'"
    echo "VERSION='$VERSION'"
    echo "PRIV='$PRIV'"
    echo "TOKEN='$TOKEN'"
    echo "FIXTURE_ROOT='$ROOT'"
    echo "FIXTURE_SLOT='$SLOT'"
  } >"$STATE/state.env"
}
load_state() {
  [ -f "$STATE/state.env" ] || return 1
  # shellcheck disable=SC1091
  . "$STATE/state.env"
  if [ "${FIXTURE_SLOT:-}" != "$SLOT" ]; then
    echo "The fixture $VM_NAME was made for slot ${FIXTURE_SLOT:-? (an older run-freebsd.sh)}, not $SLOT;" \
      "remove it with: PCP_E2E_VM_NAME=$VM_NAME run-freebsd.sh --slot ${FIXTURE_SLOT:-1} down" >&2
    exit 2
  fi
  KEEP_LAN_PORT=$LAN_PORT
  KEEP_WAN_PORT=$WAN_PORT
  set_names
  set_router_name
  vmlib_ssh
}
# The VM is ours and running: the process is the one we started, and it answers with our token.
vm_alive() {
  [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null || return 1
  [ "$(ps -o lstart= -p "$QEMU_PID" 2>/dev/null)" = "$QEMU_START" ] || return 1
  [ "$($SSH 'cat /root/.pcp-e2e-token' 2>/dev/null)" = "$TOKEN" ] || return 1
}
docker_alive() {
  for name in "$RELAY" "$ALLOW" "$DENY" "$THIRD"; do
    [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ] || return 1
  done
  [ "$(published_port 7001)" = "$LAN_PORT" ] && [ "$(published_port 7002)" = "$WAN_PORT" ]
}
# Talk to the QEMU monitor: monitor_cmd "savevm clean". Prints the answer, fails on an error.
monitor_cmd() {
  python3 - "$STATE/mon.sock" "$1" <<'PY'
import socket, sys, time
sock = socket.socket(socket.AF_UNIX)
sock.settimeout(180)
sock.connect(sys.argv[1])
def read_until_prompt():
    data = b""
    while not data.endswith(b"(qemu) "):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", "replace")
read_until_prompt()
sock.sendall(sys.argv[2].encode() + b"\n")
answer = read_until_prompt()
print(answer)
sys.exit(1 if "rror" in answer else 0)
PY
}
# A clean state to go back to: the VM with the tree built and the router up.
save_checkpoint() {
  if monitor_cmd "savevm clean" >"$RUN_DIR/savevm.log" 2>&1; then echo "Checkpoint 'clean' saved"
  else echo "Could not save a checkpoint (see $RUN_DIR/savevm.log); --reset will not work" >&2; fi
}
free_port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
stage_rank() {
  case "$1" in sync) echo 1 ;; build) echo 2 ;; daemon) echo 3 ;; cases) echo 4 ;; restart) echo 5 ;; esac
}
stage_on() { [ "$(stage_rank "$1")" -ge "$START_RANK" ]; }

# A fresh fixture, or the one of an earlier run, then the stages from START_RANK on.
main_up() {
  START_RANK=0
  reuse_ok=0
  if [ "$KEEP_MODE" = 1 ] && [ "$REUSE" = 1 ] && load_state && vm_alive; then
    reuse_ok=1
    START_RANK=1
    [ -z "$FROM" ] || START_RANK=$(stage_rank "$FROM")
    if [ "$FIXTURE_ROOT" != "$ROOT" ]; then
      echo "Note: the fixture was last synced from $FIXTURE_ROOT, not $ROOT; a full rebuild follows" >&2
      REBUILD=1
    fi
    docker_alive || { echo "Recreating the Docker side of the fixture"; docker_up; }
    echo "Using the running $ROUTER_NAME VM (pid $QEMU_PID)"
    if [ "$RESET" = 1 ]; then
      echo "Going back to the checkpoint"
      monitor_cmd "loadvm clean" >"$RUN_DIR/loadvm.log" 2>&1 || { echo "loadvm failed:" >&2; cat "$RUN_DIR/loadvm.log" >&2; exit 1; }
      set_vm_clock
    fi
  else
    if [ "$KEEP_MODE" = 1 ]; then
      [ "$REUSE" != 1 ] || echo "No running fixture, starting a fresh one"
      load_state || true
      teardown_all
      KEEP_LAN_PORT=$(free_port)
      KEEP_WAN_PORT=$(free_port)
    fi
    docker_up
    vm_boot
    [ "$KEEP_MODE" != 1 ] || save_state
  fi
  if [ "$NO_BUILD" != 1 ]; then
    if stage_on sync; then sync_tree; fi
    if stage_on build; then build_router; fi
  fi
  if stage_on daemon; then start_router; fi
  wait_for_peers
  if [ "$KEEP_MODE" = 1 ] && [ "$reuse_ok" = 0 ]; then save_checkpoint; fi
  FIXTURE_READY=1
  [ "$KEEP_MODE" != 1 ] || save_state
}

case "$COMMAND" in
down)
  load_state || true
  teardown_all
  echo "Fixture $VM_NAME removed"
  exit 0
  ;;
status)
  if load_state; then
    cat "$STATE/state.env"
    if vm_alive; then echo "VM: running"; else echo "VM: not running"; fi
    if docker_alive; then echo "Docker side: running"; else echo "Docker side: not running"; fi
    [ ! -f "$STATE/disk.qcow2" ] || qemu-img info -U "$STATE/disk.qcow2" | grep -E 'virtual size|disk size'
  else
    echo "No fixture $VM_NAME"
  fi
  exit 0
  ;;
ssh)
  load_state || { echo "No fixture $VM_NAME" >&2; exit 1; }
  # shellcheck disable=SC2086
  exec $SSH $SSH_ARGS
  ;;
esac

e2e_self_test
main_up
if [ "$COMMAND" = up ]; then
  echo "Fixture $VM_NAME is up (ssh: run-freebsd.sh ssh; remove it with: run-freebsd.sh down)"
  exit 0
fi

RESULTS_FILE=$RUN_DIR/results.tsv
: > "$RESULTS_FILE"

snapshot_daemon_state() {
  {
    echo "Snapshot time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    vm sh $ROUTER_SCRIPT snapshot
  } >"$1" 2>&1 || true
}
set_nat66() { vm sh $ROUTER_SCRIPT nat66 "$1" >/dev/null 2>&1; }
lose_rules() { vm sh $ROUTER_SCRIPT lose-rules; }

start_packet_capture() { vm sh $ROUTER_SCRIPT capture start >/dev/null 2>&1 || true; }
stop_packet_capture() {
  vm sh $ROUTER_SCRIPT capture stop >/dev/null 2>&1 || true
  for i in "$LAN_IF" "$WAN_IF"; do
    $SSH "$PRIV cat /tmp/pcp-e2e/cap-$i.pcap" >"$1/packet-capture-$i.pcap" 2>/dev/null || true
  done
}

run_family() {
  family=$1
  if [ "$family" = ipv4 ]; then
    lanip=$LAN4.2; router=$LAN4.1; external=$WAN4.1; unowned_ip=$WAN4.77
    allow_ip=$WAN4.2; deny_ip=$WAN4.130; third_ip=$WAN4.200
  else
    lanip=${LAN6}2; router=${LAN6}1; external=${WAN6}1; unowned_ip=${WAN6}77
    allow_ip=${WAN6}2; deny_ip=${WAN6}130; third_ip=${WAN6}200
  fi
  allow_url=http://$LAN4.12:18080
  deny_url=http://$LAN4.13:18080
  third_url=http://$LAN4.14:18080

  family_dir=$RUN_DIR/$family
  mkdir -p "$family_dir"
  case_rows=$(e2e_case_rows "$family")
  active_section=
  active_section_nat66=0
  while IFS="$(printf '\t')" read -r section_name case_name section_nat66 <&3; do
    [ -n "$case_name" ] || continue
    e2e_case_selected "$case_name" || continue
    if [ "$section_name" != "$active_section" ]; then
      [ "$active_section_nat66" = 1 ] && set_nat66 off
      active_section=$section_name
      active_section_nat66=0
      if [ "$section_nat66" = true ]; then set_nat66 on; active_section_nat66=1; fi
    fi
    case_client=$lanip; case_router=$router; runner_ula=skip
    if [ "$family" = ipv6 ] && [ "$section_nat66" = true ]; then
      case_client=fd42:1::2; case_router=fd42:1::1; runner_ula=add
    fi
    EXECUTED=$((EXECUTED + 1))
    case_dir=$family_dir/$section_name/$case_name
    mkdir -p "$case_dir"
    snapshot_daemon_state "$case_dir/daemon-before.txt"
    start_packet_capture
    e2e_start_runner
    e2e_wait_runner
    stop_packet_capture "$case_dir"
    snapshot_daemon_state "$case_dir/daemon-after.txt"
    $SSH "$PRIV cat /tmp/pcp-e2e/miniupnpd.log" >"$case_dir/daemon.log" 2>&1 || true
    e2e_record_result "$family/$section_name/$case_name"
  done 3<<EOT
$case_rows
EOT
  if [ "$active_section_nat66" = 1 ]; then set_nat66 off; fi
  return 0
}

# Restart check : the lease-restart cases of the pcp_wire corpus (lease-restart-ipv4 and
# -ipv6) run from the host in two phases, as with the Docker driver. The daemon is
# stopped and its anchor flushed between them and has to create the mappings again from
# the PCP lease file: the runner reads the file in the VM (--state-command) and compares
# its lines, and the rules of the anchor are compared here. PCP_E2E_RESTART=0 skips it,
# PCP_E2E_ONLY_RESTART=1 skips the cases.
run_restart_check() {
  echo "Restart check of the lease files"
  restart_dir=$RUN_DIR/restart
  mkdir -p "$restart_dir"
  lease_runner="python3 -I $PMP/run_pcp_wire_cases.py --port 5351 --platform $E2E_PLATFORM --mutating
    --profile baseline --snapshot-dir $restart_dir
    --state-command '$RSH $VM_USER@127.0.0.1 cat /var/tmp/miniupnpd.leases /var/tmp/miniupnpd.leases6'"
  ports=
  for family in ipv4 ipv6; do
    [ "$family" = ipv4 ] && router=$LAN4.1 || router=${LAN6}1
    # shellcheck disable=SC2086
    ports="$ports $(eval $lease_runner --host $router --family $family --case lease-restart-$family \
      --list-lease-ports)"
  done
  ports=$(echo $ports | tr ' ' '|')
  for family in ipv4 ipv6; do
    [ "$family" = ipv4 ] && router=$LAN4.1 || router=${LAN6}1
    # shellcheck disable=SC2086
    eval $lease_runner --host $router --family $family --case lease-restart-$family --phase create \
      || { echo "FAIL restart: the create phase failed ($family)"; STATUS=1; return 0; }
  done
  vm sh $ROUTER_SCRIPT rules "'$ports'" >"$restart_dir/before.txt" 2>&1 || true
  if [ "${PCP_E2E_BREAK_RESTART:-0}" = 1 ]; then
    # to check the test itself : lose the lease files, this has to fail
    $SSH "$PRIV rm -f /var/tmp/miniupnpd.leases /var/tmp/miniupnpd.leases6"
  fi
  vm sh $ROUTER_SCRIPT restart >"$restart_dir/restart.log" 2>&1 || \
    { echo "FAIL restart: the daemon did not start again"; STATUS=1; return 0; }
  vm sh $ROUTER_SCRIPT rules "'$ports'" >"$restart_dir/after.txt" 2>&1 || true
  restart_ok=1
  [ -s "$restart_dir/before.txt" ] || { echo "FAIL restart: no rules for the mappings before the restart"; restart_ok=0; }
  if ! diff "$restart_dir/before.txt" "$restart_dir/after.txt" >"$restart_dir/diff.txt"; then
    echo "FAIL restart: the rules of the anchor changed over the restart:"
    cat "$restart_dir/diff.txt"
    restart_ok=0
  fi
  [ "$(vm sh $ROUTER_SCRIPT restored 2>/dev/null)" -ge 1 ] 2>/dev/null || \
    { echo "FAIL restart: the daemon did not log the restored mappings"; restart_ok=0; }
  for family in ipv4 ipv6; do
    [ "$family" = ipv4 ] && router=$LAN4.1 || router=${LAN6}1
    # shellcheck disable=SC2086
    eval $lease_runner --host $router --family $family --case lease-restart-$family --phase verify \
      || { echo "FAIL restart: the verify phase failed ($family)"; restart_ok=0; }
  done
  if [ "$restart_ok" = 1 ]; then
    echo "PASS restart: the PCP lease file and the rules of the anchor are the same after the restart"
  else
    STATUS=1
  fi
}

# PCP_E2E_PF_MAKE=1 : build the development test programs of miniupnpd/pf in the VM
if [ "${PCP_E2E_PF_MAKE:-0}" = 1 ]; then
  mkdir -p "$RUN_DIR"
  vm sh $ROUTER_SCRIPT pf-make >"$RUN_DIR/pf-make.log" 2>&1 || true
  cp "$RUN_DIR/pf-make.log" "$ARTIFACTS/../claude/pf-make.log" 2>/dev/null || true
  if grep -q 'make exit status: 0' "$RUN_DIR/pf-make.log"; then
    echo "PASS pf-make: the test programs of miniupnpd/pf build"
  else
    echo "FAIL pf-make: the test programs of miniupnpd/pf do not build (see pf-make.log)"
    tail -15 "$RUN_DIR/pf-make.log"
  fi
fi

if [ "${PCP_E2E_ONLY_RESTART:-0}" != 1 ] && stage_on cases; then
  run_family ipv4
  run_family ipv6
fi
if [ "${PCP_E2E_RESTART:-1}" = 1 ] && stage_on restart; then
  run_restart_check
fi
if [ "${PCP_E2E_ONLY_RESTART:-0}" = 1 ]; then
  exit "$STATUS"
fi
e2e_write_status "${RUN_DIR#"$ROOT"/}" "router=$ROUTER_NAME" "peers=Linux Docker"
exit "$STATUS"

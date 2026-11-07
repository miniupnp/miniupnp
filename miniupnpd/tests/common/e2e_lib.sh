# Shared steps of the Docker and QEMU drivers of the test suites.
# Source this file after setting ROOT, DIR and DOCKER; set RUN_DIR, RUNNER, LAN and STATUS_FILE, and
# IMAGE and DAEMON_DIR with e2e_image and e2e_build_daemon.  The helpers read and set the drivers' variables on purpose: the
# drivers differ in how they start the daemon, take snapshots and capture packets,
# not in how a case is run and reported.

# e2e_timestamp_output "$@": when stdout is a terminal, re-run the calling script
# with every output line prefixed by the time (HH:MM:SS) and exit with its status.
# PCP_E2E_TIMESTAMPS=0 disables it. Call first, before any other output.
e2e_timestamp_output() {
  [ -t 1 ] && [ "${PCP_E2E_TIMESTAMPS:-1}" != 0 ] || return 0
  ts_status=$(mktemp)
  { sh "$0" "$@" 2>&1; echo $? >"$ts_status"; } |
    while IFS= read -r ts_line; do printf '%s %s\n' "$(date +%H:%M:%S)" "$ts_line"; done
  ts_rc=$(cat "$ts_status"); rm -f "$ts_status"
  exit "${ts_rc:-1}"
}

# e2e_address_plan SLOT: the addresses of one fixture, so fixtures run side by side (Docker refuses
# networks whose subnets overlap: bridges share the routing table of the host). Slots 1-128; the slot
# is the third octet of both /24s.
# Sets LAN4 / WAN4 (the first three octets of the /24s), LAN6 / WAN6 (the /64 prefixes, ending in
# "::"), LAN6_PREFIX / WAN6_PREFIX (the same without it) and SLOT_SSH_PORT. A host is "$LAN4.12" or "${LAN6}12"; the router is .1 / ::1 on both sides.
e2e_address_plan() {
  case "$1" in
    ''|*[!0-9]*) echo "unknown fixture slot: $1 (1-128)" >&2; exit 2 ;;
  esac
  if [ "$1" -lt 1 ] || [ "$1" -gt 128 ]; then
    echo "unknown fixture slot: $1 (1-128)" >&2; exit 2
  fi
  LAN4=172.28.$1; WAN4=6.18.$1    # public space, so the daemon sees a normal WAN address
  LAN6=2001:db8:1:$1::; WAN6=2001:db8:9000:$1::
  LAN6_PREFIX=${LAN6%::}; WAN6_PREFIX=${WAN6%::}
  SLOT_SSH_PORT=$((2230 + $1))
}

# reserve_slot PLAN WANT [nocheck]: take slot WANT, or the first free one of 1-128, into SLOT, for every
# driver that uses Docker or QEMU. All of them share one pool, and no slot is set aside for any of them:
# a slot is held by flock on PCP_E2E_LOCK_DIR/slot-N.lock (default /tmp/pcp-e2e-slots) until this
# process ends, also when it is killed; child processes keep it. PLAN SLOT sets the slot's resources:
# LAN4 and WAN4 of a slot with Docker networks (a slot with one of those subnets is not free: a kept
# fixture or a crashed run), or SLOT_BUSY with a reason. "nocheck" skips the subnet check, for a driver
# reusing its kept fixture.
reserve_slot() {
  reserve_plan=$1; reserve_want=$2; reserve_check=${3:-check}
  reserve_dir=${PCP_E2E_LOCK_DIR:-/tmp/pcp-e2e-slots}
  mkdir -p "$reserve_dir"
  chmod 1777 "$reserve_dir" 2>/dev/null || true
  for reserve_slot in ${reserve_want:-$(seq 1 128)}; do
    LAN4=; WAN4=; SLOT_BUSY=
    "$reserve_plan" "$reserve_slot"
    exec 7>>"$reserve_dir/slot-$reserve_slot.lock"
    chmod 666 "$reserve_dir/slot-$reserve_slot.lock" 2>/dev/null || true
    if ! flock -n 7; then
      reserve_why="another run holds it"
    else
      if [ -z "$SLOT_BUSY" ] && [ -n "$WAN4" ] && [ "$reserve_check" = check ]; then
        reserve_subnets=$("${DOCKER:-docker}" network ls -q | xargs -r "${DOCKER:-docker}" network inspect \
          -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | tr ' ' '\n')
        for reserve_subnet in "$LAN4.0/24" "$WAN4.0/24"; do
          if printf '%s\n' "$reserve_subnets" | grep -Fxq "$reserve_subnet"; then
            SLOT_BUSY="the subnet $reserve_subnet exists (a kept fixture or a crashed run)"
          fi
        done
      fi
      if [ -z "$SLOT_BUSY" ]; then
        SLOT=$reserve_slot
        return 0
      fi
      flock -u 7
      reserve_why=$SLOT_BUSY
    fi
    [ -z "$reserve_want" ] || { echo "slot $reserve_want is not free: $reserve_why" >&2; exit 1; }
    echo "slot $reserve_slot skipped: $reserve_why" >&2
  done
  echo "no free slot in 1-128" >&2
  exit 1
}

# e2e_image REPOSITORY DOCKERFILE [EXTRA_PACKAGES]: set IMAGE to REPOSITORY:HASH, built on the first use.
# The hash covers the directory of DOCKERFILE, which is the build context, so runs side by side share
# one image and no source goes in: the lock is what stops two first runs building one tag together.
e2e_image() {
  image_context=$(dirname "$2")
  image_hash=$( { find "$image_context" -maxdepth 1 -type f | LC_ALL=C sort | xargs cat
    printf '%s' "${3:-}"; } | sha256sum | cut -c1-12)
  IMAGE=$1:$image_hash
  image_locks=${PCP_E2E_LOCK_DIR:-/tmp/pcp-e2e-slots}
  mkdir -p "$image_locks"
  (
    flock 8
    "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1 ||
      "$DOCKER" build --quiet --build-arg "EXTRA_PACKAGES=${3:-}" -f "$2" -t "$IMAGE" "$image_context" >/dev/null
  ) 8>>"$image_locks/image-${1##*/}-$image_hash.lock"
}

# e2e_tools_image [EXTRA_PACKAGES]: e2e_image of common/docker/Dockerfile.
e2e_tools_image() {
  e2e_image miniupnpd-test-tools "$ROOT/miniupnpd/tests/common/docker/Dockerfile" "${1:-}"
}

# The recipe of e2e_build_daemon, run in IMAGE: the source comes on stdin, the output goes to /out.
E2E_DAEMON_BUILD='mkdir /tmp/src && cd /tmp/src && tar -xmf - && cd miniupnpd \
  && ./configure --firewall=nftables --pcp-peer --ipv6 --leasefile --disable-tests $1 \
  && CPPFLAGS="-DPCP_ANNOUNCE_COUNT=5" make -j2 \
  && install -m 0755 miniupnpd /out/miniupnpd && mkdir /out/scripts \
  && install -m 0755 netfilter_nft/scripts/nft_init.sh /out/scripts/nft_init.sh \
  && install -m 0644 netfilter_nft/scripts/miniupnpd_functions.sh /out/scripts/miniupnpd_functions.sh'

# e2e_build_daemon [CONFIGURE_FLAGS]: set DAEMON_DIR to the daemon of this tree, for the router to mount
# at /opt/miniupnpd. It is compiled in IMAGE from a copy, so the build leaves nothing in the tree. The
# directory is named by a hash of the source, the image and the flags: a run with the same ones reuses
# it, a run with others cannot get it. Directories not used for 7 days are removed.
e2e_build_daemon() {
  daemon_flags=${1---igd2}
  daemon_cache=$ROOT/.tmp/tests/daemon
  mkdir -p "$daemon_cache"
  find "$daemon_cache" -mindepth 1 -maxdepth 1 -mtime +7 -exec rm -rf {} +
  daemon_source=$(mktemp "$daemon_cache/source.XXXXXX")
  tar -C "$ROOT" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --exclude=miniupnpd/tests --exclude=miniupnpd/miniupnpd --exclude='*.o' --exclude='*.a' \
    -cf "$daemon_source" miniupnpd
  DAEMON_DIR=$daemon_cache/$( { sha256sum <"$daemon_source"
    printf '%s\n' "$IMAGE" "$daemon_flags" "$E2E_DAEMON_BUILD"; } | sha256sum | cut -c1-16)
  (
    flock 8
    if [ ! -x "$DAEMON_DIR/miniupnpd" ]; then
      rm -rf "$DAEMON_DIR.new"
      mkdir "$DAEMON_DIR.new"
      echo "Building the daemon: $DAEMON_DIR" >&2
      "$DOCKER" run --rm -i --user "$(id -u):$(id -g)" --volume "$DAEMON_DIR.new:/out" --entrypoint sh \
        "$IMAGE" -c "$E2E_DAEMON_BUILD" sh "$daemon_flags" <"$daemon_source" >"$DAEMON_DIR.log" 2>&1 ||
        { tail -n 40 "$DAEMON_DIR.log" >&2; rm -f "$daemon_source"; exit 1; }
      mv "$DAEMON_DIR.new" "$DAEMON_DIR"
    fi
  ) 8>>"$DAEMON_DIR.lock"
  rm -f "$daemon_source"
  touch "$DAEMON_DIR" "$DAEMON_DIR.lock"
}

# e2e_result STATUS [STATUS_FILE PLATFORM]: the last lines of a run of several parts, each with its own
# Summary: the result, and with a status report the total, the column PLATFORM of it. Pass the report
# only when it holds this run alone: a run of a few cases leaves the other results of the column.
e2e_result() {
  if [ "$#" -ge 3 ]; then
    sed -n "s/^- \*\*$3\*\*: //p" "$2" | sed 's/ (updated.*//; s/\*\*//g; s/^/Total: /'
  fi
  if [ "$1" = 0 ]; then echo "Result: passed"; else echo "Result: FAILED"; fi
}

# pcp_qemu_plan SLOT: the host resource of one VM of the FreeBSD suite run-freebsd.sh, its SSH port.
pcp_qemu_plan() {
  SSH_PORT=$((2400 + $1))
  if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :$SSH_PORT" 2>/dev/null | grep -q LISTEN; then
    SLOT_BUSY="host port $SSH_PORT is in use (a VM kept by another run?)"
  fi
}

# e2e_self_test: the self-tests of the harness (common/run_self_tests.sh, the file the GitHub
# workflows run too) before a run; a failure stops the run. PCP_TEST_SELF_TEST=0 skips them.
e2e_self_test() {
  [ "${PCP_TEST_SELF_TEST:-1}" != 0 ] || return 0
  self_test_log=$(mktemp)
  if sh "$ROOT/miniupnpd/tests/common/run_self_tests.sh" >"$self_test_log" 2>&1; then
    echo "Self-tests of the harness: $(grep -c '^PASS ' "$self_test_log") passed (PCP_TEST_SELF_TEST=0 skips them)"
    rm -f "$self_test_log"
  else
    grep -v '^PASS ' "$self_test_log" >&2
    rm -f "$self_test_log"
    echo "The self-tests of the harness failed; not running the cases." >&2
    exit 1
  fi
}

# e2e_parse_args "$@": --case NAME (repeatable) selects cases into SELECTED_CASES.
e2e_parse_args() {
  SELECTED_CASES=
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --case)
        [ "$#" -ge 2 ] || { echo "--case requires a name" >&2; exit 2; }
        case "$2" in *[!A-Za-z0-9_.-]*|'') echo "invalid case name: $2" >&2; exit 2 ;; esac
        SELECTED_CASES="$SELECTED_CASES $2"
        shift 2
        ;;
      *) echo "unsupported option: $1 (only --case NAME is accepted)" >&2; exit 2 ;;
    esac
  done
}

# e2e_case_selected NAME: true when no --case was given or NAME was selected.
e2e_case_selected() {
  [ -z "$SELECTED_CASES" ] && return 0
  case " $SELECTED_CASES " in *" $1 "*) return 0 ;; esac
  return 1
}

# The suite of the functions below: E2E_RUNNER (default the pcp_e2e runner) in DIR, and
# E2E_RUNNER_ARGS, a list of options for it (upnp_e2e: --build).
E2E_RUNNER=${E2E_RUNNER:-run_pcp_e2e_cases.py}

# e2e_compose ARGS: docker compose on common/compose.yaml, with the variables of the fixture. The
# traffic agents have the profile "agents": a suite with peers sets COMPOSE_PROFILES=agents.
e2e_compose() {
  export ROOT SLOT IMAGE DAEMON_DIR RUN_DIR LAN4 LAN6 WAN4 WAN6
  "$DOCKER" compose -f "$ROOT/miniupnpd/tests/common/compose.yaml" "$@"
}

# e2e_wait_agent CONTAINER: until the traffic agent answers.
e2e_wait_agent() {
  for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    if "$DOCKER" exec "$1" python3 -c \
      'import urllib.request; urllib.request.urlopen("http://127.0.0.1:18080/health", timeout=1)' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Traffic agent failed to start" >&2
  exit 1
}

# e2e_wait_upnp CONTAINER ADDRESS: until the daemon in CONTAINER serves its description on ADDRESS.
e2e_wait_upnp() {
  for _attempt in $(seq 1 40); do
    if "$DOCKER" exec "$1" python3 -c \
        "import urllib.request; urllib.request.urlopen('http://$2:5000/rootDesc.xml', timeout=1)" \
        >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "miniupnpd did not answer on $2:5000" >&2
  return 1
}

# e2e_router_policy CONTAINER: a normal gateway's LAN-to-WAN policy (inbound WAN traffic stays blocked
# until a mapping rule lets it in) and outbound IPv4 NAT, so PEER can adopt a mapping made by traffic.
# Again after a restart of the container: its entrypoint rebuilds the ruleset.
e2e_router_policy() {
  "$DOCKER" exec "$1" nft insert rule inet filter forward iifname eth0 oifname wan0 accept
  "$DOCKER" exec "$1" nft add rule inet filter postrouting meta nfproto ipv4 oifname wan0 masquerade
}

# e2e_case_rows FAMILY: "section<TAB>case<TAB>flag" for every case that runs on FAMILY (the flag of
# pcp_e2e is nat66).
e2e_case_rows() {
  # shellcheck disable=SC2086 # E2E_RUNNER_ARGS is a list of options
  "$DOCKER" run --rm --volume "$ROOT/miniupnpd/tests:/pcp-tests:ro" --entrypoint python3 "$IMAGE" \
    "/pcp-tests/${DIR##*/}/$E2E_RUNNER" --list-cases --family "$1" ${E2E_UPNP:+--enable-upnp} ${E2E_RUNNER_ARGS:-}
}

# e2e_start_runner: start the detached runner container for one case.  Uses family,
# section_name, case_name, case_client, case_router, runner_ula, lanip,
# external, unowned_ip (a WAN address the router does not own), the *_url and *_ip peer
# variables. The runner has a fixed address in both families: a free one from Docker
# is the first of the subnet, which on FreeBSD is the address of the router, and
# the host then sends its requests to the MAC of the runner, which is gone.
e2e_start_runner() {
  mkdir -p "$RUN_DIR/calls"
  chmod 777 "$RUN_DIR/calls"   # the runner may be another user
  # shellcheck disable=SC2086 # E2E_RUNNER_ARGS is a list of options
  "$DOCKER" run -d --name "$RUNNER" --network "$LAN" --ip "$LAN4.2" --ip6 "${LAN6}2" \
    --cap-add NET_ADMIN --entrypoint sh \
    --volume "$ROOT/miniupnpd/tests:/pcp-tests:ro" --volume "$RUN_DIR:/pcp-e2e-artifacts" \
    "$IMAGE" -c 'if [ "$1" = add ]; then ip -6 address replace fd42:1::2/64 dev eth0 nodad; fi; shift; exec python3 "$@"' \
    pcp-e2e-runner "$runner_ula" "/pcp-tests/${DIR##*/}/$E2E_RUNNER" ${E2E_RUNNER_ARGS:-} \
    --route-through-router --family "$family" --case "$case_name" ${E2E_UPNP:+--enable-upnp} \
    --router "$case_router" --client-address "$case_client" --external-address "$external" \
    --agent "allowed-peer=$allow_url" --agent "denied-peer=$deny_url" \
    --agent "third-peer=$third_url" \
    --peer-address "allowed-peer=$allow_ip" --peer-address "denied-peer=$deny_ip" \
    --peer-address "third-peer=$third_ip" \
    --peer-address "client=$lanip" --peer-address "router-wan=$external" \
    --peer-address "unowned-wan=$unowned_ip" \
    --router-call-dir /pcp-e2e-artifacts/calls >/dev/null
}

# router_call COMMAND: what a runner asks of the driver (lib_test.router_call); the output is the answer.
# A driver replaces it to add commands. snapshot:N, after request N of a case, needs snapshot_daemon_state.
# lose-rules needs lose_rules, which removes the rules of the daemon and prints their number before and after.
router_call() {
  case $1 in
    snapshot:*) snapshot_daemon_state "$case_dir/daemon-expect-${1#snapshot:}.txt" ;;
    lose-rules) lose_rules ;;
    *) echo "unknown router command: $1" ;;
  esac
}

# e2e_serve_router_calls DIRECTORY: answer the requests waiting there; false when there were none.
e2e_serve_router_calls() {
  calls_served=1
  for request in "$1"/*.req; do
    [ -e "$request" ] || continue
    router_command=$(cat "$request")
    rm -f "$request"
    router_call "$router_command" > "${request%.req}.part" 2>&1 || true
    mv "${request%.req}.part" "${request%.req}.resp"
    calls_served=0
  done
  return "$calls_served"
}

# e2e_serve_runner DIRECTORY: answer the router calls of the runner container while it runs.
e2e_serve_runner() {
  while [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$RUNNER" 2>/dev/null || echo false)" = true ]; do
    e2e_serve_router_calls "$1" || sleep 0.05
  done
}

# e2e_collect_runner LOG: the end of the runner container: its exit status in runner_exit, its log in LOG.
e2e_collect_runner() {
  runner_exit=$("$DOCKER" wait "$RUNNER")
  "$DOCKER" logs "$RUNNER" > "$1" 2>&1 || true
  "$DOCKER" rm "$RUNNER" >/dev/null
}

# e2e_wait_runner: answer the runner's router calls until it ends, then collect its result into
# case_result / case_note (and STATUS=1 on failure).
e2e_wait_runner() {
  e2e_serve_runner "$RUN_DIR/calls"
  e2e_collect_runner "$case_dir/runner.log"
  sed '/^Summary: /d' "$case_dir/runner.log"
  if [ "$runner_exit" = 0 ]; then
    case_result=PASS
    case_note="all configured assertions passed"
  else
    STATUS=1
    case_result=FAIL
    case_note=$(sed -n 's/^FAIL [^:]*: //p' "$case_dir/runner.log" | head -n 1)
  fi
}

# e2e_record_result ARTIFACTS: append this case's row to RESULTS_FILE.
e2e_record_result() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$family" "$section_name" "$case_name" "$case_result" "$case_note" "$1" >> "$RESULTS_FILE"
}

# e2e_check_selection RESULTS: a run that ran no case, or not a selected one, failed.
e2e_check_selection() {
  if [ "$EXECUTED" -eq 0 ]; then
    echo "No E2E cases matched the requested selection." >&2
    STATUS=1
  fi
  # a --case which ran nowhere is a typo or a case of another platform, not a pass
  for selected in $SELECTED_CASES; do
    if ! awk -F '\t' -v name="$selected" '$3 == name { found = 1 } END { exit !found }' "$1"; then
      echo "Selected case did not run: $selected" >&2
      STATUS=1
    fi
  done
}

# e2e_write_report ARTIFACTS_NOTE [KEY=VALUE ...]: merge RESULTS_FILE into STATUS_FILE, the report all
# the PCP tests share (one column per platform: E2E_PLATFORM), and print the summary.  The KEY=VALUEs
# are added to what the report says about the run.  Needs python3 with PyYAML on the host.
e2e_write_report() {
  artifacts=$1; shift
  PASS_TOTAL=$(awk -F '\t' '$4 == "PASS" { n++ } END { print n+0 }' "$RESULTS_FILE")
  FAIL_TOTAL=$(awk -F '\t' '$4 == "FAIL" { n++ } END { print n+0 }' "$RESULTS_FILE")
  RESULT_TOTAL=$(awk -F '\t' 'NF >= 4 { n++ } END { print n+0 }' "$RESULTS_FILE")
  SCENARIO_SELECTION=${SELECTED_CASES# }
  [ -n "$SCENARIO_SELECTION" ] || SCENARIO_SELECTION=all
  branch=$(git -C "$ROOT" branch --show-current 2>/dev/null || echo unknown)
  # the KEY=VALUEs become --run-info options (a value may hold spaces), after the three of every run
  count=$#
  set -- "$@" --run-info "branch=$branch" --run-info "selection=$SCENARIO_SELECTION" --run-info "artifacts=$artifacts"
  while [ "$count" -gt 0 ]; do
    item=$1; shift; count=$((count - 1))
    set -- "$@" --run-info "$item"
  done
  if ! python3 "$DIR/$E2E_RUNNER" --write-status "$RESULTS_FILE" --status-file "$STATUS_FILE" \
      --platform "${E2E_PLATFORM:-linux}" ${E2E_STATUS_DATA_FILE:+--status-data-file "$E2E_STATUS_DATA_FILE"} "$@"; then
    echo "Could not write the status report (python3 with PyYAML is needed on the host)." >&2
    STATUS=1
  fi
  echo "Summary: $PASS_TOTAL passed, $FAIL_TOTAL failed ($RESULT_TOTAL family runs)"
}

# e2e_write_status ARTIFACTS_NOTE [KEY=VALUE ...]: the end of a run with one results file.
e2e_write_status() {
  e2e_check_selection "$RESULTS_FILE"
  e2e_write_report "$@"
}

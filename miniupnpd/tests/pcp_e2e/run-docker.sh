#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
DIR=$ROOT/miniupnpd/tests/pcp_e2e
DOCKER=${DOCKER:-docker}
IMAGE=${PCP_E2E_IMAGE:-miniupnpd-pcp-e2e:local}
SUFFIX=$$
LAN=pcp-e2e-lan-$SUFFIX
WAN=pcp-e2e-wan-$SUFFIX
ROUTER=pcp-e2e-router-$SUFFIX
ALLOW=pcp-e2e-allow-$SUFFIX
DENY=pcp-e2e-deny-$SUFFIX
THIRD=pcp-e2e-third-$SUFFIX
RUNNER=pcp-e2e-runner-$SUFFIX
KEEP=${PCP_E2E_KEEP:-0}
ARTIFACTS=${PCP_E2E_ARTIFACT_DIR:-$ROOT/.tmp/pcp-e2e}
STATUS_FILE=${PCP_E2E_STATUS_FILE:-$DIR/status.md}
RUN_ID=$(date -u +%Y-%m-%dT%H-%M-%SZ)
SELECTED_CASES=
STATUS=0
EXECUTED=0

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

cleanup() {
  result=$?
  trap - EXIT INT TERM
  if [ "$KEEP" != 1 ]; then
    "$DOCKER" rm -f "$RUNNER" "$ALLOW" "$DENY" "$THIRD" "$ROUTER" >/dev/null 2>&1 || true
    "$DOCKER" network rm "$LAN" "$WAN" >/dev/null 2>&1 || true
  else
    echo "Retaining fixture: $LAN $WAN $ROUTER $ALLOW $DENY $THIRD $RUNNER" >&2
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$DOCKER" build -f "$ROOT/miniupnpd/tests/pcp_pmp/docker/Dockerfile" -t "$IMAGE" "$ROOT"
"$DOCKER" network create --driver bridge --ipv6 \
  --subnet 172.28.41.0/24 --gateway 172.28.41.254 \
  --subnet fd42:5351:5351::/64 --gateway fd42:5351:5351::ffff "$LAN" >/dev/null
"$DOCKER" network create --driver bridge --ipv6 \
  --opt com.docker.network.bridge.gateway_mode_ipv6=routed \
  --subnet 198.51.100.0/24 --gateway 198.51.100.254 \
  --subnet fd42:5351:5352::/64 --gateway fd42:5351:5352::ffff "$WAN" >/dev/null

# Router starts on its LAN. Connecting the WAN second gives entrypoint.sh the
# expected eth0/eth1 order; it renames the WAN link to wan0 before daemon start.
"$DOCKER" create --name "$ROUTER" --network "$LAN" --ip 172.28.41.1 \
  --ip6 fd42:5351:5351::1 --cap-add NET_ADMIN --cap-add NET_RAW \
  --env PCP_TEST_REAL_WAN=1 --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 "$IMAGE" >/dev/null
"$DOCKER" network connect --ip 198.51.100.1 --ip6 fd42:5351:5352::1 "$WAN" "$ROUTER"
"$DOCKER" start "$ROUTER" >/dev/null

start_agent() {
  name=$1; lan4=$2; lan6=$3; wan4=$4; wan6=$5
  "$DOCKER" create --name "$name" --network "$LAN" --ip "$lan4" --ip6 "$lan6" \
    --cap-add NET_ADMIN --entrypoint python3 "$IMAGE" \
    /src/miniupnpd/tests/common/traffic_agent.py --host 0.0.0.0 --source4 "$wan4" \
    --source6 "$wan6" --route6 fd42:5351:5351::/64 \
    --gateway6 fd42:5351:5352::1 >/dev/null
  "$DOCKER" network connect --ip "$wan4" --ip6 "$wan6" "$WAN" "$name"
  "$DOCKER" start "$name" >/dev/null
}
start_agent "$ALLOW" 172.28.41.12 fd42:5351:5351::12 198.51.100.2 fd42:5351:5352::2
start_agent "$DENY" 172.28.41.13 fd42:5351:5351::13 198.51.100.130 fd42:5351:5352::130
start_agent "$THIRD" 172.28.41.14 fd42:5351:5351::14 198.51.100.200 fd42:5351:5352::200

ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if "$DOCKER" exec "$ALLOW" python3 -c \
    'import urllib.request; urllib.request.urlopen("http://127.0.0.1:18080/health", timeout=1)' >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[ "$ready" = 1 ] || { echo "Traffic agent failed to start" >&2; exit 1; }
sleep 2

RUN_DIR=$ARTIFACTS/$RUN_ID
mkdir -p "$RUN_DIR"
RESULTS_FILE=$RUN_DIR/results.tsv
: > "$RESULTS_FILE"
"$DOCKER" logs --timestamps "$ROUTER" > "$RUN_DIR/daemon-start.log" 2>&1 || true
echo "Daemon startup log: $RUN_DIR/daemon-start.log"

run_family() {
  family=$1
  if [ "$family" = ipv4 ]; then
    lanip=172.28.41.2
    router=172.28.41.1
    external=198.51.100.1
    allow_url=http://172.28.41.12:18080
    deny_url=http://172.28.41.13:18080
    third_url=http://172.28.41.14:18080
    allow_ip=198.51.100.2; deny_ip=198.51.100.130; third_ip=198.51.100.200
    ip_flag=--ip
  else
    lanip=fd42:5351:5351::2
    router=fd42:5351:5351::1
    external=fd42:5351:5352::1
    # The control channel uses LAN IPv4; each agent still binds test traffic
    # to its independently assigned IPv6 WAN address.
    allow_url=http://172.28.41.12:18080
    deny_url=http://172.28.41.13:18080
    third_url=http://172.28.41.14:18080
    allow_ip=fd42:5351:5352::2; deny_ip=fd42:5351:5352::130; third_ip=fd42:5351:5352::200
    ip_flag=--ip6
  fi

  family_dir=$RUN_DIR/$family
  mkdir -p "$family_dir"
  case_names=$($DOCKER run --rm --volume "$DIR:/pcp-e2e:ro" --entrypoint python3 "$IMAGE" -c \
    'import sys,yaml; d=yaml.safe_load(open("/pcp-e2e/pcp-e2e-cases.yaml")); f=sys.argv[1]; print("\n".join(c["name"] for c in d["cases"] if c.get("family","ipv4")==f))' "$family")
  for case_name in $case_names; do
    if [ -n "$SELECTED_CASES" ]; then
      case " $SELECTED_CASES " in *" $case_name "*) ;; *) continue ;; esac
    fi
    case_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    EXECUTED=$((EXECUTED + 1))
    if "$DOCKER" run --rm --name "$RUNNER" --network "$LAN" "$ip_flag" "$lanip" \
      --cap-add NET_ADMIN --entrypoint python3 \
      --volume "$DIR:/pcp-e2e:ro" "$IMAGE" /pcp-e2e/run.py \
      --route-through-router --family "$family" --case "$case_name" \
      --router "$router" --client-address "$lanip" --external-address "$external" \
      --agent "allowed-peer=$allow_url" --agent "denied-peer=$deny_url" \
      --agent "third-peer=$third_url" \
      --peer-address "allowed-peer=$allow_ip" --peer-address "denied-peer=$deny_ip" \
      --peer-address "third-peer=$third_ip" > "$family_dir/$case_name.runner.log" 2>&1; then
      cat "$family_dir/$case_name.runner.log"
      case_result=PASS
      case_note="all PCP and traffic assertions passed"
    else
      cat "$family_dir/$case_name.runner.log"
      STATUS=1
      case_result=FAIL
      case_note=$(sed -n 's/^FAIL [^:]*: //p' "$family_dir/$case_name.runner.log" | head -n 1)
    fi
    printf '%s\t%s\t%s\t%s\n' "$family" "$case_name" "$case_result" "$case_note" >> "$RESULTS_FILE"
    "$DOCKER" logs --timestamps --since "$case_start" "$ROUTER" \
      > "$family_dir/$case_name.daemon.log" 2>&1 || true
  done
}

run_family ipv4
run_family ipv6
if [ "$EXECUTED" -eq 0 ]; then
  echo "No E2E cases matched the requested selection." >&2
  STATUS=1
fi
"$DOCKER" logs --timestamps "$ROUTER" > "$RUN_DIR/daemon-final.log" 2>&1 || true
PASS_TOTAL=$(awk -F '\t' '$3 == "PASS" { n++ } END { print n+0 }' "$RESULTS_FILE")
FAIL_TOTAL=$(awk -F '\t' '$3 == "FAIL" { n++ } END { print n+0 }' "$RESULTS_FILE")
SCENARIO_SELECTION=${SELECTED_CASES# }
[ -n "$SCENARIO_SELECTION" ] || SCENARIO_SELECTION=all
RUN_DIR_DISPLAY=${RUN_DIR#"$ROOT"/}
mkdir -p "$(dirname -- "$STATUS_FILE")"
{
  cat <<EOF
# PCP E2E Status

Updated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Run

- Branch: $(git -C "$ROOT" branch --show-current 2>/dev/null || echo unknown)
- Address families: IPv4 and IPv6
- Scenario selection: $SCENARIO_SELECTION
- Totals: **$PASS_TOTAL PASS**, **$FAIL_TOTAL FAIL**
- Artifacts: $RUN_DIR_DISPLAY

## Results
EOF
  for family in ipv4 ipv6; do
    printf '\n### %s\n\n| Case | Status | Result / note |\n|---|---|---|\n' "$family"
    awk -F '\t' -v family="$family" '$1==family { note=$4; gsub(/\|/, "\\|", note); printf "| %s | %s | %s |\n", $2, $3, note }' "$RESULTS_FILE"
  done
} > "$STATUS_FILE"
echo "Status report: $STATUS_FILE"
echo "Daemon logs: $RUN_DIR (startup, per-case snapshots, final)"
exit "$STATUS"

#!/bin/sh
# The self-tests of the PCP test harness: the unit tests of common/, common/tools/ and the pcp_wire
# tools, the --self-test of both runners (the tests of their own code) and of the traffic agent,
# and a syntax check of every shell script. No daemon, VM or Docker is needed (python3 with PyYAML is).
#
# The one list of them: pcp_e2e/run-docker.sh, pcp_e2e/run-freebsd.sh and the GitHub workflow
# (regression-testing.yml) all call this file. Run it from anywhere:
#
#   sh miniupnpd/tests/common/run_self_tests.sh
#
# Prints one line per check and the failures' output; exits 1 when one fails.
set -u

TESTS=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
FAILED=0
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

# check NAME DIR COMMAND...: run COMMAND in TESTS/DIR, keep its output only when it fails
check() {
  name=$1; dir=$2; shift 2
  if (cd "$TESTS/$dir" && "$@") >"$LOG" 2>&1; then
    echo "PASS self-test $name"
  else
    echo "FAIL self-test $name:"
    sed 's/^/  /' "$LOG"
    FAILED=1
  fi
}

check "common unit tests" common python3 -m unittest discover -p 'test_*.py'
check "slot reservation" common sh test_reserve_slot.sh
check "daemon cache" common sh test_daemon_cache.sh
check "run result" common sh test_e2e_result.sh
check "traffic agent" common python3 traffic_agent.py --self-test
check "pcp_wire runner" pcp_wire python3 run_pcp_wire_cases.py --self-test
check "common tools" common/tools python3 -m unittest discover -p 'test_*.py'
check "pcp_wire tools" pcp_wire/tools python3 -m unittest discover -p 'test_*.py'
check "pcp_e2e runner" pcp_e2e python3 run_pcp_e2e_cases.py --self-test
# the compare.py of each suite (common/tools/compare_daemon_branches.py)
for test in $(cd "$TESTS" && ls -- */test_compare.py 2>/dev/null); do
  check "${test%%/*} compare" "${test%%/*}" python3 -m unittest test_compare
done
for script in $(cd "$TESTS" && find . -name '*.sh' | sed 's|^\./||' | sort); do
  check "sh -n $script" . sh -n "$script"
done

exit "$FAILED"

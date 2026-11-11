#!/bin/sh
# FreeBSD fixture for the runner's daemon-restart cases.
#
#   freebsd.sh daemon-restart DIRECTORY FAMILY
#
# Runs inside the VM as root (freebsd/ci.sh), after freebsd/setup.sh has built
# the router.  Restarts miniupnpd from the tree in PCP_TEST_DAEMON_TREE and
# copies lan-N.pcap and wan-N.pcap into DIRECTORY (and a copy under
# FREEBSD_ARTIFACTS, if set).
set -eu

if [ "$#" -ne 3 ] || [ "$1" != daemon-restart ]; then
	echo "usage: $0 daemon-restart DIRECTORY FAMILY" >&2
	exit 2
fi
DIRECTORY=$2
FAMILY=$3
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

mkdir -p "$DIRECTORY"
(cd "${PCP_TEST_DAEMON_TREE:?set PCP_TEST_DAEMON_TREE}" && sh "$HERE/freebsd/daemon-restart.sh")
cp -R /tmp/pcp-restart/. "$DIRECTORY/"
if [ -n "${FREEBSD_ARTIFACTS:-}" ]; then
	mkdir -p "$FREEBSD_ARTIFACTS/$FAMILY"
	cp -R "$DIRECTORY/." "$FREEBSD_ARTIFACTS/$FAMILY/"
fi

#!/bin/sh
# run-freebsd.sh with an OpenBSD VM running miniupnpd with pf as the router: the same
# fixture, cases and options. OpenBSD has no cloud image: the first run installs one with
# the official installer, unattended (common/openbsd_image.sh), and caches it.
# PCP_TEST_OPENBSD_VERSION picks the release (default 8.0).
PCP_E2E_ROUTER=openbsd-pf
export PCP_E2E_ROUTER
exec sh "$(dirname -- "$0")/run-freebsd.sh" "$@"

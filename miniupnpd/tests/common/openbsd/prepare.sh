#!/bin/sh
# Runs inside the OpenBSD VM as root, once, before its image is cached: the packages the
# fixture needs, and curl and base64 for make check (validateupnphttp). The compiler, BSD
# make, pf and tcpdump are in the base system.
#
#   PCP_TEST_PYTHON=1   also install python3 and PyYAML
set -eu

packages="rsync-- curl base64"
[ "${PCP_TEST_PYTHON:-0}" = 1 ] && packages="$packages python%3 py3-yaml"
# shellcheck disable=SC2086
pkg_add -I $packages >/dev/null
if [ "${PCP_TEST_PYTHON:-0}" = 1 ]; then
	python3 -c 'import yaml' || { echo "PyYAML is not available" >&2; exit 1; }
fi
# the drivers run "cd /root/miniupnp && doas ..." as the user, as on FreeBSD, whose /root is 0755
chmod 755 /root
echo "OpenBSD prepared"

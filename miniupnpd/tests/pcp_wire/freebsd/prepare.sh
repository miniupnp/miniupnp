#!/bin/sh
# Runs inside the FreeBSD VM as root: installs what the PCP restart cases need.
#
#   PCP_TEST_PYTHON=1   also install python3 and PyYAML (to run the YAML runner
#                       inside the VM, as the GitHub workflow does)
#
# FreeBSD 15 ships neither libpfctl.h nor an installable libpfctl, so a static
# copy is built from the matching release branch into /usr/local (configure
# adds -I/usr/local/include -L/usr/local/lib).
set -eu

export IGNORE_OSVERSION=yes ASSUME_ALWAYS_YES=yes
packages="gmake pkgconf rsync"
[ "${PCP_TEST_PYTHON:-0}" = 1 ] && packages="$packages python3"
# shellcheck disable=SC2086
yes | pkg install -y $packages >/dev/null
if [ "${PCP_TEST_PYTHON:-0}" = 1 ]; then
	# The package name carries the Python version (py312-yaml, ...); look it up
	# rather than guess, and fall back to pip if the repository has none.
	python_tag=$(python3 -c 'import sys; print("py%d%d" % sys.version_info[:2])')
	yaml_pkg=$(pkg search -q -x "^${python_tag}-(py)?yaml-[0-9]" | head -n 1 | sed 's/-[0-9][^-]*$//')
	if [ -n "$yaml_pkg" ]; then
		yes | pkg install -y "$yaml_pkg" >/dev/null
	else
		python3 -m ensurepip >/dev/null 2>&1 || true
		python3 -m pip install pyyaml
	fi
	python3 -c 'import yaml' || { echo "PyYAML is not available" >&2; exit 1; }
fi

if [ "$(uname -r | cut -d. -f1)" -ge 15 ]; then
	rel=$(freebsd-version -u | sed 's/-.*//')
	url=https://raw.githubusercontent.com/freebsd/freebsd-src/releng/$rel/lib/libpfctl
	work=$(mktemp -d)
	(cd "$work" && fetch -q "$url/libpfctl.h" "$url/libpfctl.c" &&
		cc -O2 -I. -c libpfctl.c -o libpfctl.o && ar rcs libpfctl.a libpfctl.o)
	mkdir -p /usr/local/include /usr/local/lib
	install -m 644 "$work/libpfctl.h" /usr/local/include/
	install -m 644 "$work/libpfctl.a" /usr/local/lib/
	rm -rf "$work"
fi
echo "FreeBSD prepared"

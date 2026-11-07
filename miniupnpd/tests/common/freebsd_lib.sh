# Shared steps of the scripts that run inside a FreeBSD VM (pcp_wire/freebsd, pcp_e2e/freebsd). They run
# as root from a daemon tree, which need not hold these tests (ci.sh runs master's): source this file
# by the path of the script, not from the working directory.

# freebsd_link_pfctl: run in miniupnpd/ after configure. On FreeBSD 14 libpfctl is a private base
# library in /usr/lib/private, not on the default linker path; pfctl_dir stays set for the caller.
freebsd_link_pfctl() {
	pfctl_dir=$(dirname "$(ls /usr/lib/private/libpfctl.* 2>/dev/null | head -n 1)")
	grep -q lpfctl bsdmake.inc || return 0
	if [ "$pfctl_dir" != . ]; then
		echo "LDFLAGS += -L$pfctl_dir -Wl,-rpath,$pfctl_dir" >> bsdmake.inc
	fi
	echo "LIBS += -lnv" >> bsdmake.inc
}

# freebsd_rules_normalised PATTERN: the rules of the miniupnpd anchor that match PATTERN, in a form to
# compare over a restart. A restore gives pinholes new uids, in the order of the file. The "ts-N" of a
# pinhole label is its expiry on the daemon's clock; it is restored from the unix time in the lease file
# and may move by a second (the runner allows the same with expiry_tolerance), so it is left out.
freebsd_rules_normalised() {
	{ pfctl -a 'miniupnpd/*' -sn 2>&1; pfctl -a 'miniupnpd/*' -sr 2>&1; } | grep -E "$1" \
		| sed 's/ ts-[0-9]*:/ ts-N:/; s/"pinhole-[0-9]*\([: ]\)/"pinhole-N\1/' | sort || true
}

# freebsd_make_jail NAME INTERFACE ADDRESS4 ADDRESS6 [ROUTER4 ROUTER6]: a vnet jail that shares the root
# filesystem, with the end INTERFACE of an epair(4), its addresses and default routes.
freebsd_make_jail() {
	jail -c name="$1" path=/ host.hostname="$1" persist vnet vnet.interface="$2"
	jexec "$1" ifconfig lo0 127.0.0.1/8 up
	jexec "$1" ifconfig "$2" up
	jexec "$1" ifconfig "$2" inet "$3/24"
	jexec "$1" ifconfig "$2" inet6 "$4/64"
	[ "$#" -lt 5 ] || jexec "$1" route -q -n add -net default "$5" >/dev/null
	[ "$#" -lt 6 ] || jexec "$1" route -q -n add -inet6 default "$6" >/dev/null
}

# freebsd_clear_default_routes: the VM's own QEMU NIC (vtnet0) has default routes, which would win over
# those of the fixture; SSH keeps working over the connected route.
freebsd_clear_default_routes() {
	while route -n delete -net default >/dev/null 2>&1; do :; done
	while route -n delete -inet6 default >/dev/null 2>&1; do :; done
}

# freebsd_peer_option: --pcp-peer when the daemon has PCP PEER on pf. Run from the root of the tree; the
# daemon of master has PEER only on netfilter and stops at an #error with it.
freebsd_peer_option() {
	grep -q 'only supported with NETFILTER' miniupnpd/pcpserver.c || echo --pcp-peer
}

# Shared steps of the scripts that run inside a FreeBSD or OpenBSD VM (pcp_wire/freebsd, pcp_e2e/freebsd,
# daemon_options/freebsd). They run as root from a daemon tree, which need not hold these tests (ci.sh
# runs master's): source this file by the path of the script, not from the working directory. The
# freebsd_* functions are for FreeBSD; the bsd_* functions work on both.

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
	while route -n delete -inet default >/dev/null 2>&1; do :; done
	while route -n delete -inet6 default >/dev/null 2>&1; do :; done
}

# The hosts of an in-VM topology. A host is a vnet jail on FreeBSD and a routing domain (rdomain(4))
# on OpenBSD, which has no vnet jail; either way it shares the root filesystem with the router.
#
#   bsd_switch NAME ADDRESS4 ADDRESS6   a network of the router, with its addresses: a bridge(4) on
#                                       FreeBSD, a veb(4) with a vport(4) on OpenBSD. Sets SWITCH_IF,
#                                       the interface of the router on it (where pf and miniupnpd are).
#   bsd_host NAME SWITCH ADDRESS4 ADDRESS6 [ROUTER4 ROUTER6]
#                                       a host on the network SWITCH (a NAME of bsd_switch), with its
#                                       addresses and default routes. Sets HOST_IF, its interface.
#   bsd_exec NAME COMMAND...            run COMMAND in the host NAME
#   bsd_remove NAME                     remove the host NAME and stop its processes
BSD_HOSTS=/tmp/bsd-hosts
bsd_switch() {
	mkdir -p "$BSD_HOSTS"
	if [ "$(uname)" = OpenBSD ]; then
		n=$(ls "$BSD_HOSTS" | grep -c '^switch-' || true)
		ifconfig "veb$n" create
		ifconfig "vport$n" create
		ifconfig "veb$n" add "vport$n" up
		SWITCH_IF=vport$n
		echo "veb$n" >"$BSD_HOSTS/switch-$1"
	else
		SWITCH_IF=$(ifconfig bridge create)
		echo "$SWITCH_IF" >"$BSD_HOSTS/switch-$1"
	fi
	ifconfig "$SWITCH_IF" inet "$2/24" up
	ifconfig "$SWITCH_IF" inet6 "$3/64" alias
}
bsd_host() {
	switch=$(cat "$BSD_HOSTS/switch-$2")
	if [ "$(uname)" = OpenBSD ]; then
		# rdomain k, on the pair(4) interfaces 2k (the switch side) and 2k+1 (the host)
		k=$(($(ls "$BSD_HOSTS" | grep -c '^host-' || true) + 1))
		outer=pair$((2 * k)); HOST_IF=pair$((2 * k + 1))
		ifconfig "$outer" create
		ifconfig "$HOST_IF" create
		ifconfig "$HOST_IF" rdomain "$k"
		ifconfig "$HOST_IF" patch "$outer"
		ifconfig "$switch" add "$outer"
		ifconfig "$outer" up
		ifconfig "lo$k" create rdomain "$k" 2>/dev/null || ifconfig "lo$k" rdomain "$k"
		ifconfig "lo$k" inet 127.0.0.1/8 up
		ifconfig "$HOST_IF" inet "$3/24" up
		ifconfig "$HOST_IF" inet6 "$4/64" alias
		[ "$#" -lt 5 ] || route -T "$k" -qn add -inet default "$5" >/dev/null
		[ "$#" -lt 6 ] || route -T "$k" -qn add -inet6 default "$6" >/dev/null
		echo "$k $outer $HOST_IF" >"$BSD_HOSTS/host-$1"
	else
		outer=$(ifconfig epair create)
		HOST_IF=${outer%a}b
		ifconfig "$switch" addm "$outer"
		ifconfig "$outer" up
		name=$1; shift 2
		freebsd_make_jail "$name" "$HOST_IF" "$@"
		echo "jail $outer $HOST_IF" >"$BSD_HOSTS/host-$name"
	fi
}
bsd_exec() {
	name=$1
	shift
	if [ "$(uname)" = OpenBSD ]; then
		route -T "$(cut -d' ' -f1 "$BSD_HOSTS/host-$name")" exec "$@"
	else
		jexec "$name" "$@"
	fi
}
bsd_remove() {
	[ -f "$BSD_HOSTS/host-$1" ] || return 0
	if [ "$(uname)" = OpenBSD ]; then
		read -r k outer inner <"$BSD_HOSTS/host-$1"
		# as jail -r does: the processes of the host go too. A server left running there keeps
		# the SSH session of the driver open, and the run never ends.
		pkill -T "$k" 2>/dev/null || true
		ifconfig "$inner" destroy 2>/dev/null || true
		ifconfig "$outer" destroy 2>/dev/null || true
	else
		jail -r "$1" >/dev/null 2>&1 || true
	fi
	rm -f "$BSD_HOSTS/host-$1"
}

# bsd_fetch URL: exit 0 when an HTTP GET of URL succeeds within a second
bsd_fetch() {
	if [ "$(uname)" = OpenBSD ]; then ftp -M -V -w 1 -o /dev/null "$1" >/dev/null 2>&1
	else fetch -q -T 1 -o /dev/null "$1" 2>/dev/null; fi
}

# freebsd_peer_option: --pcp-peer when the daemon has PCP PEER on pf. Run from the root of the tree; the
# daemon of master has PEER only on netfilter and stops at an #error with it.
freebsd_peer_option() {
	grep -q 'only supported with NETFILTER' miniupnpd/pcpserver.c || echo --pcp-peer
}

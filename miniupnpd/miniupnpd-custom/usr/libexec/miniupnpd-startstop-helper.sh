#!/bin/sh -e

DEFAULT=/etc/default/miniupnpd
SCRIPT_DIR=/etc/miniupnpd


[ -f "${DEFAULT}" ] && . "${DEFAULT}"

check_miniupnpd () {
	# detect iptables, since `iptables` may not be present if only nftables installed
	system_backend=$(update-alternatives --query iptables | grep -F Value | grep -qF legacy \
		&& echo iptables || echo nftables)
	if [ -f "${SCRIPT_DIR}/iptables_init.sh" -a "${system_backend}" = nftables -o \
			-f "${SCRIPT_DIR}/nft_init.sh" -a "${system_backend}" = iptables ] ; then
		echo "WARNING: Your miniupnpd binary seems to mismatch your *tables backend; refused to start!"
		echo "WARNING: You should install 'miniupnpd-${system_backend}' instead"
		echo "WARNING: Read /usr/share/doc/miniupnpd/NEWS.Debian.gz for more information"
		return 1
	fi
}

get_ext_ifname () {
	if [ -f "${CONFFILE}" ] ; then
		ext_ifname=$(read_config "${CONFFILE}" ext_ifname)
		ext_ifname6=$(read_config "${CONFFILE}" ext_ifname6)
		[ -z "${ext_ifname6}" ] && ext_ifname6="${ext_ifname}"
	fi
	if [ -z "${ext_ifname}" ] ; then
		echo "Warning: no interface defined"
		return 1
	fi
}

case "${1}" in
	start)
		if [ -n "${MiniUPnPd_PRESTART_COMMAND}" ] ; then
			${MiniUPnPd_PRESTART_COMMAND}
			exit $?
		fi
		check_miniupnpd || exit 2
		if [ "${system_backend}" = nftables ] ; then
			"${SCRIPT_DIR}/nft_init.sh"
		elif get_ext_ifname ; then
			"${SCRIPT_DIR}/iptables_init.sh" -i "${ext_ifname}"
			if [ "${MiniUPnPd_ip6tables_enable}" = 1 ] ; then
				"${SCRIPT_DIR}/ip6tables_init.sh" -i "${ext_ifname6}"
			fi
		fi
		;;

	stop)
		if [ -n "${MiniUPnPd_POSTSTOP_COMMAND}" ] ; then
			${MiniUPnPd_POSTSTOP_COMMAND}
			exit $?
		fi
		check_miniupnpd || exit 2
		if [ "${system_backend}" = nftables ] ; then
			"${SCRIPT_DIR}/nft_removeall.sh"
		elif get_ext_ifname ; then
			"${SCRIPT_DIR}/iptables_removeall.sh" -i "${ext_ifname}"
			if [ "${MiniUPnPd_ip6tables_enable}" = 1 ] ; then
				"${SCRIPT_DIR}/ip6tables_removeall.sh" -i "${ext_ifname6}"
			fi
		fi
		;;

	*)
		echo "Usage: ${0} {start|stop}"
		exit 1
		;;
esac

exit 0

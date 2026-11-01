#! /bin/sh
# vim: tabstop=4 shiftwidth=4

if [ ! -x "$NFT" ] ; then
NFT=$(which nft) || {
	echo "Can't find nft" >&2
	exit 1
}
fi

$NFT list tables > /dev/null
if [ $? -ne 0 ] ; then
	echo "nft error" >&2
	exit 1
fi

# nft support the following address families :
# ip       IPv4 address family.
# ip6      IPv6 address family.
# inet     Internet (IPv4/IPv6) address family.
af=inet
TABLE="filter"
NAT_TABLE="filter"
CHAIN="miniupnpd"
PREROUTING_CHAIN="prerouting_miniupnpd"
POSTROUTING_CHAIN="postrouting_miniupnpd"

while getopts ":t:n:c:p:r:f:h" opt; do
	case $opt in
		t)
			TABLE=$OPTARG
			;;
		n)
			NAT_TABLE=$OPTARG
			;;
		c)
			CHAIN=$OPTARG
			;;
		p)
			PREROUTING_CHAIN=$OPTARG
			;;
		r)
			POSTROUTING_CHAIN=$OPTARG
			;;
		f)
			conf=$OPTARG
			if [ ! -r "$conf" ] ; then
				echo "$conf is unreadable" >&2
				exit 1
			fi
			for line in $(grep -E '^[a-z_]+=' $conf | sed 's/\s*#.*//') ; do
				v=$(echo "$line" | cut -d= -f2)
				case $line in
					upnp_table_name=*) TABLE=$v ;;
					upnp_nat_table_name=*) NAT_TABLE=$v ;;
					upnp_forward_chain=*) CHAIN=$v ;;
					upnp_nat_chain=*) PREROUTING_CHAIN=$v ;;
					upnp_nat_postrouting_chain=*) POSTROUTING_CHAIN=$v ;;
					upnp_nftables_family_split=*) if [ "$v" = "yes" ] ; then af=ip ; fi ;;
				esac
			done
			echo "TABLE=$TABLE"
			;;
		h)
			echo "Usage: $0 [options]"
			echo
			echo "Options:"
			echo "  -f /to/miniupnpd.conf read table and chain names from miniupnpd.conf"
			echo "  -t table              upnp_table_name in miniupnpd.conf"
			echo "  -n nat_table          upnp_nat_table_name in miniupnpd.conf"
			echo "  -c chain              upnp_forward_chain in miniupnpd.conf"
			echo "  -p nat_chain          upnp_nat_chain in miniupnpd.conf"
			echo "  -r postrouting_chain  upnp_nat_postrouting_chain in miniupnpd.conf"
			exit 0
			;;
		\?)
			echo "Invalid option: -$OPTARG" >&2
			echo "To show usage: $0 -h" >&2
			exit 1
			;;
		:)
			echo "Option -$OPTARG requires an argument." >&2
			exit 1
			;;
	esac
done

# FILTER policies use private base chains so updates cannot briefly expose an
# unrestricted mapping.  Remove only the exact names owned by the daemon.
remove_pcp_filter_chains() {
	pcp_filter_families=$af
	if [ "$af" = ip ]; then
		pcp_filter_families="ip ip6"
	fi
	for pcp_filter_family in $pcp_filter_families; do
		$NFT list table "$pcp_filter_family" "$TABLE" 2>/dev/null |
			sed -n 's/^[[:space:]]*chain \(pcp-filter-[0-9a-f]\{32\}-[0-9a-f]\{4\}-[0-9a-f]\{2\}\) {.*/\1/p' |
			while IFS= read -r pcp_filter_chain; do
				$NFT flush chain "$pcp_filter_family" "$TABLE" "$pcp_filter_chain"
				$NFT delete chain "$pcp_filter_family" "$TABLE" "$pcp_filter_chain"
			done
	done
}

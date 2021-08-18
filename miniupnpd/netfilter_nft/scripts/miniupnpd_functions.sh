#! /bin/sh

NFT=$(which nft) || {
	echo "Can't find nft" >&2
	exit 1
}

TABLE="filter"
NAT_TABLE="filter"
CHAIN="miniupnpd"
PREROUTEING_CHAIN="prerouting_miniupnpd"
POSTROUTEING_CHAIN="postrouting_miniupnpd"

while getopts ":t:n:c:p:r:" opt; do
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
			PREROUTEING_CHAIN=$OPTARG
			;;
		r)
			POSTROUTEING_CHAIN=$OPTARG
			;;
		\?)
			echo "Invalid option: -$OPTARG" >&2
			exit 1
			;;
		:)
			echo "Option -$OPTARG requires an argument." >&2
			exit 1
			;;
	esac
done

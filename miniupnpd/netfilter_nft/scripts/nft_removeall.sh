#!/bin/sh
#
# Undo the things nft_init.sh did
#
# Do not disturb other existing structures in nftables, e.g. those created by firewalld
#

nft --check list table inet miniupnpd > /dev/null 2>&1
if [ $? -eq "0" ]; then
{
	# table exists, so first remove the nat chains we added
	nft --check list chain inet miniupnpd prerouting > /dev/null 2>&1
	if [ $? -eq "0" ]; then
		echo "Remove nat chain from miniupnpd table"
		nft delete chain inet miniupnpd prerouting
	fi

	nft --check list chain inet miniupnpd postrouting > /dev/null 2>&1
	if [ $? -eq "0" ]; then
		echo "Remove pcp peer chain from miniupnpd table"
		nft delete chain inet miniupnpd postrouting
	fi

	# remove the filter chain we added
	nft --check list chain inet miniupnpd forward > /dev/null 2>&1
	if [ $? -eq "0" ]; then
		echo "Remove filter chain from miniupnpd table"
		nft delete chain inet miniupnpd forward
	fi

	# then remove the table itself
	echo "Remove miniupnpd table"
	nft delete table inet miniupnpd
}
fi

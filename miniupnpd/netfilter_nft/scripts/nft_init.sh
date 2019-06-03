#! /bin/sh

nft list table nat > /dev/null
nft_nat_exists=$?
nft list table filter > /dev/null
nft_filter_exists=$?
nft list table mangle > /dev/null
nft_mangle_exists=$?

if [ $nft_nat_exists -eq "1" ]; then
	echo "create nat"
	nft "add table nat"
fi
if [ $nft_filter_exists -eq "1" ]; then
	echo "create filter"
	nft "add table inet filter"
fi
if [ $nft_mangle_exists -eq "1" ]; then
	echo "create mangle"
	nft "add table mangle"
fi

nft list chain nat MINIUPNPD > /dev/null
nft_nat_miniupnpd_exists=$?
nft list chain nat MINIUPNPD-POSTROUTING > /dev/null
nft_nat_miniupnpd_pcp_peer_exists=$?
nft list chain filter MINIUPNPD > /dev/null
nft_filter_miniupnpd_exists=$?
nft list chain mangle MINIUPNPD > /dev/null
nft_mangle_miniupnpd_exists=$?

if [ $nft_nat_miniupnpd_exists -eq "1" ]; then
	echo "create chain in nat"
	nft "add chain nat MINIUPNPD"
fi
if [ $nft_nat_miniupnpd_pcp_peer_exists -eq "1" ]; then
	echo "create pcp peer chain in nat"
	nft "add chain nat MINIUPNPD-POSTROUTING"
fi
if [ $nft_filter_miniupnpd_exists -eq "1" ]; then
	echo "create chain in filter "
	nft "add chain filter MINIUPNPD"
fi
if [ $nft_mangle_miniupnpd_exists -eq "1" ]; then
	echo "create chain in mangle"
	nft "add chain mangle MINIUPNPD"
fi

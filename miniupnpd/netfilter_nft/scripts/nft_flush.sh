#!/bin/sh
# remove all rules created by miniupnpd

. "$(dirname "$0")/miniupnpd_functions.sh"

remove_pcp_filter_chains

$NFT flush chain $af $TABLE $CHAIN
$NFT flush chain $af $NAT_TABLE $PREROUTING_CHAIN
$NFT flush chain $af $NAT_TABLE $POSTROUTING_CHAIN

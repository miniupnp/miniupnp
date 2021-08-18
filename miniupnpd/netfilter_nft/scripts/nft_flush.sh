#!/bin/sh

. $(dirname "$0")/miniupnpd_functions.sh

$NFT flush chain inet $TABLE $CHAIN
$NFT flush chain inet $NAT_TABLE $PREROUTEING_CHAIN
$NFT flush chain inet $NAT_TABLE $POSTROUTEING_CHAIN

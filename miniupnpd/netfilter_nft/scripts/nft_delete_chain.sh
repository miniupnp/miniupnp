#!/bin/sh

. $(dirname "$0")/miniupnpd_functions.sh

# Prerouting
$NFT delete chain inet $NAT_TABLE $PREROUTEING_CHAIN
# Postrouting
$NFT delete chain inet $NAT_TABLE $POSTROUTEING_CHAIN
# Filter
$NFT delete chain inet $TABLE $CHAIN

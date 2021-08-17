#!/bin/sh
#
# establish the chains that miniupnpd will update dynamically
#
# 'add' doesn't raise an error if the object already exists. 'create' does.
#

#opts="--echo"

echo "create table"
nft ${opts} add table inet miniupnpd

echo "create NAT chain table"
nft ${opts} add chain inet miniupnpd preouting

echo "create pcp peer chain in table"
nft ${opts} add chain inet miniupnpd postrouting

echo "create filter chain in table"
nft ${opts} add chain inet miniupnpd forward

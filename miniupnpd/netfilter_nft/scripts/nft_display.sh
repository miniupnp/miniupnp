#!/bin/sh

# Prerouting
nft list chain inet miniupnpd prerouting
# Postrouting
nft list chain inet miniupnpd postrouting
# Filter
nft list chain inet miniupnpd forward

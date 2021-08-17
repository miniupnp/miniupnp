#!/bin/sh

nft flush chain inet miniupnpd prerouting
nft flush chain inet miniupnpd postrouting
nft flush chain inet miniupnpd filter

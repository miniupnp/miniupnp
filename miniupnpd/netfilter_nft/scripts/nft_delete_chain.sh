#! /sbin/nft -f

delete chain nat MINIUPNPD
delete chain nat MINIUPNPD-POSTROUTING
delete chain filter MINIUPNPD

#! /sbin/nft -f

delete rule nat MINIUPNPD
delete rule nat MINIUPNPD-POSTROUTING
delete rule filter MINIUPNPD

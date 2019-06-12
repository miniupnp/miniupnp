#! /sbin/nft -f

flush chain ip nat MINIUPNPD
flush chain ip nat MINIUPNPD-POSTROUTING
flush chain inet filter MINIUPNPD

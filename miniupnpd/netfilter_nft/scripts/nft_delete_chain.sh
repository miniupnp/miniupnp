#!/bin/sh

nft delete chain miniupnpd forward
nft delete chain miniupnpd postrouting
nft delete chain miniupnpd prerouting

#!/bin/sh
# $Id: testminissdpd.sh,v 1.1 2015/08/06 10:17:51 nanard Exp $
# (c) 2015 Thomas Bernard

IF=lo
SOCKET=`mktemp`
PID="${SOCKET}.pid"
./minissdpd -s $SOCKET -p $PID -i $IF  || exit 1
./testminissdpd -s $SOCKET || exit 2
kill `cat $PID`

#!/bin/sh
# $Id: testminissdpd.sh,v 1.8 2017/04/21 11:57:59 nanard Exp $
# (c) 2017 Thomas Bernard

OS=`uname -s`

# if set, 1st argument is network interface
if [ -n "$1" ] ; then
	IF=$1
else
	case $OS in
		*BSD | Darwin | SunOS)
			IF=lo0
			;;
		*)
			IF=lo
			;;
	esac
fi

SOCKET=`mktemp -t minissdpdsocketXXXXXX`
PID="${SOCKET}.pid"
./minissdpd -s $SOCKET -p $PID -i $IF  || exit 1
./testminissdpd -s $SOCKET || exit 2
kill `cat $PID`

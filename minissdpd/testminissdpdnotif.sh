#!/bin/sh
# $Id: $
# (c) 2016 Thomas Bernard

OS=`uname -s`
IF=lo
if [ "$OS" = "Darwin" ] ; then
	IF=lo0
fi
# if set, 1st argument is network interface
if [ -n "$1" ] ; then
	IF=$1
fi
SOCKET=`mktemp -t minissdpdsocketXXXXXX`
PID="${SOCKET}.pid"
./minissdpd -s $SOCKET -p $PID -i $IF  || exit 1
./showminissdpdnotif -s $SOCKET || exit 2
kill `cat $PID`

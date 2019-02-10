#!/bin/sh
# $Id: testminissdpdnotif.sh,v 1.4 2019/02/10 13:39:18 nanard Exp $
# (c) 2019 Thomas Bernard

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

# trap sigint in the script so CTRL-C interrupts the running program,
# not the script
trap 'echo SIGINT' INT

SOCKET=`mktemp -t minissdpdsocketXXXXXX`
PID="${SOCKET}.pid"
./minissdpd -s $SOCKET -p $PID -i $IF  || exit 1
sleep .5
echo "minissdpd process id `cat $PID`"
./showminissdpdnotif -s $SOCKET
echo "showminissdpdnotif returned $?"
kill `cat $PID`

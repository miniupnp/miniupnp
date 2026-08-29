#!/bin/sh

TMPD=`mktemp -d -t upnphttpXXXXXXXXXX`
if [ -z "$HTTPSERVER" ] ; then
  HTTPSERVER=./testupnphttp
fi
HTTPSERVEROUT="${TMPD}/httpserverout"

$HTTPSERVER > $HTTPSERVEROUT &
SERVERPID=$!
while [ -z "$PORT" ]; do
  sleep 1
  ls -l $HTTPSERVEROUT
  cat $HTTPSERVEROUT
  PORT=`cat $HTTPSERVEROUT | sed 's/^Listening on port \([0-9]*\)$/\1/'`
done
echo "port=$PORT pid=$SERVERPID"
RET=0

if curl --fail-with-body -v "http://127.0.0.1:${PORT}/rootDesc.xml" ; then
  echo
  echo "ok"
else
  echo
  echo "test FAILED"
  RET=1
fi

kill $SERVERPID
wait $SERVERPID
rm $HTTPSERVEROUT
rmdir $TMPD
exit $RET

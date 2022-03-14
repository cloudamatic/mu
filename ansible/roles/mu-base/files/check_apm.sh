#!/bin/sh

errs=`/bin/sudo /bin/apm-server test output | grep "ERROR"`
warns=`/bin/sudo /bin/apm-server test output | grep -v " server's certificate chain verification is disabled" | grep WARN` # XXX might be nice to care about this
oks=`/bin/sudo /bin/apm-server test output | grep OK`

if [ "$errs" != "" ];then
  echo $errs
  exit 2
elif [ "$warns" != "" ];then
  echo $warns
  exit 1
elif [ "$oks" != "" ];then
  /bin/sudo /bin/apm-server test output
  exit 0
else
  exit 3
fi

#!/bin/sh

status=`curl -XGET 'localhost:9600/_node/stats/pipelines?pretty' | grep '^  "status" :' | cut -d: -f2 | cut -d\" -f2`

echo $status
if [ "$status" == "green" ];then
  exit 0
elif [ "$status" == "yellow" ];then
  exit 1
elif [ "$status" == "red" ];then
  exit 2
else
  exit 3
fi

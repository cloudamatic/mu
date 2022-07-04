#!/bin/sh

errs=`/bin/sudo /bin/tail -100 /var/log/elasticsearch/elasticsearch.log | grep "maximum normal shards open"`
code=$?

if [ "$errs" != "" ];then
  echo $errs
  exit 2
else
  /bin/sudo /bin/grep shards /var/log/elasticsearch/elasticsearch.log | tail -1
  exit 0
fi

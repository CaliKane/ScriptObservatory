#!/bin/bash
#

foo=0123456789abcdef
for (( i=0; i<${#foo}; i++ )); do
  for (( j=0; j<${#foo}; j++ )); do
    echo "gzip ./static/script-content/${foo:$i:1}${foo:$j:1}*txt"
    gzip ./static/script-content/${foo:$i:1}${foo:$j:1}*txt
  done
done

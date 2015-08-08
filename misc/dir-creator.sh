#!/bin/bash
#

foo=abcdef0123456789
for (( i=0; i<${#foo}; i++ )); do
  for (( j=0; j<${#foo}; j++ )); do
    for (( k=0; k<${#foo}; k++ )); do
      for (( l=0; l<${#foo}; l++ )); do
        echo "mv -f script-content/${foo:$i:1}${foo:$j:1}${foo:$k:1}${foo:$l:1}* script-content/${foo:$i:1}${foo:$j:1}${foo:$k:1}${foo:$l:1}/"
        mv -f script-content/${foo:$i:1}${foo:$j:1}${foo:$k:1}${foo:$l:1}* script-content/${foo:$i:1}${foo:$j:1}${foo:$k:1}${foo:$l:1}/
      done
    done
  done
done

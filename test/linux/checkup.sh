#!/bin/bash
if [ $# = 1 ]; then
  filename=`basename $1`
  expected=`grep " $filename\$" ../CHECKSUMS | awk '{print $1}'`
  actual=`sha256sum $1 | awk '{print $1}'`
  if [ "$expected" = "$actual" ]; then
    echo "CHECKSUMS MATCH!"
    exit 0
  else
    echo "CHECKSUMS MISMATCH!"
    exit 1
  fi
else
  cmp $1 $2
  if [ $? = 0 ]; then
    echo "FILES MATCH!"
    exit 0
  else
    echo "FILES MISMATCH!"
    exit 1
  fi
fi

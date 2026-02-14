#!/bin/bash

. ./settings

filename=`basename $1`
expected=`grep " $filename\$" ../CHECKSUMS | awk '{print $1}'`
actual=`$command sha256 -i $1`
test "$expected" = "$actual"

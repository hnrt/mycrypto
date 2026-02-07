#!/bin/bash -x

. ./settings

expected=`grep " $1\$" ../CHECKSUMS | awk '{print $1}'`
actual=`$command sha256 -i $1`
test "$expected" = "$actual"

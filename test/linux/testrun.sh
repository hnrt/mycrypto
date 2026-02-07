#!/bin/sh

successful=""
failed=""

./ecbtest.sh
if [ $? = 0 ]; then
  successful="$successful ECB"
else
  failed="$failed ECB"
fi

./cbctest.sh
if [ $? = 0 ]; then
  successful="$successful CBC"
else
  failed="$failed CBC"
fi

./cfb1test.sh
if [ $? = 0 ]; then
  successful="$successful CFB1"
else
  failed="$failed CFB1"
fi

./cfb8test.sh
if [ $? = 0 ]; then
  successful="$successful CFB8"
else
  failed="$failed CFB8"
fi

./cfb128test.sh
if [ $? = 0 ]; then
  successful="$successful CFB128"
else
  failed="$failed CFB128"
fi

./ccmtest.sh
if [ $? = 0 ]; then
  successful="$successful CCM"
else
  failed="$failed CCM"
fi

./gcmtest.sh
if [ $? = 0 ]; then
  successful="$successful GCM"
else
  failed="$failed GCM"
fi

if [ "$successful" != "" ]; then
  echo "OK:$successful"
fi
if [ "$failed" != "" ]; then
  echo "FAILED:$failed"
fi

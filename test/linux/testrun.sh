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

./cfbtest.sh
if [ $? = 0 ]; then
  successful="$successful CFB"
else
  failed="$failed CFB"
fi

./cfb8test.sh
if [ $? = 0 ]; then
  successful="$successful CFB8"
else
  failed="$failed CFB8"
fi

./ofbtest.sh
if [ $? = 0 ]; then
  successful="$successful OFB"
else
  failed="$failed OFB"
fi

./ctrtest.sh
if [ $? = 0 ]; then
  successful="$successful CTR"
else
  failed="$failed CTR"
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

echo "RESULT SUMMARY:"
if [ "$successful" != "" ]; then
  echo "OK:$successful"
fi
if [ "$failed" != "" ]; then
  echo "FAILED:$failed"
fi

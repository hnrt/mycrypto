#!/bin/bash

. ./settings

if [ -d tmp ]; then rm -f tmp/*.ofb128 ; else mkdir tmp ; fi

$command aes-256-ofb -e -i ../plaintext44.txt -o tmp/ciphertext44.ofb128 -p $pp -iv $iv
./checkup.sh tmp/ciphertext44.ofb128 || exit 1

$command aes-256-ofb -d -i tmp/ciphertext44.ofb128 -o tmp/plaintext44.ofb128 -p $pp
./checkup.sh ../plaintext44.txt tmp/plaintext44.ofb128 || exit 2

$command aes-256-ofb -e -i ../plaintext6570.txt -o tmp/ciphertext6570.ofb128 -p $pp -iv $iv
./checkup.sh tmp/ciphertext6570.ofb128 || exit 3

$command aes-256-ofb -d -i tmp/ciphertext6570.ofb128 -o tmp/plaintext6570.ofb128 -p $pp
./checkup.sh ../plaintext6570.txt tmp/plaintext6570.ofb128 || exit 4

$command aes-256-ofb -e -i ../plaintext2M.jpg -o tmp/ciphertext2M.ofb128 -p $pp -iv $iv
./checkup.sh tmp/ciphertext2M.ofb128 || exit 5

$command aes-256-ofb -d -i tmp/ciphertext2M.ofb128 -o tmp/plaintext2M.ofb128 -p $pp
./checkup.sh ../plaintext2M.jpg tmp/plaintext2M.ofb128 || exit 6

echo "AES-OFB LOOKS GOOD!"

exit 0

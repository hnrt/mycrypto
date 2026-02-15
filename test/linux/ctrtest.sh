#!/bin/bash

. ./settings

if [ -d tmp ]; then rm -f tmp/*.ctr ; else mkdir tmp ; fi

$command aes-256-ctr -e -i ../plaintext44.txt -o tmp/ciphertext44.ctr -p $pp -iv $iv
./checkup.sh tmp/ciphertext44.ctr || exit 1

$command aes-256-ctr -d -i tmp/ciphertext44.ctr -o tmp/plaintext44.ctr -p $pp
./checkup.sh ../plaintext44.txt tmp/plaintext44.ctr || exit 2

$command aes-256-ctr -e -i ../plaintext6570.txt -o tmp/ciphertext6570.ctr -p $pp -iv $iv
./checkup.sh tmp/ciphertext6570.ctr || exit 3

$command aes-256-ctr -d -i tmp/ciphertext6570.ctr -o tmp/plaintext6570.ctr -p $pp
./checkup.sh ../plaintext6570.txt tmp/plaintext6570.ctr || exit 4

$command aes-256-ctr -e -i ../plaintext2M.jpg -o tmp/ciphertext2M.ctr -p $pp -iv $iv
./checkup.sh tmp/ciphertext2M.ctr || exit 5

$command aes-256-ctr -d -i tmp/ciphertext2M.ctr -o tmp/plaintext2M.ctr -p $pp
./checkup.sh ../plaintext2M.jpg tmp/plaintext2M.ctr || exit 6

echo "AES-CTR LOOKS GOOD!"

exit 0

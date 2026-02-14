#!/bin/bash

. ./settings

if [ -d tmp ]; then rm -f tmp/*.ecb ; else mkdir tmp ; fi

$command aes-256-ecb -e -i ../plaintext44.txt -o tmp/ciphertext44.ecb -p $pp
./checkup.sh tmp/ciphertext44.ecb || exit 1

$command aes-256-ecb -d -i tmp/ciphertext44.ecb -o tmp/plaintext44.ecb -p $pp
cmp ../plaintext44.txt tmp/plaintext44.ecb || exit 2

$command aes-256-ecb -e -i ../plaintext6570.txt -o tmp/ciphertext6570.ecb -p $pp
./checkup.sh tmp/ciphertext6570.ecb || exit 3

$command aes-256-ecb -d -i tmp/ciphertext6570.ecb -o tmp/plaintext6570.ecb -p $pp
cmp ../plaintext6570.txt tmp/plaintext6570.ecb || exit 4

$command aes-256-ecb -e -i ../plaintext2M.jpg -o tmp/ciphertext2M.ecb -p $pp
./checkup.sh tmp/ciphertext2M.ecb || exit 5

$command aes-256-ecb -d -i tmp/ciphertext2M.ecb -o tmp/plaintext2M.ecb -p $pp
cmp ../plaintext2M.jpg tmp/plaintext2M.ecb || exit 6

echo "AES-ECB LOOKS GOOD!"

exit 0

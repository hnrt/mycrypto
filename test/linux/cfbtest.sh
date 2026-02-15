#!/bin/bash

. ./settings

if [ -d tmp ]; then rm -f tmp/*.cfb128 ; else mkdir tmp ; fi

$command aes-256-cfb -e -i ../plaintext44.txt -o tmp/ciphertext44.cfb128 -p $pp -iv $iv
./checkup.sh tmp/ciphertext44.cfb128 || exit 1

$command aes-256-cfb -d -i tmp/ciphertext44.cfb128 -o tmp/plaintext44.cfb128 -p $pp
./checkup.sh ../plaintext44.txt tmp/plaintext44.cfb128 || exit 2

$command aes-256-cfb -e -i ../plaintext6570.txt -o tmp/ciphertext6570.cfb128 -p $pp -iv $iv
./checkup.sh tmp/ciphertext6570.cfb128 || exit 3

$command aes-256-cfb -d -i tmp/ciphertext6570.cfb128 -o tmp/plaintext6570.cfb128 -p $pp
./checkup.sh ../plaintext6570.txt tmp/plaintext6570.cfb128 || exit 4

$command aes-256-cfb -e -i ../plaintext2M.jpg -o tmp/ciphertext2M.cfb128 -p $pp -iv $iv
./checkup.sh tmp/ciphertext2M.cfb128 || exit 5

$command aes-256-cfb -d -i tmp/ciphertext2M.cfb128 -o tmp/plaintext2M.cfb128 -p $pp
./checkup.sh ../plaintext2M.jpg tmp/plaintext2M.cfb128 || exit 6

echo "AES-CFB LOOKS GOOD!"

exit 0

#!/bin/bash

. ./settings

if [ -d tmp ]; then rm -f tmp/*.cfb8 ; else mkdir tmp ; fi

$command aes-256-cfb8 -e -i ../plaintext44.txt -o tmp/ciphertext44.cfb8 -p $pp -iv $iv
./checkup.sh tmp/ciphertext44.cfb8 || exit 1

$command aes-256-cfb8 -d -i tmp/ciphertext44.cfb8 -o tmp/plaintext44.cfb8 -p $pp
cmp ../plaintext44.txt tmp/plaintext44.cfb8 || exit 2

$command aes-256-cfb8 -e -i ../plaintext6570.txt -o tmp/ciphertext6570.cfb8 -p $pp -iv $iv
./checkup.sh tmp/ciphertext6570.cfb8 || exit 1

$command aes-256-cfb8 -d -i tmp/ciphertext6570.cfb8 -o tmp/plaintext6570.cfb8 -p $pp
cmp ../plaintext6570.txt tmp/plaintext6570.cfb8 || exit 4

$command aes-256-cfb8 -e -i ../plaintext2M.jpg -o tmp/ciphertext2M.cfb8 -p $pp -iv $iv
./checkup.sh tmp/ciphertext2M.cfb8 || exit 1

$command aes-256-cfb8 -d -i tmp/ciphertext2M.cfb8 -o tmp/plaintext2M.cfb8 -p $pp
cmp ../plaintext2M.jpg tmp/plaintext2M.cfb8 || exit 6

$command aes-256-cfb8 -e -i ../plaintext4096.zero -o tmp/ciphertext4096.cfb8 -p $pp -iv $iv
./checkup.sh tmp/ciphertext4096.cfb8 || exit 7

$command aes-256-cfb8 -d -i tmp/ciphertext4096.cfb8 -o tmp/plaintext4096.cfb8 -p $pp
cmp ../plaintext4096.zero tmp/plaintext4096.cfb8 || exit 8

echo "AES-CFB8 LOOKS GOOD!"

exit 0

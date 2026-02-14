#!/bin/bash

. ./settings

if [ -d tmp ]; then rm -f tmp/*.gcm ; else mkdir tmp ; fi

$command aes-256-gcm -e -i ../plaintext44.txt -o tmp/ciphertext44.gcm -p $pp -n $nonce12 -a $aad
./checkup.sh tmp/ciphertext44.gcm || exit 1

$command aes-256-gcm -d -i tmp/ciphertext44.gcm -o tmp/plaintext44.gcm -p $pp -a $aad
cmp ../plaintext44.txt tmp/plaintext44.gcm || exit 2

$command aes-256-gcm -e -i ../plaintext6570.txt -o tmp/ciphertext6570.gcm -p $pp -n $nonce12 -a $aad
./checkup.sh tmp/ciphertext6570.gcm || exit 3

$command aes-256-gcm -d -i tmp/ciphertext6570.gcm -o tmp/plaintext6570.gcm -p $pp -a $aad
cmp ../plaintext6570.txt tmp/plaintext6570.gcm || exit 4

$command aes-256-gcm -e -i ../plaintext2M.jpg -o tmp/ciphertext2M.gcm -p $pp -n $nonce12 -a $aad
./checkup.sh tmp/ciphertext2M.gcm || exit 5

$command aes-256-gcm -d -i tmp/ciphertext2M.gcm -o tmp/plaintext2M.gcm -p $pp -a $aad
cmp ../plaintext2M.jpg tmp/plaintext2M.gcm || exit 6

$command aes-256-gcm -d -i tmp/ciphertext2M.gcm -o tmp/plaintext2M-2.gcm -p $pp -a 123$aad && exit 7

echo "AES-GCM LOOKS GOOD!"

exit 0

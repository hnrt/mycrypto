#!/bin/bash

. ./settings

if [ -d tmp ]; then rm -f tmp/*.ccm ; else mkdir tmp ; fi

$command aes-256-ccm -e -i ../plaintext44.txt -o tmp/ciphertext44.ccm -p $pp -n $nonce7 -a $aad
./checkup.sh tmp/ciphertext44.ccm || exit 1

$command aes-256-ccm -d -i tmp/ciphertext44.ccm -o tmp/plaintext44.ccm -p $pp -a $aad
./checkup.sh ../plaintext44.txt tmp/plaintext44.ccm || exit 2

$command aes-256-ccm -d -i tmp/ciphertext44.ccm -o tmp/plaintext44-1.ccm -p $pp -a 123$aad && exit 12

$command aes-256-ccm -e -i ../plaintext6570.txt -o tmp/ciphertext6570.ccm -p $pp -n $nonce7 -a $aad
./checkup.sh tmp/ciphertext6570.ccm || exit 3

$command aes-256-ccm -d -i tmp/ciphertext6570.ccm -o tmp/plaintext6570.ccm -p $pp -a $aad
./checkup.sh ../plaintext6570.txt tmp/plaintext6570.ccm || exit 4

$command aes-256-ccm -e -i ../plaintext2M.jpg -o tmp/ciphertext2M-0.ccm -p $pp -n $nonce7
./checkup.sh tmp/ciphertext2M-0.ccm || exit 8

$command aes-256-ccm -d -i tmp/ciphertext2M-0.ccm -o tmp/plaintext2M-0.ccm -p $pp
./checkup.sh ../plaintext2M.jpg tmp/plaintext2M-0.ccm || exit 9

$command aes-256-ccm -e -i ../plaintext2M.jpg -o tmp/ciphertext2M.ccm -p $pp -n $nonce7 -a $aad
./checkup.sh tmp/ciphertext2M.ccm || exit 5

$command aes-256-ccm -d -i tmp/ciphertext2M.ccm -o tmp/plaintext2M.ccm -p $pp -a $aad
./checkup.sh ../plaintext2M.jpg tmp/plaintext2M.ccm || exit 6

$command aes-256-ccm -d -i tmp/ciphertext2M.ccm -o tmp/plaintext2M-1.ccm -p $pp -a ${aad}123 && exit 7

echo "AES-CCM LOOKS GOOD!"

exit 0

#!/bin/bash -x

. ./settings

rm -f ./*.gcm

$command aes-256-gcm -e -i ../plaintext44.txt -o ciphertext44.gcm -p $pp -iv $nonce12 -aad $aad
./checkup.sh ciphertext44.gcm || exit 1

$command aes-256-gcm -d -i ciphertext44.gcm -o plaintext44.gcm -p $pp -aad $aad
cmp ../plaintext44.txt plaintext44.gcm || exit 2

$command aes-256-gcm -e -i ../plaintext6570.txt -o ciphertext6570.gcm -p $pp -iv $nonce12 -aad $aad
./checkup.sh ciphertext6570.gcm || exit 3

$command aes-256-gcm -d -i ciphertext6570.gcm -o plaintext6570.gcm -p $pp -aad $aad
cmp ../plaintext6570.txt plaintext6570.gcm || exit 4

$command aes-256-gcm -e -i ../plaintext2M.jpg -o ciphertext2M.gcm -p $pp -iv $nonce12 -aad $aad
./checkup.sh ciphertext2M.gcm || exit 5

$command aes-256-gcm -d -i ciphertext2M.gcm -o plaintext2M.gcm -p $pp -aad $aad
cmp ../plaintext2M.jpg plaintext2M.gcm || exit 6

$command aes-256-gcm -d -i ciphertext2M.gcm -o plaintext2M-2.gcm -p $pp -aad 123$aad && exit 7

exit 0

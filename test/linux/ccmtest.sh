#!/bin/bash -x

. ./settings

rm -f ./*.ccm

$command aes-256-ccm -e -i ../plaintext44.txt -o ciphertext44.ccm -p $pp -n $nonce7 -a $aad
./checkup.sh ciphertext44.ccm || exit 1

$command aes-256-ccm -d -i ciphertext44.ccm -o plaintext44.ccm -p $pp -a $aad
cmp ../plaintext44.txt plaintext44.ccm || exit 2

$command aes-256-ccm -d -i ciphertext44.ccm -o plaintext44-1.ccm -p $pp -a 123$aad && exit 12

$command aes-256-ccm -e -i ../plaintext6570.txt -o ciphertext6570.ccm -p $pp -n $nonce7 -a $aad
./checkup.sh ciphertext6570.ccm || exit 3

$command aes-256-ccm -d -i ciphertext6570.ccm -o plaintext6570.ccm -p $pp -a $aad
cmp ../plaintext6570.txt plaintext6570.ccm || exit 4

$command aes-256-ccm -e -i ../plaintext2M.jpg -o ciphertext2M-0.ccm -p $pp -n $nonce7
./checkup.sh ciphertext2M-0.ccm || exit 8

$command aes-256-ccm -d -i ciphertext2M-0.ccm -o plaintext2M-0.ccm -p $pp
cmp ../plaintext2M.jpg plaintext2M-0.ccm || exit 9

$command aes-256-ccm -e -i ../plaintext2M.jpg -o ciphertext2M.ccm -p $pp -n $nonce7 -a $aad
./checkup.sh ciphertext2M.ccm || exit 5

$command aes-256-ccm -d -i ciphertext2M.ccm -o plaintext2M.ccm -p $pp -a $aad
cmp ../plaintext2M.jpg plaintext2M.ccm || exit 6

$command aes-256-ccm -d -i ciphertext2M.ccm -o plaintext2M-1.ccm -p $pp -a ${aad}123 && exit 7

exit 0

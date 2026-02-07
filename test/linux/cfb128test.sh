#!/bin/bash -x

. ./settings

rm -f ./*.cfb128

$command aes-256-cfb128 -e -i ../plaintext44.txt -o ciphertext44.cfb128 -p $pp -iv $iv
./checkup.sh ciphertext44.cfb128 || exit 1

$command aes-256-cfb128 -d -i ciphertext44.cfb128 -o plaintext44.cfb128 -p $pp
cmp ../plaintext44.txt plaintext44.cfb128 || exit 2

$command aes-256-cfb128 -e -i ../plaintext6570.txt -o ciphertext6570.cfb128 -p $pp -iv $iv
./checkup.sh ciphertext6570.cfb128 || exit 3

$command aes-256-cfb128 -d -i ciphertext6570.cfb128 -o plaintext6570.cfb128 -p $pp
cmp ../plaintext6570.txt plaintext6570.cfb128 || exit 4

$command aes-256-cfb128 -e -i ../plaintext2M.jpg -o ciphertext2M.cfb128 -p $pp -iv $iv
./checkup.sh ciphertext2M.cfb128 || exit 5

$command aes-256-cfb128 -d -i ciphertext2M.cfb128 -o plaintext2M.cfb128 -p $pp
cmp ../plaintext2M.jpg plaintext2M.cfb128 || exit 6

exit 0

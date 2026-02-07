#!/bin/bash -x

. ./settings

rm -f ./*.cfb1

$command aes-256-cfb1 -e -i ../plaintext44.txt -o ciphertext44.cfb1 -p $pp -iv $iv
./checkup.sh ciphertext44.cfb1 || exit 1

$command aes-256-cfb1 -d -i ciphertext44.cfb1 -o plaintext44.cfb1 -p $pp
cmp ../plaintext44.txt plaintext44.cfb1 || exit 2

$command aes-256-cfb1 -e -i ../plaintext6570.txt -o ciphertext6570.cfb1 -p $pp -iv $iv
./checkup.sh ciphertext6570.cfb1 || exit 1

$command aes-256-cfb1 -d -i ciphertext6570.cfb1 -o plaintext6570.cfb1 -p $pp
cmp ../plaintext6570.txt plaintext6570.cfb1 || exit 4

$command aes-256-cfb1 -e -i ../plaintext2M.jpg -o ciphertext2M.cfb1 -p $pp -iv $iv
./checkup.sh ciphertext2M.cfb1 || exit 1

$command aes-256-cfb1 -d -i ciphertext2M.cfb1 -o plaintext2M.cfb1 -p $pp
cmp ../plaintext2M.jpg plaintext2M.cfb1 || exit 6

exit 0

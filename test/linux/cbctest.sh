#!/bin/bash -x

. ./settings

rm -f ./*.cbc

$command aes-256-cbc -e -i ../plaintext44.txt -o ciphertext44.cbc -p $pp -iv $iv
./checkup.sh ciphertext44.cbc || exit 1

$command aes-256-cbc -d -i ciphertext44.cbc -o plaintext44.cbc -p $pp
cmp ../plaintext44.txt plaintext44.cbc || exit 2

$command aes-256-cbc -e -i ../plaintext6570.txt -o ciphertext6570.cbc -p $pp -iv $iv
./checkup.sh ciphertext6570.cbc || exit 3

$command aes-256-cbc -d -i ciphertext6570.cbc -o plaintext6570.cbc -p $pp
cmp ../plaintext6570.txt plaintext6570.cbc || exit 4

$command aes-256-cbc -e -i ../plaintext2M.jpg -o ciphertext2M.cbc -p $pp -iv $iv
./checkup.sh ciphertext2M.cbc || exit 5

$command aes-256-cbc -d -i ciphertext2M.cbc -o plaintext2M.cbc -p $pp
cmp ../plaintext2M.jpg plaintext2M.cbc || exit 6

$command aes-256-cbc -e -i ../plaintext4096.zero -o ciphertext4096.cbc -p $pp -iv $iv
./checkup.sh ciphertext4096.cbc || exit 7

$command aes-256-cbc -d -i ciphertext4096.cbc -o plaintext4096.cbc -p $pp
cmp ../plaintext4096.zero plaintext4096.cbc || exit 8

exit 0

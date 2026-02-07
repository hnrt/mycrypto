#!/bin/bash -x

. ./settings

rm -f ./*.ecb

$command aes-256-ecb -e -i ../plaintext44.txt -o ciphertext44.ecb -p $pp
./checkup.sh ciphertext44.ecb || exit 1

$command aes-256-ecb -d -i ciphertext44.ecb -o plaintext44.ecb -p $pp
cmp ../plaintext44.txt plaintext44.ecb || exit 2

$command aes-256-ecb -e -i ../plaintext6570.txt -o ciphertext6570.ecb -p $pp
./checkup.sh ciphertext6570.ecb || exit 3

$command aes-256-ecb -d -i ciphertext6570.ecb -o plaintext6570.ecb -p $pp
cmp ../plaintext6570.txt plaintext6570.ecb || exit 4

$command aes-256-ecb -e -i ../plaintext2M.jpg -o ciphertext2M.ecb -p $pp
./checkup.sh ciphertext2M.ecb || exit 5

$command aes-256-ecb -d -i ciphertext2M.ecb -o plaintext2M.ecb -p $pp
cmp ../plaintext2M.jpg plaintext2M.ecb || exit 6

exit 0

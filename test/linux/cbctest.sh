#!/bin/bash

. ./settings

if [ -d tmp ]; then rm -f tmp/*.cbc ; else mkdir tmp ; fi

$command aes-256-cbc -e -i ../plaintext44.txt -o tmp/ciphertext44.cbc -p $pp -iv $iv
./checkup.sh tmp/ciphertext44.cbc || exit 1

$command aes-256-cbc -d -i tmp/ciphertext44.cbc -o tmp/plaintext44.cbc -p $pp
./checkup.sh ../plaintext44.txt tmp/plaintext44.cbc || exit 2

$command aes-256-cbc -e -i ../plaintext6570.txt -o tmp/ciphertext6570.cbc -p $pp -iv $iv
./checkup.sh tmp/ciphertext6570.cbc || exit 3

$command aes-256-cbc -d -i tmp/ciphertext6570.cbc -o tmp/plaintext6570.cbc -p $pp
./checkup.sh ../plaintext6570.txt tmp/plaintext6570.cbc || exit 4

$command aes-256-cbc -e -i ../plaintext2M.jpg -o tmp/ciphertext2M.cbc -p $pp -iv $iv
./checkup.sh tmp/ciphertext2M.cbc || exit 5

$command aes-256-cbc -d -i tmp/ciphertext2M.cbc -o tmp/plaintext2M.cbc -p $pp
./checkup.sh ../plaintext2M.jpg tmp/plaintext2M.cbc || exit 6

$command aes-256-cbc -e -i ../plaintext4096.zero -o tmp/ciphertext4096.cbc -p $pp -iv $iv
./checkup.sh tmp/ciphertext4096.cbc || exit 7

$command aes-256-cbc -d -i tmp/ciphertext4096.cbc -o tmp/plaintext4096.cbc -p $pp
./checkup.sh ../plaintext4096.zero tmp/plaintext4096.cbc || exit 8

$command aes-256-cbc -e -i - -o tmp/ciphertext44-2.cbc -p $pp -iv $iv <../plaintext44.txt
./checkup.sh tmp/ciphertext44.cbc tmp/ciphertext44-2.cbc || exit 9

$command aes-256-cbc -d -i tmp/ciphertext44-2.cbc -o - -p $pp >tmp/plaintext44-2.cbc
./checkup.sh ../plaintext44.txt tmp/plaintext44-2.cbc || exit 10

$command aes-256-cbc -e -i ../plaintext44.txt -o - -p $pp -iv $iv >tmp/ciphertext44-3.cbc
./checkup.sh tmp/ciphertext44.cbc tmp/ciphertext44-3.cbc || exit 11

$command aes-256-cbc -d -i - -o tmp/plaintext44-3.cbc -p $pp <tmp/ciphertext44-3.cbc
./checkup.sh ../plaintext44.txt tmp/plaintext44-3.cbc || exit 12

$command aes-256-cbc -e -i - -o tmp/ciphertext2M-2.cbc -p $pp -iv $iv <../plaintext2M.jpg
./checkup.sh tmp/ciphertext2M.cbc tmp/ciphertext2M-2.cbc || exit 13

$command aes-256-cbc -d -i tmp/ciphertext2M-2.cbc -o - -p $pp >tmp/plaintext2M-2.cbc
./checkup.sh ../plaintext2M.jpg tmp/plaintext2M-2.cbc || exit 14

$command aes-256-cbc -e -i ../plaintext2M.jpg -o - -p $pp -iv $iv >tmp/ciphertext2M-3.cbc
./checkup.sh tmp/ciphertext2M.cbc tmp/ciphertext2M-3.cbc || exit 15

$command aes-256-cbc -d -i - -o tmp/plaintext2M-3.cbc -p $pp <tmp/ciphertext2M-3.cbc
./checkup.sh ../plaintext2M.jpg tmp/plaintext2M-3.cbc || exit 16

echo "AES-CBC LOOKS GOOD!"

exit 0

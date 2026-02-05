#!/bin/sh -x

command=../../bin/linux/Debug/mycrypto

pp=ouch
iv=1075187BE7ADAEA7FB232A57ED173A17
nonce=9A39E08D4AA7752016E7094B
aad=abracadabra

sh ./cleanup.sh

$command aes-256-ecb -e -i ../plaintext44.txt -o ciphertext44.ecb -p $pp
$command aes-256-ecb -d -i ciphertext44.ecb -o plaintext44.ecb -p $pp
cmp ../ciphertext44.ecb ciphertext44.ecb || exit 1
diff ../plaintext44.txt plaintext44.ecb || exit 1

$command aes-256-ecb -e -i ../plaintext6570.txt -o ciphertext6570.ecb -p $pp
$command aes-256-ecb -d -i ciphertext6570.ecb -o plaintext6570.ecb -p $pp
cmp ../ciphertext6570.ecb ciphertext6570.ecb || exit 1
diff ../plaintext6570.txt plaintext6570.ecb || exit 1

$command aes-256-cbc -e -i ../plaintext44.txt -o ciphertext44.cbc -p $pp -iv $iv
$command aes-256-cbc -d -i ciphertext44.cbc -o plaintext44.cbc -p $pp
cmp ../ciphertext44.cbc ciphertext44.cbc || exit 1
diff ../plaintext44.txt plaintext44.cbc || exit 1

$command aes-256-cbc -e -i ../plaintext6570.txt -o ciphertext6570.cbc -p $pp -iv $iv
$command aes-256-cbc -d -i ciphertext6570.cbc -o plaintext6570.cbc -p $pp
cmp ../ciphertext6570.cbc ciphertext6570.cbc || exit 1
diff ../plaintext6570.txt plaintext6570.cbc || exit 1

$command aes-256-gcm -e -i ../plaintext44.txt -o ciphertext44.gcm -p $pp -iv $nonce -aad $aad
$command aes-256-gcm -d -i ciphertext44.gcm -o plaintext44.gcm -p $pp -aad $aad
cmp ../ciphertext44.gcm ciphertext44.gcm || exit 1
diff ../plaintext44.txt plaintext44.gcm || exit 1

$command aes-256-gcm -e -i ../plaintext6570.txt -o ciphertext6570.gcm -p $pp -iv $nonce -aad $aad
$command aes-256-gcm -d -i ciphertext6570.gcm -o plaintext6570.gcm -p $pp -aad $aad
cmp ../ciphertext6570.gcm ciphertext6570.gcm || exit 1
diff ../plaintext6570.txt plaintext6570.gcm || exit 1

$command aes-256-ccm -e -i ../plaintext44.txt -o ciphertext44.ccm -p $pp -iv $nonce -aad $aad
$command aes-256-ccm -d -i ciphertext44.ccm -o plaintext44.ccm -p $pp -aad $aad
cmp ../ciphertext44.ccm ciphertext44.ccm || exit 1
diff ../plaintext44.txt plaintext44.ccm || exit 1

$command aes-256-ccm -e -i ../plaintext6570.txt -o ciphertext6570.ccm -p $pp -iv $nonce -aad $aad
$command aes-256-ccm -d -i ciphertext6570.ccm -o plaintext6570.ccm -p $pp -aad $aad
cmp ../ciphertext6570.ccm ciphertext6570.ccm || exit 1
diff ../plaintext6570.txt plaintext6570.ccm || exit 1

echo 'PASS!'

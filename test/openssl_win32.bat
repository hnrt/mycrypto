setlocal
set command="C:\Program Files\git\usr\bin\openssl.exe"
set key=25A2B76224CDDB2F88A4AD8D806A7ED6AD00A2DF283C23A806F2DAD73D343E63
set iv=1075187BE7ADAEA7FB232A57ED173A17
%command% aes-256-cbc -e -in plaintext44.txt -out ciphertext44.tmp -K %key% -iv %iv%
copy /B /Y IV+ciphertext44.tmp ciphertext44.cbc
del ciphertext44.tmp
%command% aes-256-ecb -e -in plaintext44.txt -out ciphertext44.ecb -K %key%
%command% aes-256-cbc -e -in plaintext6570.txt -out ciphertext6570.tmp -K %key% -iv %iv%
copy /B /Y IV+ciphertext6570.tmp ciphertext6570.cbc
del ciphertext6570.tmp
%command% aes-256-ecb -e -in plaintext6570.txt -out ciphertext6570.ecb -K %key%

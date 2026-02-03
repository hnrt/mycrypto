setlocal
set command=..\..\bin\x64\Debug\mycrypto.exe
set pp=ouch
set iv=1075187BE7ADAEA7FB232A57ED173A17
del ciphertext44.cbc
del plaintext44.cbc
del ciphertext44.ecb
del plaintext44.ecb
del ciphertext6570.cbc
del plaintext6570.cbc
del ciphertext6570.ecb
del plaintext6570.ecb
%command% aes-256-cbc -e -i ..\plaintext44.txt -o ciphertext44.cbc -p %pp% -iv %iv%
%command% aes-256-cbc -d -i ciphertext44.cbc -o plaintext44.cbc -p %pp%
fc ..\ciphertext44.cbc ciphertext44.cbc
@if ERRORLEVEL 1 (
  @echo NOT PASS!
  @exit /B 1
)
fc ..\plaintext44.txt plaintext44.cbc
@if ERRORLEVEL 1 (
  @echo NOT PASS!
  @exit /B 1
)
%command% aes-256-ecb -e -i ..\plaintext44.txt -o ciphertext44.ecb -p %pp%
%command% aes-256-ecb -d -i ciphertext44.ecb -o plaintext44.ecb -p %pp%
fc ..\ciphertext44.ecb ciphertext44.ecb
@if ERRORLEVEL 1 (
  @echo NOT PASS!
  @exit /B 1
)
fc ..\plaintext44.txt plaintext44.ecb
@if ERRORLEVEL 1 (
  @echo NOT PASS!
  @exit /B 1
)
%command% aes-256-cbc -e -i ..\plaintext6570.txt -o ciphertext6570.cbc -p %pp% -iv %iv%
%command% aes-256-cbc -d -i ciphertext6570.cbc -o plaintext6570.cbc -p %pp%
fc ..\ciphertext6570.cbc ciphertext6570.cbc
@if ERRORLEVEL 1 (
  @echo NOT PASS!
  @exit /B 1
)
fc ..\plaintext6570.txt plaintext6570.cbc
@if ERRORLEVEL 1 (
  @echo NOT PASS!
  @exit /B 1
)
%command% aes-256-ecb -e -i ..\plaintext6570.txt -o ciphertext6570.ecb -p %pp%
%command% aes-256-ecb -d -i ciphertext6570.ecb -o plaintext6570.ecb -p %pp%
fc ..\ciphertext6570.ecb ciphertext6570.ecb
@if ERRORLEVEL 1 (
  @echo NOT PASS!
  @exit /B 1
)
fc ..\plaintext6570.txt plaintext6570.ecb
@if ERRORLEVEL 1 (
  @echo NOT PASS!
  @exit /B 1
)
@echo PASS!

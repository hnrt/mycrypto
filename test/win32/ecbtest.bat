SETLOCAL

CALL .\settings.bat

DEL .\*.ecb

%command% aes-256-ecb -e -i ..\plaintext44.txt -o ciphertext44.ecb -p %pp%
CALL .\checkup.bat ciphertext44.ecb
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-ecb -d -i ciphertext44.ecb -o plaintext44.ecb -p %pp%
FC ..\plaintext44.txt plaintext44.ecb
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-ecb -e -i ..\plaintext6570.txt -o ciphertext6570.ecb -p %pp%
CALL .\checkup.bat ciphertext6570.ecb
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-ecb -d -i ciphertext6570.ecb -o plaintext6570.ecb -p %pp%
FC ..\plaintext6570.txt plaintext6570.ecb
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-ecb -e -i ..\plaintext2M.jpg -o ciphertext2M.ecb -p %pp%
CALL .\checkup.bat ciphertext2M.ecb
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-ecb -d -i ciphertext2M.ecb -o plaintext2M.ecb -p %pp%
FC ..\plaintext2M.jpg plaintext2M.ecb
@IF ERRORLEVEL 1 @EXIT /B 6

@EXIT /B 0

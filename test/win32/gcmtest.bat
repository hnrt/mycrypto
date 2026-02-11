SETLOCAL

CALL .\settings.bat

DEL .\*.gcm

%command% aes-256-gcm -e -i ..\plaintext44.txt -o ciphertext44.gcm -p %pp% -n %nonce12% -a %aad%
CALL .\checkup.bat ciphertext44.gcm
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-gcm -d -i ciphertext44.gcm -o plaintext44.gcm -p %pp% -a %aad%
FC ..\plaintext44.txt plaintext44.gcm
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-gcm -d -i ciphertext44.gcm -o plaintext44-2.gcm -p %pp% -a %aad%123
@IF ERRORLEVEL 1 (@ECHO OK for STATUS_AUTH_TAG_MISMATCH) ELSE (@EXIT /B 2)

%command% aes-256-gcm -e -i ..\plaintext6570.txt -o ciphertext6570.gcm -p %pp% -n %nonce12% -a %aad%
CALL .\checkup.bat ciphertext6570.gcm
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-gcm -d -i ciphertext6570.gcm -o plaintext6570.gcm -p %pp% -a %aad%
FC ..\plaintext6570.txt plaintext6570.gcm
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-gcm -e -i ..\plaintext2M.jpg -o ciphertext2M.gcm -p %pp% -n %nonce12% -a %aad%
CALL .\checkup.bat ciphertext2M.gcm
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-gcm -d -i ciphertext2M.gcm -o plaintext2M.gcm -p %pp% -a %aad%
FC ..\plaintext2M.jpg plaintext2M.gcm
@IF ERRORLEVEL 1 @EXIT /B 6

@EXIT /B 0

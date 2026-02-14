SETLOCAL

CALL .\settings.bat

IF EXIST tmp (DEL tmp\*.gcm) ELSE (MKDIR tmp)

%command% aes-256-gcm -e -i ..\plaintext44.txt -o tmp\ciphertext44.gcm -p %pp% -n %nonce12% -a %aad%
CALL .\checkup.bat tmp\ciphertext44.gcm
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-gcm -d -i tmp\ciphertext44.gcm -o tmp\plaintext44.gcm -p %pp% -a %aad%
FC ..\plaintext44.txt tmp\plaintext44.gcm
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-gcm -d -i tmp\ciphertext44.gcm -o tmp\plaintext44-2.gcm -p %pp% -a %aad%123
@IF ERRORLEVEL 1 (@ECHO OK for STATUS_AUTH_TAG_MISMATCH) ELSE (@EXIT /B 2)

%command% aes-256-gcm -e -i ..\plaintext6570.txt -o tmp\ciphertext6570.gcm -p %pp% -n %nonce12% -a %aad%
CALL .\checkup.bat tmp\ciphertext6570.gcm
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-gcm -d -i tmp\ciphertext6570.gcm -o tmp\plaintext6570.gcm -p %pp% -a %aad%
FC ..\plaintext6570.txt tmp\plaintext6570.gcm
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-gcm -e -i ..\plaintext2M.jpg -o tmp\ciphertext2M.gcm -p %pp% -n %nonce12% -a %aad%
CALL .\checkup.bat tmp\ciphertext2M.gcm
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-gcm -d -i tmp\ciphertext2M.gcm -o tmp\plaintext2M.gcm -p %pp% -a %aad%
FC ..\plaintext2M.jpg tmp\plaintext2M.gcm
@IF ERRORLEVEL 1 @EXIT /B 6

@ECHO AES-GCM LOOKS GOOD!

@EXIT /B 0

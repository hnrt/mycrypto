SETLOCAL

CALL .\settings.bat

IF EXIST tmp (DEL tmp\*.ecb) ELSE (MKDIR tmp)

%command% aes-256-ecb -e -i ..\plaintext44.txt -o tmp\ciphertext44.ecb -p %pp%
CALL .\checkup.bat tmp\ciphertext44.ecb
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-ecb -d -i tmp\ciphertext44.ecb -o tmp\plaintext44.ecb -p %pp%
FC ..\plaintext44.txt tmp\plaintext44.ecb
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-ecb -e -i ..\plaintext6570.txt -o tmp\ciphertext6570.ecb -p %pp%
CALL .\checkup.bat tmp\ciphertext6570.ecb
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-ecb -d -i tmp\ciphertext6570.ecb -o tmp\plaintext6570.ecb -p %pp%
FC ..\plaintext6570.txt tmp\plaintext6570.ecb
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-ecb -e -i ..\plaintext2M.jpg -o tmp\ciphertext2M.ecb -p %pp%
CALL .\checkup.bat tmp\ciphertext2M.ecb
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-ecb -d -i tmp\ciphertext2M.ecb -o tmp\plaintext2M.ecb -p %pp%
FC ..\plaintext2M.jpg tmp\plaintext2M.ecb
@IF ERRORLEVEL 1 @EXIT /B 6

@ECHO AES-ECB LOOKS GOOD!

@EXIT /B 0

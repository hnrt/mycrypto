SETLOCAL

CALL .\settings.bat

IF EXIST tmp (DEL tmp\*.ccm) ELSE (MKDIR tmp)

%command% aes-256-ccm -e -i ..\plaintext44.txt -o tmp\ciphertext44.ccm -p %pp% -n %nonce7% -a %aad%
CALL .\checkup.bat tmp\ciphertext44.ccm
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-ccm -d -i tmp\ciphertext44.ccm -o tmp\plaintext44.ccm -p %pp% -a %aad%
FC ..\plaintext44.txt tmp\plaintext44.ccm
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-ccm -d -i tmp\ciphertext44.ccm -o tmp\plaintext44-2.ccm -p %pp% -a %aad%123
@IF ERRORLEVEL 1 (@ECHO OK for STATUS_AUTH_TAG_MISMATCH) ELSE (@EXIT /B 2)

%command% aes-256-ccm -e -i ..\plaintext6570.txt -o tmp\ciphertext6570.ccm -p %pp% -n %nonce7% -a %aad%
CALL .\checkup.bat tmp\ciphertext6570.ccm
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-ccm -d -i tmp\ciphertext6570.ccm -o tmp\plaintext6570.ccm -p %pp% -a %aad%
FC ..\plaintext6570.txt tmp\plaintext6570.ccm
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-ccm -e -i ..\plaintext2M.jpg -o tmp\ciphertext2M.ccm -p %pp% -n %nonce7% -a %aad%
CALL .\checkup.bat tmp\ciphertext2M.ccm
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-ccm -d -i tmp\ciphertext2M.ccm -o tmp\plaintext2M.ccm -p %pp% -a %aad%
FC ..\plaintext2M.jpg tmp\plaintext2M.ccm
@IF ERRORLEVEL 1 @EXIT /B 6

@ECHO AES-CCM LOOKS GOOD!

@EXIT /B 0

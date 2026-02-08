SETLOCAL

CALL .\settings.bat

DEL .\*.ccm

%command% aes-256-ccm -e -i ..\plaintext44.txt -o ciphertext44.ccm -p %pp% -iv %nonce7% -aad %aad%
CALL .\checkup.bat ciphertext44.ccm
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-ccm -d -i ciphertext44.ccm -o plaintext44.ccm -p %pp% -aad %aad%
FC ..\plaintext44.txt plaintext44.ccm
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-ccm -d -i ciphertext44.ccm -o plaintext44-2.ccm -p %pp% -aad %aad%123
@IF ERRORLEVEL 1 (@ECHO OK for STATUS_AUTH_TAG_MISMATCH) ELSE (@EXIT /B 2)

%command% aes-256-ccm -e -i ..\plaintext6570.txt -o ciphertext6570.ccm -p %pp% -iv %nonce7% -aad %aad%
REM CALL .\checkup.bat ciphertext6570.ccm
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-ccm -d -i ciphertext6570.ccm -o plaintext6570.ccm -p %pp% -aad %aad%
FC ..\plaintext6570.txt plaintext6570.ccm
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-ccm -e -i ..\plaintext2M.jpg -o ciphertext2M.ccm -p %pp% -iv %nonce7% -aad %aad%
REM CALL .\checkup.bat ciphertext2M.ccm
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-ccm -d -i ciphertext2M.ccm -o plaintext2M.ccm -p %pp% -aad %aad%
FC ..\plaintext2M.jpg plaintext2M.ccm
@IF ERRORLEVEL 1 @EXIT /B 6

@EXIT /B 0

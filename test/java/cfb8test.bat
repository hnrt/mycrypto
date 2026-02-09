SETLOCAL

CALL .\settings.bat

DEL .\*.cfb8

%command% aes-256-cfb8 -e -i ..\plaintext44.txt -o ciphertext44.cfb8 -p %pp% -iv %iv%
CALL .\checkup.bat ciphertext44.cfb8
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-cfb8 -d -i ciphertext44.cfb8 -o plaintext44.cfb8 -p %pp%
FC ..\plaintext44.txt plaintext44.cfb8
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-cfb8 -e -i ..\plaintext6570.txt -o ciphertext6570.cfb8 -p %pp% -iv %iv%
CALL .\checkup.bat ciphertext6570.cfb8
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-cfb8 -d -i ciphertext6570.cfb8 -o plaintext6570.cfb8 -p %pp%
FC ..\plaintext6570.txt plaintext6570.cfb8
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-cfb8 -e -i ..\plaintext2M.jpg -o ciphertext2M.cfb8 -p %pp% -iv %iv%
CALL .\checkup.bat ciphertext2M.cfb8
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-cfb8 -d -i ciphertext2M.cfb8 -o plaintext2M.cfb8 -p %pp%
FC ..\plaintext2M.jpg plaintext2M.cfb8
@IF ERRORLEVEL 1 @EXIT /B 6

%command% aes-256-cfb8 -e -i ..\plaintext4096.zero -o ciphertext4096.cfb8 -p %pp% -iv %iv%
CALL .\checkup.bat ciphertext4096.cfb8
@IF ERRORLEVEL 1 @EXIT /B 7

%command% aes-256-cfb8 -d -i ciphertext4096.cfb8 -o plaintext4096.cfb8 -p %pp%
FC ..\plaintext4096.zero plaintext4096.cfb8
@IF ERRORLEVEL 1 @EXIT /B 8

@EXIT /B 0

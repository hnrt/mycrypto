SETLOCAL

CALL .\settings.bat

DEL .\*.cbc

%command% aes-256-cbc -e -i ..\plaintext44.txt -o ciphertext44.cbc -p %pp% -iv %iv%
CALL .\checkup.bat ciphertext44.cbc
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-cbc -d -i ciphertext44.cbc -o plaintext44.cbc -p %pp%
FC ..\plaintext44.txt plaintext44.cbc
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-cbc -e -i ..\plaintext6570.txt -o ciphertext6570.cbc -p %pp% -iv %iv%
CALL .\checkup.bat ciphertext6570.cbc
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-cbc -d -i ciphertext6570.cbc -o plaintext6570.cbc -p %pp%
FC ..\plaintext6570.txt plaintext6570.cbc
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-cbc -e -i ..\plaintext2M.jpg -o ciphertext2M.cbc -p %pp% -iv %iv%
CALL .\checkup.bat ciphertext2M.cbc
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-cbc -d -i ciphertext2M.cbc -o plaintext2M.cbc -p %pp%
FC ..\plaintext2M.jpg plaintext2M.cbc
@IF ERRORLEVEL 1 @EXIT /B 6

%command% aes-256-cbc -e -i ..\plaintext4096.zero -o ciphertext4096.cbc -p %pp% -iv %iv%
CALL .\checkup.bat ciphertext4096.cbc
@IF ERRORLEVEL 1 @EXIT /B 7

%command% aes-256-cbc -d -i ciphertext4096.cbc -o plaintext4096.cbc -p %pp%
FC ..\plaintext4096.zero plaintext4096.cbc
@IF ERRORLEVEL 1 @EXIT /B 8

%command% aes-256-cbc -e -i - -o ciphertext44-2.cbc -p %pp% -iv %iv% <..\plaintext44.txt
CALL .\checkup.bat ciphertext44-2.cbc
@IF ERRORLEVEL 1 @EXIT /B 9

%command% aes-256-cbc -d -i ciphertext44-2.cbc -o - -p %pp% >plaintext44-2.cbc
FC ..\plaintext44.txt plaintext44-2.cbc
@IF ERRORLEVEL 1 @EXIT /B 10

%command% aes-256-cbc -e -i ..\plaintext44.txt -o - -p %pp% -iv %iv% >ciphertext44-3.cbc
CALL .\checkup.bat ciphertext44-3.cbc
@IF ERRORLEVEL 1 @EXIT /B 11

%command% aes-256-cbc -d -i - -o plaintext44-3.cbc -p %pp% <ciphertext44-3.cbc
FC ..\plaintext44.txt plaintext44-3.cbc
@IF ERRORLEVEL 1 @EXIT /B 12

%command% aes-256-cbc -e -i - -o ciphertext2M-2.cbc -p %pp% -iv %iv% <..\plaintext2M.jpg
CALL .\checkup.bat ciphertext2M-2.cbc
@IF ERRORLEVEL 1 @EXIT /B 13

%command% aes-256-cbc -d -i ciphertext2M-2.cbc -o - -p %pp% >plaintext2M-2.cbc
FC ..\plaintext2M.jpg plaintext2M-2.cbc
@IF ERRORLEVEL 1 @EXIT /B 14

%command% aes-256-cbc -e -i ..\plaintext2M.jpg -o - -p %pp% -iv %iv% >ciphertext2M-3.cbc
CALL .\checkup.bat ciphertext2M-3.cbc
@IF ERRORLEVEL 1 @EXIT /B 15

%command% aes-256-cbc -d -i - -o plaintext2M-3.cbc -p %pp% <ciphertext2M-3.cbc
FC ..\plaintext2M.jpg plaintext2M-3.cbc
@IF ERRORLEVEL 1 @EXIT /B 16


@EXIT /B 0

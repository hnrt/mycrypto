@SETLOCAL

@CALL .\settings.bat

@IF EXIST tmp (DEL tmp\*.cbc) ELSE (MKDIR tmp)

%command% aes-256-cbc -e -i ..\plaintext44.txt -o tmp\ciphertext44.cbc -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext44.cbc
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-cbc -d -i tmp\ciphertext44.cbc -o tmp\plaintext44.cbc -p %pp%
CALL .\checkup.bat ..\plaintext44.txt tmp\plaintext44.cbc
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-cbc -e -i ..\plaintext6570.txt -o tmp\ciphertext6570.cbc -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext6570.cbc
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-cbc -d -i tmp\ciphertext6570.cbc -o tmp\plaintext6570.cbc -p %pp%
CALL .\checkup.bat ..\plaintext6570.txt tmp\plaintext6570.cbc
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-cbc -e -i ..\plaintext2M.jpg -o tmp\ciphertext2M.cbc -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext2M.cbc
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-cbc -d -i tmp\ciphertext2M.cbc -o tmp\plaintext2M.cbc -p %pp%
CALL .\checkup.bat ..\plaintext2M.jpg tmp\plaintext2M.cbc
@IF ERRORLEVEL 1 @EXIT /B 6

%command% aes-256-cbc -e -i ..\plaintext4096.zero -o tmp\ciphertext4096.cbc -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext4096.cbc
@IF ERRORLEVEL 1 @EXIT /B 7

%command% aes-256-cbc -d -i tmp\ciphertext4096.cbc -o tmp\plaintext4096.cbc -p %pp%
CALL .\checkup.bat ..\plaintext4096.zero tmp\plaintext4096.cbc
@IF ERRORLEVEL 1 @EXIT /B 8

%command% aes-256-cbc -e -i - -o tmp\ciphertext44-2.cbc -p %pp% -iv %iv% <..\plaintext44.txt
CALL .\checkup.bat tmp\ciphertext44.cbc tmp\ciphertext44-2.cbc
@IF ERRORLEVEL 1 @EXIT /B 9

%command% aes-256-cbc -d -i tmp\ciphertext44-2.cbc -o - -p %pp% >tmp\plaintext44-2.cbc
CALL .\checkup.bat ..\plaintext44.txt tmp\plaintext44-2.cbc
@IF ERRORLEVEL 1 @EXIT /B 10

%command% aes-256-cbc -e -i ..\plaintext44.txt -o - -p %pp% -iv %iv% >tmp\ciphertext44-3.cbc
CALL .\checkup.bat tmp\ciphertext44.cbc tmp\ciphertext44-3.cbc
@IF ERRORLEVEL 1 @EXIT /B 11

%command% aes-256-cbc -d -i - -o tmp\plaintext44-3.cbc -p %pp% <tmp\ciphertext44-3.cbc
CALL .\checkup.bat ..\plaintext44.txt tmp\plaintext44-3.cbc
@IF ERRORLEVEL 1 @EXIT /B 12

%command% aes-256-cbc -e -i - -o tmp\ciphertext2M-2.cbc -p %pp% -iv %iv% <..\plaintext2M.jpg
CALL .\checkup.bat tmp\ciphertext2M.cbc tmp\ciphertext2M-2.cbc
@IF ERRORLEVEL 1 @EXIT /B 13

%command% aes-256-cbc -d -i tmp\ciphertext2M-2.cbc -o - -p %pp% >tmp\plaintext2M-2.cbc
CALL .\checkup.bat ..\plaintext2M.jpg tmp\plaintext2M-2.cbc
@IF ERRORLEVEL 1 @EXIT /B 14

%command% aes-256-cbc -e -i ..\plaintext2M.jpg -o - -p %pp% -iv %iv% >tmp\ciphertext2M-3.cbc
CALL .\checkup.bat tmp\ciphertext2M.cbc tmp\ciphertext2M-3.cbc
@IF ERRORLEVEL 1 @EXIT /B 15

%command% aes-256-cbc -d -i - -o tmp\plaintext2M-3.cbc -p %pp% <tmp\ciphertext2M-3.cbc
CALL .\checkup.bat ..\plaintext2M.jpg tmp\plaintext2M-3.cbc
@IF ERRORLEVEL 1 @EXIT /B 16

@ECHO AES-CBC LOOKS GOOD!

@EXIT /B 0

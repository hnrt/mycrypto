@SETLOCAL

@CALL .\settings.bat

@IF EXIST tmp (DEL tmp\*.ctr) ELSE (MKDIR tmp)

%command% aes-256-ctr -e -i ..\plaintext44.txt -o tmp\ciphertext44.ctr -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext44.ctr
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-ctr -d -i tmp\ciphertext44.ctr -o tmp\plaintext44.ctr -p %pp%
CALL .\checkup.bat ..\plaintext44.txt tmp\plaintext44.ctr
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-ctr -e -i ..\plaintext6570.txt -o tmp\ciphertext6570.ctr -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext6570.ctr
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-ctr -d -i tmp\ciphertext6570.ctr -o tmp\plaintext6570.ctr -p %pp%
CALL .\checkup.bat ..\plaintext6570.txt tmp\plaintext6570.ctr
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-ctr -e -i ..\plaintext2M.jpg -o tmp\ciphertext2M.ctr -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext2M.ctr
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-ctr -d -i tmp\ciphertext2M.ctr -o tmp\plaintext2M.ctr -p %pp%
CALL .\checkup.bat ..\plaintext2M.jpg tmp\plaintext2M.ctr
@IF ERRORLEVEL 1 @EXIT /B 6

@ECHO AES-CTR LOOKS GOOD!

@EXIT /B 0

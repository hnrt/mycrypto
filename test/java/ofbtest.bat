@SETLOCAL

@CALL .\settings.bat

@IF EXIST tmp (DEL tmp\*.ofb128) ELSE (MKDIR tmp)

%command% aes-256-ofb -e -i ..\plaintext44.txt -o tmp\ciphertext44.ofb128 -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext44.ofb128
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-ofb -d -i tmp\ciphertext44.ofb128 -o tmp\plaintext44.ofb128 -p %pp%
CALL .\checkup.bat ..\plaintext44.txt tmp\plaintext44.ofb128
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-ofb -e -i ..\plaintext6570.txt -o tmp\ciphertext6570.ofb128 -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext6570.ofb128
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-ofb -d -i tmp\ciphertext6570.ofb128 -o tmp\plaintext6570.ofb128 -p %pp%
CALL .\checkup.bat ..\plaintext6570.txt tmp\plaintext6570.ofb128
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-ofb -e -i ..\plaintext2M.jpg -o tmp\ciphertext2M.ofb128 -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext2M.ofb128
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-ofb -d -i tmp\ciphertext2M.ofb128 -o tmp\plaintext2M.ofb128 -p %pp%
CALL .\checkup.bat ..\plaintext2M.jpg tmp\plaintext2M.ofb128
@IF ERRORLEVEL 1 @EXIT /B 6

@ECHO AES-OFB LOOKS GOOD!

@EXIT /B 0

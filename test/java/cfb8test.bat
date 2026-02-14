SETLOCAL

CALL .\settings.bat

IF EXIST tmp (DEL tmp\*.cfb8) ELSE (MKDIR tmp)

%command% aes-256-cfb8 -e -i ..\plaintext44.txt -o tmp\ciphertext44.cfb8 -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext44.cfb8
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-cfb8 -d -i tmp\ciphertext44.cfb8 -o tmp\plaintext44.cfb8 -p %pp%
FC ..\plaintext44.txt tmp\plaintext44.cfb8
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-cfb8 -e -i ..\plaintext6570.txt -o tmp\ciphertext6570.cfb8 -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext6570.cfb8
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-cfb8 -d -i tmp\ciphertext6570.cfb8 -o tmp\plaintext6570.cfb8 -p %pp%
FC ..\plaintext6570.txt tmp\plaintext6570.cfb8
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-cfb8 -e -i ..\plaintext2M.jpg -o tmp\ciphertext2M.cfb8 -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext2M.cfb8
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-cfb8 -d -i tmp\ciphertext2M.cfb8 -o tmp\plaintext2M.cfb8 -p %pp%
FC ..\plaintext2M.jpg tmp\plaintext2M.cfb8
@IF ERRORLEVEL 1 @EXIT /B 6

%command% aes-256-cfb8 -e -i ..\plaintext4096.zero -o tmp\ciphertext4096.cfb8 -p %pp% -iv %iv%
CALL .\checkup.bat tmp\ciphertext4096.cfb8
@IF ERRORLEVEL 1 @EXIT /B 7

%command% aes-256-cfb8 -d -i tmp\ciphertext4096.cfb8 -o tmp\plaintext4096.cfb8 -p %pp%
FC ..\plaintext4096.zero tmp\plaintext4096.cfb8
@IF ERRORLEVEL 1 @EXIT /B 8

@ECHO AES-CFB8 LOOKS GOOD!

@EXIT /B 0

@SETLOCAL

@CALL .\settings.bat

@IF EXIST tmp (DEL tmp\*.cfb128) ELSE (MKDIR tmp)

%command% aes-256-cfb -e -i ..\plaintext44.txt -o tmp\ciphertext44.cfb128 -p %pp% -iv %iv%
%checkup% tmp\ciphertext44.cfb128
@IF ERRORLEVEL 1 @EXIT /B 1

%command% aes-256-cfb -d -i tmp\ciphertext44.cfb128 -o tmp\plaintext44.cfb128 -p %pp%
%checkup% ..\plaintext44.txt tmp\plaintext44.cfb128
@IF ERRORLEVEL 1 @EXIT /B 2

%command% aes-256-cfb -e -i ..\plaintext6570.txt -o tmp\ciphertext6570.cfb128 -p %pp% -iv %iv%
%checkup% tmp\ciphertext6570.cfb128
@IF ERRORLEVEL 1 @EXIT /B 3

%command% aes-256-cfb -d -i tmp\ciphertext6570.cfb128 -o tmp\plaintext6570.cfb128 -p %pp%
%checkup% ..\plaintext6570.txt tmp\plaintext6570.cfb128
@IF ERRORLEVEL 1 @EXIT /B 4

%command% aes-256-cfb -e -i ..\plaintext2M.jpg -o tmp\ciphertext2M.cfb128 -p %pp% -iv %iv%
%checkup% tmp\ciphertext2M.cfb128
@IF ERRORLEVEL 1 @EXIT /B 5

%command% aes-256-cfb -d -i tmp\ciphertext2M.cfb128 -o tmp\plaintext2M.cfb128 -p %pp%
%checkup% ..\plaintext2M.jpg tmp\plaintext2M.cfb128
@IF ERRORLEVEL 1 @EXIT /B 6

@ECHO AES-CFB LOOKS GOOD!

@EXIT /B 0

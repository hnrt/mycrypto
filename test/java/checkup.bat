@ECHO OFF
SETLOCAL
REM SET configuration=Debug
SET configuration=Release
SET command=..\..\bin\x64\%configuration%\mycrypto.exe
FOR %%a IN (%1) DO SET target=%%~nxa
FOR /F "tokens=1" %%a IN ('FINDSTR %target% ..\CHECKSUMS') DO SET expected=%%a
FOR /F "tokens=1" %%a IN ('%command% sha256 -i %1') DO SET actual=%%a
IF "%expected%" == "%actual%" (EXIT /B 0) ELSE (EXIT /B 1)

@ECHO OFF

SETLOCAL

IF "%~2" == "" (
  GOTO CHECKSUMS
) ELSE (
  GOTO FILES
)

:CHECKSUMS

  SET command=..\..\bin\x64\Release\mycrypto.exe
  FOR %%a IN (%1) DO SET target=%%~nxa
  FOR /F "tokens=1" %%a IN ('FINDSTR %target% ..\CHECKSUMS') DO SET expected=%%a
  FOR /F "tokens=1" %%a IN ('%command% sha256 -i %1') DO SET actual=%%a
  IF "%expected%" == "%actual%" (
    ECHO CHECKSUMS MATCH!
    @ECHO ON
    EXIT /B 0
  ) ELSE (
    ECHO CHECKSUMS MISMATCH!
    @ECHO ON
    EXIT /B 1
  )

:FILES

  FC "%~1" "%~2" >NUL
  IF ERRORLEVEL 1 (
    ECHO FILES MISMATCH!
    @ECHO ON
    EXIT /B 1
  ) ELSE (
    ECHO FILES MATCH!
    @ECHO ON
    EXIT /B 0
  )

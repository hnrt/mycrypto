SETLOCAL
SET successful=
SET failed=
CALL .\ecbtest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% ECB) ELSE (SET successful=%successful% ECB)
CALL .\cbctest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% CBC) ELSE (SET successful=%successful% CBC)
CALL .\cfb8test.bat
@IF ERRORLEVEL 1 (SET failed=%failed% CFB8) ELSE (SET successful=%successful% CFB8)
CALL .\gcmtest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% GCM) ELSE (SET successful=%successful% GCM)
CALL .\ccmtest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% CCM) ELSE (SET successful=%successful% CCM)
@IF NOT "%successful%"=="" (@ECHO OK:%successful%)
@IF NOT "%failed%"=="" (@ECHO FAILED:%failed%)

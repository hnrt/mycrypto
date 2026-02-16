@SETLOCAL
@SET successful=
@SET failed=
CALL ..\ecbtest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% ECB) ELSE (SET successful=%successful% ECB)
CALL ..\cbctest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% CBC) ELSE (SET successful=%successful% CBC)
CALL .\cfbtest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% CFB) ELSE (SET successful=%successful% CFB)
CALL ..\cfb8test.bat
@IF ERRORLEVEL 1 (SET failed=%failed% CFB8) ELSE (SET successful=%successful% CFB8)
CALL .\ofbtest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% OFB) ELSE (SET successful=%successful% OFB)
CALL .\ofb8test.bat
@IF ERRORLEVEL 1 (SET failed=%failed% OFB8) ELSE (SET successful=%successful% OFB8)
CALL .\ctrtest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% CTR) ELSE (SET successful=%successful% CTR)
CALL ..\gcmtest.bat
@IF ERRORLEVEL 1 (SET failed=%failed% GCM) ELSE (SET successful=%successful% GCM)
@ECHO RESULT SUMMARY:
@IF NOT "%successful%"=="" (ECHO OK:%successful%)
@IF NOT "%failed%"=="" (ECHO FAILED:%failed%)

@ECHO OFF
SETLOCAL
FOR /F "delims=" %%A IN ("%0") DO SET dir1=%%~dpsA
FOR /F "delims=" %%A IN ("%dir1%.") DO SET dir2=%%~dpsA
SET tmpfile=%dir2%quux_20260222
SET solutiondir=%dir2%
SET target=%solutiondir%src\main\cpp\ApplicationVersion.h
SET pomfile=%solutiondir%pom.xml
SET grep=%ProgramFiles%\Git\usr\bin\grep.exe
SET head=%ProgramFiles%\Git\usr\bin\head.exe
SET sed=%ProgramFiles%\Git\usr\bin\sed.exe
"%grep%" "[<]version[>]" %pomfile% | "%head%" -1 | "%sed%" -e "s/^[^0-9]*//" -e "s/[^0-9]*$//" >%tmpfile%
FOR /F "delims=" %%A IN (%tmpfile%) DO SET version=%%A
ECHO #ifndef APPLICATION_VERSION>%target%
ECHO #define APPLICATION_VERSION "%version%">>%target%
ECHO #endif //!APPLICATION_VERSION>>%target%
ECHO Wrote the following content to %target%
type %target%
del %tmpfile%
ENDLOCAL

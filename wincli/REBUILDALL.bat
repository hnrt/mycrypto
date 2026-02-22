@SETLOCAL
@FOR /F "delims=" %%A IN ("%0") DO @SET dir1=%%~dpsA
@SET vcxproj=%dir1%wincli.vcxproj
@SET devenv=%ProgramFiles%\Microsoft Visual Studio\18\Community\Common7\IDE\devenv.com
"%devenv%" %vcxproj% /rebuild "Debug|x64" || EXIT /B 1
"%devenv%" %vcxproj% /rebuild "Release|x64" || EXIT /B 1

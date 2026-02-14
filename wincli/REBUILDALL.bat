SETLOCAL
set devenv=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\devenv.com
"%devenv%" .\wincli.vcxproj /rebuild "Debug|x64" || EXIT /B 1
"%devenv%" .\wincli.vcxproj /rebuild "Release|x64" || EXIT /B 1

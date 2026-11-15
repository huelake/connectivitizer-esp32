@echo off
rem Builds the library for this PC with the Visual Studio compiler: host\build\cz_host.exe
setlocal
set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo Visual Studio 2022 with the C++ tools was not found.
  exit /b 1
)
call "%VCVARS%" >nul
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /W3 /O2 /std:c11 /D_CRT_SECURE_NO_WARNINGS /Fo:build\ /Fe:build\cz_host.exe cz_host.c ..\src\*.c ..\src\port\*.c ..\src\vendor\*.c
exit /b %ERRORLEVEL%

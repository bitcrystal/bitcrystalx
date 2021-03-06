@echo off

set DEPS_EXIST=0
set MINGW32_EXIST=0
set QT_EXIST=0
set MINGWCOIN_EXIST=0
set CLEAN="true"

set /A DIR_EXISTS=0
if exist C:\deps (
	set DEPS_EXIST=1
	set /A DIR_EXISTS=%DIR_EXISTS%+1
)

if exist C:\mingw32 (
	set MINGW32_EXIST=1
	set /A DIR_EXISTS=%DIR_EXISTS%+1
)

if exist C:\Qt (
	set QT_EXIST=1
	set /A DIR_EXISTS=%DIR_EXISTS%+1
)

if exist C:\MinGWcoin (
	set MINGWCOIN_EXIST=1
	set /A DIR_EXISTS=%DIR_EXISTS%+1
)

if %DIR_EXISTS%==4 goto done else goto BatchGotAdmin
rem this not by me

:BatchGotAdmin
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

rem this script here is by me
if %DEPS_EXIST%==0 (
	mklink C:\deps %~dp0build_deps\deps
)

if %QT_EXIST%==0 (
	mklink C:\Qt %~dp0build_deps\Qt
	set PATH=C:\Qt\4.8.6\bin;%PATH%
)

if %MINGW32_EXIST%==0 (
	mklink C:\mingw32 %~dp0build_deps\mingw32
	set PATH=C:\mingw32\bin;%PATH%
)

if %MINGWCOIN_EXIST%==0 (
	mklink C:\MinGWcoin %~dp0build_deps\MinGWcoin
)

:done
del /f /q "%~dp0src\leveldb\libleveldb.a"
del /f /q "%~dp0src\leveldb\libmemenv.a"
copy /b "%~dp0libleveldb.a" "%~dp0src\leveldb"
copy /b "%~dp0libmemenv.a" "%~dp0src\leveldb"
cd %~dp0src
if %CLEAN%=="true" (
del /f /q bitcrystalxd.exe
del /f /q bitcrystalx_test.exe
del /f /q obj\*.o
del /f /q obj-test\*.o
del /f /q src\obj\*.obj
)
mingw32-make -f %~dp0my.makefile.mingw USE_PNP=bitcrystalxd -j4
strip bitcrystalxd.exe
pause
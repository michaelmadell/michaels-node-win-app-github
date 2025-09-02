@echo off
setlocal enabledelayedexpansion

REM --- Define output files and source locations ---
set "SOURCE_DIR=C:\Users\labtest\Documents\winapp"
set "INSTALLER_DIR=%SOURCE_DIR%\install"
set "SERVICE_EXE_FILE=%INSTALLER_DIR%\CoreStation_HX_Agent.exe"
set "TRAY_APP_EXE_FILE=%INSTALLER_DIR%\CoreStation_HX_Agent_Tray.exe"
set "SERVICE_SOURCE=%SOURCE_DIR%\main.cpp"
set "TRAY_APP_SOURCE=%SOURCE_DIR%\TrayApp.cpp"

REM --- MODIFIED: Point to the new trayapp.rc and define service resource files ---
set "SERVICE_RC=%SOURCE_DIR%\service.rc"
set "SERVICE_RES=%SOURCE_DIR%\service.res"
set "TRAY_APP_RC=%SOURCE_DIR%\trayapp.rc"
set "TRAY_APP_RES=%SOURCE_DIR%\TrayApp.res"

if exist %INSTALLER_DIR% (
    echo Yes
) else (
    mkdir %INSTALLER_DIR% 2> NUL
)

REM --- Check if the service .exe is writeable (might be running) ---
>> "%SERVICE_EXE_FILE%" (
    REM If appending succeeds, do nothing
) || (
    echo File "%SERVICE_EXE_FILE%" is not writable,
    echo have you STOPPED the service?
    exit /b 1
)


REM --- Gather git info and create git.h ---
REM Get the current Git branch name
for /f "delims=" %%i in ('git rev-parse --abbrev-ref HEAD') do set "GIT_BRANCH=%%i"

REM Get the short commit hash
for /f "delims=" %%i in ('git rev-parse --short HEAD') do set "GIT_HASH=%%i"

REM Check for uncommitted modifications
git diff --quiet || set MODIFICATIONS=1
git diff --cached --quiet || set MODIFICATIONS=1

if not defined MODIFICATIONS (
    set "MODIFICATIONS=0"
) else (
    set "GIT_HASH=!GIT_HASH!-mods"
)

REM Get the current date and time as build time
for /f %%i in ('powershell -Command "Get-Date -Format yyyy-MM-dd_HH:mm:ss"') do set "BUILD_TIME=%%i"

REM Generate the C++ header file
set "HEADER_FILE=git_info.h"
(
    echo #pragma once
    echo #include ^<string^>
    echo namespace GitInfo {
    echo     const std::string BRANCH = "!GIT_BRANCH!";
    echo     const std::string HASH = "!GIT_HASH!";
    echo     const std::string BUILD_TIME = "!BUILD_TIME!";
    echo }
) > %HEADER_FILE%

echo Header file %HEADER_FILE% generated successfully.
echo Branch: !GIT_BRANCH!
echo Hash: !GIT_HASH!
echo Modified: !MODIFICATIONS!
echo Time: !BUILD_TIME!


REM --- Copy release notes to output dir ---
copy release-notes.txt "%INSTALLER_DIR%"

REM --- ADDED: Build service resources ---
echo.
echo Compiling Service resources...
rc.exe /fo "%SERVICE_RES%" "%SERVICE_RC%"
if errorlevel 1 (
    echo ##### SERVICE RESOURCES COMPILATION FAILED #####
    exit /b 1
)

REM --- Build executables to output dir ---
echo Building Service: %SERVICE_EXE_FILE%
cl.exe /O2 /DNDEBUG /EHsc /MT /nologo /Fe"%SERVICE_EXE_FILE%" "%SERVICE_SOURCE%" "%SERVICE_RES%" /link wbemuuid.lib netapi32.lib iphlpapi.lib ws2_32.lib Wtsapi32.lib setupapi.lib shell32.lib advapi32.lib user32.lib Ole32.lib OleAut32.lib
if errorlevel 1 (
    echo ##### SERVICE COMPILATION FAILED #####
    exit /b 1
)

echo.
echo Compiling Tray app resources...
rc.exe /fo "%TRAY_APP_RES%" "%TRAY_APP_RC%"
if errorlevel 1 (
    echo ##### TRAY APP RESOURCES COMPILATION FAILED #####
    exit /b 1
)

echo.
echo Building Tray App: %TRAY_APP_EXE_FILE%
cl.exe /O2 /DNDEBUG /EHsc /MT /nologo /Fe"%TRAY_APP_EXE_FILE%" "%TRAY_APP_SOURCE%" "%TRAY_APP_RES%" /link user32.lib shell32.lib
if errorlevel 1 (
    echo ##### TRAY APP COMPILATION FAILED #####
    exit /b 1
)

REM --- Check if it is a release branch ---
echo.
echo Branch = !GIT_BRANCH!
REM Check if branch matches format *.*.*
echo !GIT_BRANCH! | findstr /R "^[0-9]*\.[0-9]*\.[0-9]*" >nul
if errorlevel 1 (
    echo Not a release branch, finished
    exit /b 0
)

set /p userChoice=Do you want to sign the .exe files? (y/n): 

if /i "%userChoice%"=="y" (
    echo.
    echo Signing the Service executable...
    smctl sign --keypair-alias key_1269013793 --input "!SERVICE_EXE_FILE!"
    echo.
    echo Signing the Tray App executable...
    smctl sign --keypair-alias key_1269013793 --input "!TRAY_APP_EXE_FILE!"
    echo.
    echo If signing failed, try running 'smctl healthcheck' or check [C:\Users\labtest\.signingmanager\logs\smctl.log]
) else (    
    echo skipping signing and transfer steps
)
echo.
set /p userChoice=Do you want to push to ahkengbuild? (y/n): 

if /i not "%userChoice%"=="y" (
    echo skipping transfer steps
    echo.
    exit /b 0
)

REM --- Build version number string ---
set "VERSION_H=version.h"

REM Initialize variables
set "VERSION_YEAR="
set "VERSION_MONTH="
set "VERSION_RELEASE="
set "VERSION_EXTRAVERSION="
set "VERSION_RC_NO="
set "VERSION_ADHOC_NO="

REM Read each line of version.h
for /f "usebackq tokens=1,2,3 delims= " %%A in ("%VERSION_H%") do (
    if "%%A"=="#define" (
        if "%%B"=="VERSION_YEAR" set "VERSION_YEAR=%%C"
        if "%%B"=="VERSION_MONTH" set "VERSION_MONTH=%%C"
        if "%%B"=="VERSION_RELEASE" set "VERSION_RELEASE=%%C"
        if "%%B"=="VERSION_EXTRAVERSION" set "VERSION_EXTRAVERSION=%%~C"
        if "%%B"=="VERSION_RC_NO" set "VERSION_RC_NO=%%C"
        if "%%B"=="VERSION_ADHOC_NO" set "VERSION_ADHOC_NO=%%C"
    )
)

REM Strip quotes from VERSION_EXTRAVERSION
set "VERSION_EXTRAVERSION=!VERSION_EXTRAVERSION:"=!"

REM Build the VERSION string
if /i "!VERSION_EXTRAVERSION!"=="rc" (
    set "VERSION=!VERSION_YEAR!.!VERSION_MONTH!.!VERSION_RELEASE!_rc!VERSION_RC_NO!"
) else if /i "!VERSION_EXTRAVERSION!"=="adhoc" (
    set "VERSION=!VERSION_YEAR!.!VERSION_MONTH!.!VERSION_RELEASE!_adhoc!VERSION_ADHOC_NO!"
) else if /i "!VERSION_EXTRAVERSION!"=="ga" (
    set "VERSION=!VERSION_YEAR!.!VERSION_MONTH!.!VERSION_RELEASE!_ga"
) else (
    echo Unknown VERSION_EXTRAVERSION: !VERSION_EXTRAVERSION!
    exit /b 1
)

echo Version = %VERSION%


REM --- Transfer to build server ---
set "REMOTE_MACHINE=ci.user@ahkengbuild"
set "REMOTE_DIR=/srv/build_server/builds/releases/node-win-app/%GIT_BRANCH%/%VERSION%"

REM Use percent vars since they don't need delayed expansion and don't interfere with remote shell
ssh %REMOTE_MACHINE% "DIR=%REMOTE_DIR%; if [ -d \"$DIR\" ]; then exit 1; else mkdir -p \"$DIR\"; fi"

if errorlevel 1 (
    echo Release %VERSION% already exists on build server
    exit /b 1
)

echo Sorry, you need to enter the password again for scp...

REM Now copy
scp -r "%INSTALLER_DIR%"/* %REMOTE_MACHINE%:%REMOTE_DIR%/

endlocal

echo Deployment to build server complete.
echo.
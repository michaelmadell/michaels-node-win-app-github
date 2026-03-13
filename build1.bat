@echo off
setlocal enabledelayedexpansion

set "OUTPUT_EXE_FILE=%~dp0build\CoreStationHXAgent.exe"

call "%~dp0build.bat"
if errorlevel 1 (
    echo Build failed, skipping sign and deploy steps.
    exit /b 1
)

if not exist "%OUTPUT_EXE_FILE%" (
    echo Build output not found at "%OUTPUT_EXE_FILE%"
    exit /b 1
)

for /f "delims=" %%i in ('git rev-parse --abbrev-ref HEAD 2^>nul') do set "GIT_BRANCH=%%i"
if not defined GIT_BRANCH set "GIT_BRANCH=unknown"


REM If a release branch 
echo Branch = !GIT_BRANCH!
REM Check if branch matches format *.*.*
echo !GIT_BRANCH! | findstr /R "^[0-9]*\.[0-9]*\.[0-9]*" >nul
if errorlevel 1 (
    echo Not a release branch, finished
    exit /b 0
)

set /p userChoice=Do you want to sign the .exe file? (y/n): 

if /i "%userChoice%"=="y" (
    echo.
    smctl sign --keypair-alias key_1269013793 --input "!OUTPUT_EXE_FILE!"
    echo.
    echo If signing failed, try running 'smctl healthcheck' or check [C:\Users\labtest\.signingmanager\logs\smctl.log]
) else (    
    echo skipping siging and transfer steps

)
echo.
set /p userChoice=Do you want to push to ahkengbuild? (y/n): 

if /i not "%userChoice%"=="y" (
    echo skipping transfer steps
    echo.
    exit /b 0
)

REM Build version number string 
set "VERSION_H=src\version.h"

REM Initialize variables
set "VERSION_MAJOR="
set "VERSION_MINOR="
set "VERSION_RELEASE="
set "VERSION_EXTRAVERSION="
set "VERSION_RC_NO="
set "VERSION_ADHOC_NO="

REM Read each line of version.h
for /f "usebackq tokens=1,2,3 delims= " %%A in ("%VERSION_H%") do (
    if "%%A"=="#define" (
        if "%%B"=="VERSION_MAJOR" set "VERSION_MAJOR=%%C"
        if "%%B"=="VERSION_MINOR" set "VERSION_MINOR=%%C"
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
    set "VERSION=!VERSION_MAJOR!.!VERSION_MINOR!.!VERSION_RELEASE!_rc!VERSION_RC_NO!"
) else if /i "!VERSION_EXTRAVERSION!"=="adhoc" (
    set "VERSION=!VERSION_MAJOR!.!VERSION_MINOR!.!VERSION_RELEASE!_adhoc!VERSION_ADHOC_NO!"
) else if /i "!VERSION_EXTRAVERSION!"=="ga" (
    set "VERSION=!VERSION_MAJOR!.!VERSION_MINOR!.!VERSION_RELEASE!_ga"
) else (
    echo Unknown VERSION_EXTRAVERSION: !VERSION_EXTRAVERSION!
    exit /b 1
)

echo Version = %VERSION%

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
scp -r installer/* %REMOTE_MACHINE%:%REMOTE_DIR%/

endlocal

echo Deployment to build server complete.
echo.
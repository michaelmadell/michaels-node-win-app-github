@echo off
setlocal enabledelayedexpansion
REM Initialize the MSVC environment so cl.exe and rc.exe are on PATH
if not defined DevEnvDir (
    for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
    if exist "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" (
        call "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else (
        echo Could not find vcvarsall.bat; install Visual Studio Build Tools with C++ workload.
        exit /b 1
    )
)
REM check the target .exe is writeable (local machine might be running it)


REM Attempt to open the file for appending without modifying it
set "OUTPUT_EXE_FILE=C:\Users\michael.madell\source\repos\michaels-node-win-app\build\CoreStationHXAgent.exe"

REM Attempt to append (without modifying) to test writability
>> "%OUTPUT_EXE_FILE%" (
    REM If appending succeeds, do nothing
) || (
    echo File "%OUTPUT_EXE_FILE%" is not writable,
    echo have you STOPPED the service?
    exit /b 1
)



REM Gather git info and create git.h


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

echo Compiling Resources...
rc.exe app.rc


REM Copy release notes to output dir
copy release-notes.txt installer 

REM Build exe file to output dir
cl.exe /O2 /DNDEBUG /EHsc /MT /nologo /Fe"!OUTPUT_EXE_FILE!" src\main.cpp src\WindowsPlatform.cpp app.res /link user32.lib gdi32.lib shell32.lib advapi32.lib comctl32.lib winmm.lib Wtsapi32.lib


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
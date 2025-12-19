@echo off
setlocal enabledelayedexpansion

:: --- NEW: Initialise the MSVC Environment ---
if not defined DevEnvDir (
    for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
    if exist "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" (
        call "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" x64
    ) else (
        echo Could not find vcvarsall.bat, please ensure Visual Studio with C++ tools is installed.
        exit /b 1
    )
)
:: --- END NEW: Initialise the MSVC Environment ---

REM check the target .exe is writeable (local machine might be running it)


REM Attempt to open the file for appending without modifying it
set "OUTPUT_EXE_FILE=%~dp0build\CoreStationHXAgent.exe"

if not exist build\ (
    mkdir build
)

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

cp build\CoreStationHXAgent.exe installer\CoreStationHXAgent.exe

echo finished
exit /b 0


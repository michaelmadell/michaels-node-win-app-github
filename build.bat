@echo off

REM Gather git info and create git.h
setlocal enabledelayedexpansion

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

endlocal


REM Copy release notes to output dir
copy release-notes.txt installer 

REM Build exe file to output dir
cl.exe /O2 /DNDEBUG /EHsc /MT /nologo /FeC:\Users\labtest\repos\node-win-app\installer\nodeWinApp.exe C:\Users\labtest\repos\node-win-app\main.cpp /link user32.lib gdi32.lib shell32.lib advapi32.lib comctl32.lib winmm.lib Wtsapi32.lib
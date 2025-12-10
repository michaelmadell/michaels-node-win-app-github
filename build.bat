@echo off
REM Centralized build script
set CONFIG=Debug
set PLATFORM=x64

set OUT_DIR=%~dp0bin\%CONFIG%\%PLATFORM%\

REM Build tray app project
msbuild "%~dp0NewWinAppTray\NewWinAppTray.vcxproj" /t:Build /p:Configuration=%CONFIG%;Platform=%PLATFORM%;OutDir=%OUT_DIR%
if ERRORLEVEL 1 goto :err

REM Build main project
rc.exe "%~dp0NewWinApp\NewWinApp.rc"
msbuild "%~dp0NewWinApp\NewWinApp.vcxproj" /t:Build /p:Configuration=%CONFIG%;Platform=%PLATFORM%;OutDir=%OUT_DIR%
if ERRORLEVEL 1 goto :err

echo Build Successful.
goto :eof

:err
echo Build Failed.
exit /b 1
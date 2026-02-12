@echo off
setlocal enabledelayedexpansion
REM ============================================================================
REM ADVANCED MODULAR BUILD SCRIPT - SIMPLIFIED & FIXED
REM ============================================================================

REM Capture start time using PowerShell (more reliable than batch arithmetic)
for /f %%i in ('powershell -command "[int](Get-Date -UFormat %%s)"') do set START_EPOCH=%%i


echo ============================================================================
echo CoreStationHXAgent - Advanced Build System
echo ============================================================================

REM ============================================================================
REM Configuration
REM ============================================================================
set "BUILD_DIR=build"
set "OUTPUT_EXE_FILE=build\CoreStationHXAgent.exe"

REM ============================================================================
REM Initialize MSVC
REM ============================================================================
echo [1/6] Initializing MSVC environment...
if not defined DevEnvDir (
    for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
    if exist "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" (
        call "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
        if errorlevel 1 (
            echo ERROR: Failed to initialize Visual Studio environment
            exit /b 1
        )
    ) else (
        echo ERROR: Could not find vcvarsall.bat
        exit /b 1
    )
)
echo    Visual Studio environment ready

REM ============================================================================
REM Create Directories
REM ============================================================================
echo [2/6] Setting up build directory...
if not exist "%BUILD_DIR%" (
    mkdir "%BUILD_DIR%"
) else (
    echo    Build directory already exists, cleaning up...
     del /Q "%BUILD_DIR%\*.*" >nul 2>&1
)
echo    Build directory: %BUILD_DIR%

REM ============================================================================
REM Check Output
REM ============================================================================
echo [3/6] Checking output file...
if exist "%OUTPUT_EXE_FILE%" (
    >> "%OUTPUT_EXE_FILE%" ( rem ) 2>nul || (
        echo ERROR: File "%OUTPUT_EXE_FILE%" is locked
        echo Have you stopped the service?
        exit /b 1
    )
    echo    Output file is writable
) else (
    echo    First build (output doesn't exist yet)
)

REM ============================================================================
REM Generate Git Info
REM ============================================================================
echo [4/6] Generating version info...

for /f "delims=" %%i in ('git rev-parse --abbrev-ref HEAD 2^>nul') do set "GIT_BRANCH=%%i"
if not defined GIT_BRANCH set "GIT_BRANCH=unknown"

for /f "delims=" %%i in ('git rev-parse --short HEAD 2^>nul') do set "GIT_HASH=%%i"
if not defined GIT_HASH set "GIT_HASH=unknown"

set "MODIFICATIONS=0"
git diff --quiet 2>nul || set "MODIFICATIONS=1"
git diff --cached --quiet 2>nul || set "MODIFICATIONS=1"
if "!MODIFICATIONS!"=="1" set "GIT_HASH=!GIT_HASH!-mods"

for /f %%i in ('powershell -Command "Get-Date -Format yyyy-MM-dd_HH:mm:ss"') do set "BUILD_TIME=%%i"

(
    echo #pragma once
    echo #include ^<string^>
    echo namespace GitInfo {
    echo     const std::string BRANCH = "!GIT_BRANCH!";
    echo     const std::string HASH = "!GIT_HASH!";
    echo     const std::string BUILD_TIME = "!BUILD_TIME!";
    echo }
) > git_info.h

echo    Version: !GIT_BRANCH! @ !GIT_HASH!

REM ============================================================================
REM Compile Resources
REM ============================================================================
echo [5/6] Compiling resources...
rc.exe /nologo /fo "%BUILD_DIR%\app.res" app.rc
if errorlevel 1 (
    echo ERROR: Resource compilation failed
    exit /b 1
)
echo    Resources compiled

REM ============================================================================
REM Link Executable
REM ============================================================================
echo [6/6] Building executable...

cl.exe /O2 /DNDEBUG /EHsc /MT /nologo /Fe"%OUTPUT_EXE_FILE%" ^
       src\main.cpp src\WindowsPlatform.cpp "%BUILD_DIR%\app.res" /link ^
       user32.lib gdi32.lib shell32.lib advapi32.lib comctl32.lib ^
       winmm.lib Wtsapi32.lib ws2_32.lib pdh.lib iphlpapi.lib
    
if errorlevel 1 (
    echo.
    echo ============================================================================
    echo BUILD FAILED
    echo ============================================================================
    exit /b 1
)

REM Copy release notes
if exist "release-notes.txt" (
    if not exist "installer" mkdir "installer"
    copy /Y "release-notes.txt" "installer\" >nul 2>&1
)

REM Get file size
for %%F in ("%OUTPUT_EXE_FILE%") do set FILE_SIZE=%%~zF
set /a FILE_SIZE_KB=FILE_SIZE/1024

REM Calculate build time using PowerShell (reliable!)
for /f %%i in ('powershell -command "[int](Get-Date -UFormat %%s)"') do set END_EPOCH=%%i
set /a ELAPSED_S=END_EPOCH-START_EPOCH

echo    Output: %OUTPUT_EXE_FILE% (!FILE_SIZE_KB! KB)

echo.
echo ============================================================================
echo BUILD SUCCESSFUL (completed in !ELAPSED_S! seconds)
echo ============================================================================
echo.

endlocal
exit /b 0
exit /b 0
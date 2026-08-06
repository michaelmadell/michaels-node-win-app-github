@echo off
setlocal enabledelayedexpansion

set "START_TIME=%TIME%"

echo ============================================================================
echo CoreStationHXAgent - CMake Build (PRODUCTION config)
echo    TrayApp=OFF  C2A=OFF  SerialBridgePipe=OFF  SessionMonitor=ON  Metrics=OFF
echo ============================================================================

set "BUILD_DIR=build-production"
set "CONFIG=Release"
set "OUTPUT_EXE_FILE=%BUILD_DIR%\..\installer\CoreStationHXAgent.exe"
set "BUILT_EXE="

echo [1/5] Initializing MSVC environment...
rem Always call vcvarsall.bat x64, even if DevEnvDir is already set - an
rem ambient dev-shell environment (e.g. auto-initialized by a PowerShell
rem profile) can predate a Windows SDK install/repair and leave a stale LIB
rem missing the SDK's Lib\<ver>\um\x64 path, causing "cannot open file
rem kernel32.lib" at link time even though cl.exe itself works fine.
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
echo    Visual Studio environment ready

echo [2/5] Ensuring build directory exists...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [3/5] Configuring CMake (production feature set)...
rem -A x64 lets CMake auto-pick a "Visual Studio X" generator, which does its
rem own independent toolset probing instead of using the cl.exe vcvarsall.bat
rem just put on PATH above - that probing doesn't yet handle VS2026 reliably
rem (fails with "No CMAKE_CXX_COMPILER could be found" even though cl.exe is
rem present). Ninja builds directly against the PATH-resolved compiler instead.
cmake -S . -B "%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=%CONFIG% ^
    -DBUILD_TRAY_APP=OFF ^
    -DBUILD_C2A=OFF ^
    -DBUILD_SERIAL_BRIDGE_PIPE=OFF ^
    -DBUILD_SESSION_MONITOR=ON ^
    -DBUILD_METRICS=OFF
if errorlevel 1 (
    echo ERROR: CMake configure failed
    exit /b 1
)

echo [4/5] Building target CoreStationHXAgent...
cmake --build "%BUILD_DIR%" --target CoreStationHXAgent -- -j%NUMBER_OF_PROCESSORS%
if errorlevel 1 (
    echo ERROR: CMake build failed
    exit /b 1
)

echo [5/5] Collecting build artifact...
if exist "%BUILD_DIR%\%CONFIG%\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\%CONFIG%\CoreStationHXAgent.exe"
if not defined BUILT_EXE if exist "%BUILD_DIR%\bin\%CONFIG%\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\bin\%CONFIG%\CoreStationHXAgent.exe"
if not defined BUILT_EXE if exist "%BUILD_DIR%\bin\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\bin\CoreStationHXAgent.exe"
if not defined BUILT_EXE if exist "%BUILD_DIR%\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\CoreStationHXAgent.exe"

if not defined BUILT_EXE (
    echo ERROR: Build succeeded but CoreStationHXAgent.exe was not found in expected locations
    exit /b 1
)

if /I not "%BUILT_EXE%"=="%OUTPUT_EXE_FILE%" (
    copy /Y "%BUILT_EXE%" "%OUTPUT_EXE_FILE%" >nul
    if errorlevel 1 (
        echo ERROR: Failed to copy build output to %OUTPUT_EXE_FILE%
        exit /b 1
    )
)

if exist "release-notes.txt" (
    if not exist "installer" mkdir "installer"
    copy /Y "release-notes.txt" "installer\" >nul 2>&1
)

for %%F in ("%OUTPUT_EXE_FILE%") do set FILE_SIZE=%%~zF
set /a FILE_SIZE_KB=FILE_SIZE/1024

set "END_TIME=%TIME%"

echo ===========================================================================
echo Do you want to sign the executable? (Y/N)
set /p SIGN_CHOICE=
if /I "%SIGN_CHOICE%"=="Y" (
    echo Signing the executable...
    sign "%OUTPUT_EXE_FILE%"
    echo Signing completed.
) else (
    echo Skipping signing.
)

echo    Output: %OUTPUT_EXE_FILE% (!FILE_SIZE_KB! KB)
echo.
echo ============================================================================
echo BUILD SUCCESSFUL (PRODUCTION config)
echo    Started: %START_TIME%
echo    Ended:   %END_TIME%
echo ============================================================================
echo.

endlocal
exit /b 0

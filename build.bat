@echo off
setlocal enabledelayedexpansion

for /f %%i in ('powershell -command "[int](Get-Date -UFormat %%s)"') do set START_EPOCH=%%i

echo ============================================================================
echo CoreStationHXAgent - CMake Build
echo ============================================================================

set "BUILD_DIR=build"
set "CONFIG=Release"
set "OUTPUT_EXE_FILE=%BUILD_DIR%\CoreStationHXAgent.exe"
set "BUILT_EXE="

echo [1/5] Initializing MSVC environment...
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

echo [2/5] Ensuring build directory exists...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [3/5] Configuring CMake...
cmake -S . -B "%BUILD_DIR%" -A x64 -DBUILD_REGEDIT=OFF
if errorlevel 1 (
    echo ERROR: CMake configure failed
    exit /b 1
)

echo [4/5] Building target CoreStationHXAgent...
cmake --build "%BUILD_DIR%" --config "%CONFIG%" --target CoreStationHXAgent -- /m
if errorlevel 1 (
    echo ERROR: CMake build failed
    exit /b 1
)

echo [5/5] Collecting build artifact...
if exist "%BUILD_DIR%\%CONFIG%\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\%CONFIG%\CoreStationHXAgent.exe"
if not defined BUILT_EXE if exist "%BUILD_DIR%\bin\%CONFIG%\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\bin\%CONFIG%\CoreStationHXAgent.exe"
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
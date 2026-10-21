@echo off
setlocal enabledelayedexpansion

rem ============================================================================
rem CoreStationHXAgent - Windows build (CMake + Ninja + MSVC)
rem
rem   build.bat                              plain CMake defaults -> build\
rem   build.bat --profile dev-full           cmake\profiles\dev-full.cmake -> build-dev-full\
rem   build.bat --profile production         shipping feature set -> build-production\
rem   build.bat --config Debug               Debug instead of Release
rem   build.bat --profile dev-full "-DCORESTATION_LOG_MIN_LEVEL=Debug"
rem
rem Extra CMake flags are passed through to the configure step. Quote them:
rem cmd.exe splits unquoted arguments at "=".
rem
rem With no profile or --profile production the exe is copied to installer\ and
rem you're offered signing. dev-* builds stay in their build dir (dev-full has
rem IPC client auth compiled out and must never reach the installer).
rem Unit tests are built and run whenever the profile enables them.
rem See docs\dev-config.md.
rem ============================================================================

rem Run from the repo root wherever we're invoked from (setlocal restores the
rem caller's directory on exit).
cd /d "%~dp0"

set "START_TIME=%TIME%"

set "PROFILE="
set "CONFIG=Release"
set "EXTRA_CMAKE_ARGS="

:parse_args
if "%~1"=="" goto :args_done
if /I "%~1"=="--profile" (
    if "%~2"=="" (
        echo ERROR: --profile needs a name ^(see cmake\profiles\^)
        exit /b 1
    )
    set "PROFILE=%~2"
    shift
    shift
    goto :parse_args
)
if /I "%~1"=="--config" (
    if "%~2"=="" (
        echo ERROR: --config needs a value ^(Release, Debug, RelWithDebInfo, MinSizeRel^)
        exit /b 1
    )
    set "CONFIG=%~2"
    shift
    shift
    goto :parse_args
)
if /I "%~1"=="--help" goto :usage
if /I "%~1"=="-h" goto :usage
set "EXTRA_CMAKE_ARGS=!EXTRA_CMAKE_ARGS! "%~1""
shift
goto :parse_args

:usage
echo Usage: build.bat [--profile NAME] [--config Release^|Debug] ["-DVAR=VALUE" ...]
echo.
echo Profiles ^(cmake\profiles\^):
for %%P in (cmake\profiles\*.cmake) do if /I not "%%~nP"=="local" echo    %%~nP
exit /b 0

:args_done
if defined PROFILE (
    if /I "!PROFILE!"=="local" goto :bad_profile
    if not exist "cmake\profiles\!PROFILE!.cmake" goto :bad_profile
    set "BUILD_DIR=build-!PROFILE!"
) else (
    set "BUILD_DIR=build"
)

rem Only shippable builds go to installer\ (see header).
set "SHIPPABLE=0"
if not defined PROFILE set "SHIPPABLE=1"
if /I "!PROFILE!"=="production" set "SHIPPABLE=1"

set "OUTPUT_EXE_FILE=installer\CoreStationHXAgent.exe"
set "BUILT_EXE="

echo ============================================================================
if defined PROFILE (
    echo CoreStationHXAgent - CMake Build ^(profile: !PROFILE!, %CONFIG%^)
) else (
    echo CoreStationHXAgent - CMake Build ^(default options, %CONFIG%^)
)
echo ============================================================================

echo [1/6] Initializing MSVC environment...
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

echo [2/6] Ensuring build directory exists...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [3/6] Configuring CMake (build dir: %BUILD_DIR%)...
rem -A x64 lets CMake auto-pick a "Visual Studio X" generator, which does its
rem own independent toolset probing instead of using the cl.exe vcvarsall.bat
rem just put on PATH above - that probing doesn't yet handle VS2026 reliably
rem (fails with "No CMAKE_CXX_COMPILER could be found" even though cl.exe is
rem present). Ninja builds directly against the PATH-resolved compiler instead.
rem DEVELOPMENT_PROFILE is always passed (empty = none) so a build dir never
rem silently keeps a profile from an earlier configure.
cmake -S . -B "%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=%CONFIG% "-DDEVELOPMENT_PROFILE=!PROFILE!" !EXTRA_CMAKE_ARGS!
if errorlevel 1 (
    echo ERROR: CMake configure failed
    exit /b 1
)

echo [4/6] Building...
cmake --build "%BUILD_DIR%" -- -j%NUMBER_OF_PROCESSORS%
if errorlevel 1 (
    echo ERROR: CMake build failed
    exit /b 1
)

echo [5/6] Running unit tests...
if exist "%BUILD_DIR%\CTestTestfile.cmake" (
    ctest --test-dir "%BUILD_DIR%" --output-on-failure
    if errorlevel 1 (
        echo ERROR: Unit tests failed
        exit /b 1
    )
) else (
    echo    Skipped ^(ENABLE_TESTING is off^)
)

echo [6/6] Collecting build artifact...
if exist "%BUILD_DIR%\%CONFIG%\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\%CONFIG%\CoreStationHXAgent.exe"
if not defined BUILT_EXE if exist "%BUILD_DIR%\bin\%CONFIG%\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\bin\%CONFIG%\CoreStationHXAgent.exe"
if not defined BUILT_EXE if exist "%BUILD_DIR%\bin\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\bin\CoreStationHXAgent.exe"
if not defined BUILT_EXE if exist "%BUILD_DIR%\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\CoreStationHXAgent.exe"

if not defined BUILT_EXE (
    echo ERROR: Build succeeded but CoreStationHXAgent.exe was not found in expected locations
    exit /b 1
)

if "%SHIPPABLE%"=="0" (
    set "OUTPUT_EXE_FILE=!BUILT_EXE!"
    echo    Dev profile: leaving the exe in %BUILD_DIR% ^(not copied to installer\^)
    goto :report
)

if not exist "installer" mkdir "installer"
copy /Y "%BUILT_EXE%" "%OUTPUT_EXE_FILE%" >nul
if errorlevel 1 (
    echo ERROR: Failed to copy build output to %OUTPUT_EXE_FILE%
    exit /b 1
)

if exist "release-notes.txt" (
    copy /Y "release-notes.txt" "installer\" >nul 2>&1
)

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

:report
for %%F in ("%OUTPUT_EXE_FILE%") do set FILE_SIZE=%%~zF
set /a FILE_SIZE_KB=FILE_SIZE/1024

set "END_TIME=%TIME%"

echo    Output: %OUTPUT_EXE_FILE% (!FILE_SIZE_KB! KB)
echo.
echo ============================================================================
if defined PROFILE (
    echo BUILD SUCCESSFUL ^(profile: !PROFILE!^)
) else (
    echo BUILD SUCCESSFUL
)
echo    Started: %START_TIME%
echo    Ended:   %END_TIME%
echo ============================================================================
echo.

endlocal
exit /b 0

:bad_profile
echo ERROR: Unknown profile "%PROFILE%". Available profiles:
for %%P in (cmake\profiles\*.cmake) do if /I not "%%~nP"=="local" echo    %%~nP
exit /b 1

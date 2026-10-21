@echo off
setlocal enabledelayedexpansion

rem ============================================================================
rem CoreStationHXAgent - Windows build with MSYS2 MinGW G++ (CMake)
rem
rem   build-g++.bat                              option defaults -> build-mingw\
rem   build-g++.bat --profile dev-full           cmake\profiles\dev-full.cmake -> build-mingw-dev-full\
rem   build-g++.bat --config Debug
rem   build-g++.bat --profile dev-full "-DCORESTATION_LOG_MIN_LEVEL=Debug"
rem
rem Extra CMake flags go to the configure step - quote them (cmd.exe splits
rem unquoted arguments at "="). The exe stays in the build dir; this script
rem has never fed installer\ (use build.bat). See docs\dev-config.md.
rem ============================================================================

cd /d "%~dp0"

for /f %%i in ('powershell -command "[int](Get-Date -UFormat %%s)"') do set START_EPOCH=%%i

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
echo Usage: build-g++.bat [--profile NAME] [--config Release^|Debug] ["-DVAR=VALUE" ...]
echo.
echo Profiles ^(cmake\profiles\^):
for %%P in (cmake\profiles\*.cmake) do if /I not "%%~nP"=="local" echo    %%~nP
exit /b 0

:args_done
if defined PROFILE (
    if /I "!PROFILE!"=="local" goto :bad_profile
    if not exist "cmake\profiles\!PROFILE!.cmake" goto :bad_profile
    set "BUILD_DIR=build-mingw-!PROFILE!"
) else (
    set "BUILD_DIR=build-mingw"
)

echo ============================================================================
echo CoreStationHXAgent - MSYS2 MinGW G++ Build ^(profile: !PROFILE!, %CONFIG%^)
echo ============================================================================

set "OUTPUT_EXE_FILE=%BUILD_DIR%\bin\CoreStationHXAgent.exe"
set "BUILT_EXE="

echo [1/4] Locating MSYS2 MinGW64 toolchain...
set "MINGW_BIN="
where /q g++.exe
if not errorlevel 1 (
    for /f "delims=" %%i in ('where g++.exe') do (
        if not defined MINGW_BIN set "MINGW_BIN=%%~dpi"
    )
)
for %%R in (mingw64 ucrt64 clang64) do (
    if not defined MINGW_BIN if exist "C:\msys64\%%R\bin\g++.exe" set "MINGW_BIN=C:\msys64\%%R\bin\"
    if not defined MINGW_BIN if exist "%USERPROFILE%\msys64\%%R\bin\g++.exe" set "MINGW_BIN=%USERPROFILE%\msys64\%%R\bin\"
)

if not defined MINGW_BIN (
    echo ERROR: Could not find MSYS2 MinGW64 g++.exe
    echo        Install it via: pacman -S mingw-w64-x86_64-gcc
    echo        Or add msys64\mingw64\bin to PATH
    exit /b 1
)

set "PATH=%MINGW_BIN%;%PATH%"
rem CMake mishandles backslashes in -D compiler paths (they get baked into generated
rem .cmake files and misread as escape sequences) - use forward slashes instead.
set "MINGW_BIN_FWD=%MINGW_BIN:\=/%"
echo    Using toolchain: %MINGW_BIN%
"%MINGW_BIN%g++.exe" --version | findstr /b /c:"g++"

echo [1b/4] Locating CMake...
set "CMAKE_EXE=cmake"
where /q cmake.exe
if errorlevel 1 (
    for /f "usebackq tokens=*" %%i in (`"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath 2^>nul`) do set "VS_PATH=%%i"
    if defined VS_PATH if exist "!VS_PATH!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
        set "CMAKE_EXE=!VS_PATH!\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    )
)
if "%CMAKE_EXE%"=="cmake" (
    where /q cmake.exe || (
        echo ERROR: cmake.exe not found ^(checked PATH and Visual Studio bundled CMake^)
        echo        Install it via: pacman -S mingw-w64-x86_64-cmake  ^(in MSYS2^)
        exit /b 1
    )
)
echo    Using cmake: %CMAKE_EXE%

echo [2/4] Ensuring build directory exists...
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [3/4] Configuring CMake (MinGW Makefiles)...
"%CMAKE_EXE%" -S . -B "%BUILD_DIR%" -G "MinGW Makefiles" ^
    -DCMAKE_BUILD_TYPE=%CONFIG% ^
    -DCMAKE_C_COMPILER="%MINGW_BIN_FWD%gcc.exe" ^
    -DCMAKE_CXX_COMPILER="%MINGW_BIN_FWD%g++.exe" ^
    -DCMAKE_RC_COMPILER="%MINGW_BIN_FWD%windres.exe" ^
    "-DDEVELOPMENT_PROFILE=!PROFILE!" !EXTRA_CMAKE_ARGS!
if errorlevel 1 (
    echo ERROR: CMake configure failed
    exit /b 1
)

echo [4/4] Building...
"%CMAKE_EXE%" --build "%BUILD_DIR%" --config %CONFIG% -- -j%NUMBER_OF_PROCESSORS%
if errorlevel 1 (
    echo ERROR: CMake build failed
    exit /b 1
)

if exist "%BUILD_DIR%\CTestTestfile.cmake" (
    echo [4b/4] Running unit tests...
    rem ctest lives next to whichever cmake was found above.
    if "%CMAKE_EXE%"=="cmake" (set "CTEST_EXE=ctest") else (set "CTEST_EXE=!CMAKE_EXE:cmake.exe=ctest.exe!")
    "!CTEST_EXE!" --test-dir "%BUILD_DIR%" --output-on-failure
    if errorlevel 1 (
        echo ERROR: Unit tests failed
        exit /b 1
    )
)

if exist "%BUILD_DIR%\bin\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\bin\CoreStationHXAgent.exe"
if not defined BUILT_EXE if exist "%BUILD_DIR%\CoreStationHXAgent.exe" set "BUILT_EXE=%BUILD_DIR%\CoreStationHXAgent.exe"

if not defined BUILT_EXE (
    echo ERROR: Build succeeded but CoreStationHXAgent.exe was not found in expected locations
    exit /b 1
)

for %%F in ("%BUILT_EXE%") do set FILE_SIZE=%%~zF
set /a FILE_SIZE_KB=FILE_SIZE/1024

for /f %%i in ('powershell -command "[int](Get-Date -UFormat %%s)"') do set END_EPOCH=%%i
set /a ELAPSED_S=END_EPOCH-START_EPOCH

echo    Output: %BUILT_EXE% (!FILE_SIZE_KB! KB)
echo.
echo ============================================================================
echo BUILD SUCCESSFUL (completed in !ELAPSED_S! seconds)
echo ============================================================================
echo.

endlocal
exit /b 0

:bad_profile
echo ERROR: Unknown profile "%PROFILE%". Available profiles:
for %%P in (cmake\profiles\*.cmake) do if /I not "%%~nP"=="local" echo    %%~nP
exit /b 1

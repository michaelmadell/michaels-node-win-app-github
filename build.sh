#!/usr/bin/env bash
#
# CoreStationHXAgent - Linux-hosted build (CMake).
#
#   ./build.sh                                   native Linux build, option defaults  -> build-linux/
#   ./build.sh --profile dev-full                native, cmake/profiles/dev-full.cmake -> build-linux-dev-full/
#   ./build.sh --target windows                  cross-compile the Windows .exe (mingw-w64) -> build-win/
#   ./build.sh --target windows --profile production                                 -> build-win-production/
#   ./build.sh --config Debug                    Debug instead of Release
#   ./build.sh --profile dev-full -DCORESTATION_LOG_MIN_LEVEL=Debug   (other args go to the configure step)
#
# With no profile or --profile production the binary is copied to installer/
# (with release-notes.txt). dev-* builds stay in their build dir: dev-full has
# IPC client auth compiled out and must never reach the installer.
# Unit tests are built whenever the profile enables them, and run for native
# builds (cross-compiled test .exes can't run here).
# See docs/dev-config.md.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PROFILE=""
TARGET="linux"
CONFIG="Release"
EXTRA_CMAKE_ARGS=()

die() { echo "ERROR: $*" >&2; exit 1; }

list_profiles() {
    for f in cmake/profiles/*.cmake; do
        name="$(basename "$f" .cmake)"
        [[ "$name" == "local" ]] || echo "    $name"
    done
}

usage() {
    echo "Usage: ./build.sh [--profile NAME] [--target linux|windows] [--config Release|Debug] [-DVAR=VALUE ...]"
    echo
    echo "Profiles (cmake/profiles/):"
    list_profiles
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            [[ $# -ge 2 && -n "$2" ]] || die "--profile needs a name (see cmake/profiles/)"
            PROFILE="$2"; shift 2 ;;
        --target)
            [[ $# -ge 2 && -n "$2" ]] || die "--target needs a value (linux or windows)"
            TARGET="$2"; shift 2 ;;
        --config)
            [[ $# -ge 2 && -n "$2" ]] || die "--config needs a value (Release, Debug, RelWithDebInfo, MinSizeRel)"
            CONFIG="$2"; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            EXTRA_CMAKE_ARGS+=("$1"); shift ;;
    esac
done

if [[ -n "$PROFILE" ]]; then
    if [[ "$PROFILE" == "local" || ! -f "cmake/profiles/$PROFILE.cmake" ]]; then
        echo "ERROR: Unknown profile \"$PROFILE\". Available profiles:" >&2
        list_profiles >&2
        exit 1
    fi
fi

case "$TARGET" in
    linux)   BUILD_DIR="build-linux"; OUTPUT_NAME="CoreStationHXAgent" ;;
    windows) BUILD_DIR="build-win";   OUTPUT_NAME="CoreStationHXAgent.exe" ;;
    *)       die "--target must be linux or windows (got \"$TARGET\")" ;;
esac
[[ -n "$PROFILE" ]] && BUILD_DIR="$BUILD_DIR-$PROFILE"

# Only shippable builds go to installer/ (see header).
SHIPPABLE=0
[[ -z "$PROFILE" || "$PROFILE" == "production" ]] && SHIPPABLE=1

START_EPOCH=$(date +%s)

echo "============================================================================"
echo "CoreStationHXAgent - CMake Build (target: $TARGET, profile: ${PROFILE:-none}, $CONFIG)"
echo "============================================================================"

# Installs a missing apt package, as the old build-linux.sh did - but only
# from an interactive terminal: without one, sudo can block waiting for a
# password it can never read, so fail fast with the command to run instead.
ensure_tool() {
    local check="$1" package="$2"
    if eval "$check" >/dev/null 2>&1; then
        return 0
    fi
    if [[ ! -t 0 ]] || ! command -v apt-get >/dev/null 2>&1; then
        die "$package not found. Install it with: sudo apt-get install -y $package"
    fi
    echo "    $package not found. Installing..."
    sudo apt-get install -y "$package" || die "Failed to install $package. Please install it manually."
}

echo "[1/5] Checking toolchain..."
ensure_tool "command -v cmake" cmake
CMAKE_ARGS=(-S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$CONFIG" "-DDEVELOPMENT_PROFILE=$PROFILE")
if command -v ninja >/dev/null 2>&1; then
    CMAKE_ARGS+=(-G Ninja)
fi

if [[ "$TARGET" == "linux" ]]; then
    CXX="${CXX:-g++}"
    ensure_tool "command -v $CXX" build-essential
    ensure_tool "command -v pkg-config" pkg-config
    ensure_tool "pkg-config --exists dbus-1" libdbus-1-dev
    echo "    Using $($CXX --version | head -n1)"
    CMAKE_ARGS+=(-DCMAKE_CXX_COMPILER="$CXX")
else
    # The toolchain file uses the -posix mingw-w64 variants (needed for
    # std::thread); windmc compiles the Event Log message table.
    ensure_tool "command -v x86_64-w64-mingw32-g++-posix" mingw-w64
    ensure_tool "command -v x86_64-w64-mingw32-windmc" binutils-mingw-w64-x86-64
    echo "    Using $(x86_64-w64-mingw32-g++-posix --version | head -n1)"
    CMAKE_ARGS+=(-DCMAKE_TOOLCHAIN_FILE=mingw-w64-toolchain.cmake)
fi

echo "[2/5] Configuring CMake (build dir: $BUILD_DIR)..."
# DEVELOPMENT_PROFILE is always passed (empty = none) so a build dir never
# silently keeps a profile from an earlier configure.
cmake "${CMAKE_ARGS[@]}" ${EXTRA_CMAKE_ARGS[@]+"${EXTRA_CMAKE_ARGS[@]}"}

echo "[3/5] Building..."
cmake --build "$BUILD_DIR" --parallel "$(nproc)"

echo "[4/5] Running unit tests..."
if [[ ! -f "$BUILD_DIR/CTestTestfile.cmake" ]]; then
    echo "    Skipped (ENABLE_TESTING is off)"
elif [[ "$TARGET" == "windows" ]]; then
    echo "    Skipped (cross-compiled Windows test binaries can't run on this host)"
else
    ctest --test-dir "$BUILD_DIR" --output-on-failure
fi

echo "[5/5] Collecting build artifact..."
BUILT=""
for candidate in "$BUILD_DIR/bin/$OUTPUT_NAME" "$BUILD_DIR/$OUTPUT_NAME" "$BUILD_DIR/$CONFIG/$OUTPUT_NAME"; do
    if [[ -f "$candidate" ]]; then BUILT="$candidate"; break; fi
done
[[ -n "$BUILT" ]] || die "Build succeeded but $OUTPUT_NAME was not found in $BUILD_DIR"

OUTPUT="$BUILT"
if [[ "$SHIPPABLE" == "1" ]]; then
    mkdir -p installer
    OUTPUT="installer/$OUTPUT_NAME"
    cp -f "$BUILT" "$OUTPUT"
    [[ "$TARGET" == "linux" ]] && chmod +x "$OUTPUT"
    [[ -f release-notes.txt ]] && cp -f release-notes.txt installer/
else
    echo "    Dev profile: leaving the binary in $BUILD_DIR (not copied to installer/)"
fi

FILE_SIZE_KB=$(( $(stat -c%s "$OUTPUT") / 1024 ))
ELAPSED_S=$(( $(date +%s) - START_EPOCH ))

echo "    Output: $OUTPUT (${FILE_SIZE_KB} KB)"
echo ""
echo "============================================================================"
echo "BUILD SUCCESSFUL (completed in ${ELAPSED_S} seconds)"
echo "============================================================================"
echo ""

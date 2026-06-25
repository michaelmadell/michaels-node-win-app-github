#!/usr/bin/env bash
#
# Native Linux build using GCC/G++ via CMake.
# Mirrors build.bat (which drives the Windows/MSVC build through CMake).

set -e

START_EPOCH=$(date +%s)

echo "============================================================================"
echo "CoreStationHXAgent - GCC/G++ Build"
echo "============================================================================"

BUILD_DIR="build"
CONFIG="Release"
OUTPUT_EXE_FILE="$BUILD_DIR/bin/CoreStationHXAgent"

if ! command -v cmake >/dev/null 2>&1; then
    echo "ERROR: cmake not found. Installing..."
    sudo apt install cmake -y
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install cmake. Please install it manually."
        exit 1
    fi
fi

echo "[1/4] Selecting compiler..."
CC="${CC:-gcc}"
CXX="${CXX:-g++}"
if ! command -v "$CXX" >/dev/null 2>&1; then
    echo "ERROR: $CXX not found. Installing..."
    sudo apt install build-essential -y
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install $CXX. Please install it manually."
        exit 1
    fi
fi
echo "    Using $($CXX --version | head -n1)"

if ! command -v dbus-1 >/dev/null 2>&1; then
    echo "ERROR: dbus-1 not found. Installing..."
    sudo apt install libdbus-1-dev -y
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install libdbus-1-dev. Please install it manually."
        exit 1
    fi
fi

echo "[2/4] Configuring CMake (build dir: $BUILD_DIR)..."
cmake -S . -B "$BUILD_DIR" \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_BUILD_TYPE="$CONFIG"

echo "[3/4] Building target CoreStationHXAgent..."
cmake --build "$BUILD_DIR" --target CoreStationHXAgent -- -j"$(nproc)"

echo "[4/4] Collecting build artifact..."
if [ ! -f "$OUTPUT_EXE_FILE" ]; then
    echo "ERROR: Build succeeded but $OUTPUT_EXE_FILE was not found"
    exit 1
fi

FILE_SIZE_KB=$(( $(stat -c%s "$OUTPUT_EXE_FILE") / 1024 ))
END_EPOCH=$(date +%s)
ELAPSED_S=$(( END_EPOCH - START_EPOCH ))

echo "    Output: $OUTPUT_EXE_FILE (${FILE_SIZE_KB} KB)"
echo ""
echo "============================================================================"
echo "BUILD SUCCESSFUL (completed in ${ELAPSED_S} seconds)"
echo "============================================================================"
echo ""

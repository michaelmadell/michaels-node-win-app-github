#!/bin/bash

START_EPOCH=$(date +%s)

echo "=========================================="
echo "CoreStation HX Agent - CMake Build - Linux"
echo "=========================================="

BUILD_DIR="build"
CONFIG="Release"
INSTALLER_DIR="installer"
OUTPUT_BIN_FILE="${INSTALLER_DIR}/CoreStationHXAgent"
BUILT_BIN=""

echo "[1/4] Ensuring build and output directories exist..."
mkdir -p "$BUILD_DIR"
mkdir -p "$INSTALLER_DIR"

echo "[2/4] Configuring CMake..."
# NOTE: Linux generators use CMAKE_BUILD_TYPE instead of the Windows --config flag at build time
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$CONFIG" -DBUILD_REGEDIT=OFF
if [ $? -ne 0 ]; then
    echo "ERROR: CMake Configure Failed."
    exit 1
fi

echo "[3/4] Building Target CoreStationHXAgent..."
cmake --build "$BUILD_DIR" --config "$CONFIG" --target CoreStationHXAgent --parallel
if [ $? -ne 0 ]; then
    echo "ERROR: CMake build failed"
    exit 1
fi

echo "[4/4] Collecting build artifact..."
if [ -f "${BUILD_DIR}/CoreStationHXAgent" ]; then
    BUILT_BIN="${BUILD_DIR}/CoreStationHXAgent"
elif [ -f "${BUILD_DIR}/bin/CoreStationHXAgent" ]; then
    BUILT_BIN="${BUILD_DIR}/bin/CoreStationHXAgent"
elif [ -f "${BUILD_DIR}/${CONFIG}/CoreStationHXAgent" ]; then
    BUILT_BIN="${BUILD_DIR}/${CONFIG}/CoreStationHXAgent"
fi

if [ "$BUILT_BIN" != "$OUTPUT_BIN_FILE" ]; then
    cp -f "$BUILT_BIN" "$OUTPUT_BIN_FILE"
    chmod +x "$OUTPUT_BIN_FILE"
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to copy build output to $OUTPUT_BIN_FILE"
        exit 1
    fi
fi

if [ -f "release-notes.txt" ]; then
    cp -f "release-notes.txt" "${INSTALLER_DIR}/"
fi

# Get filesize in bytes using GNU stat
FILE_SIZE=$(stat -c%s "$OUTPUT_BIN_FILE" 2>/dev/null || stat -f%z "$OUTPUT_BIN_FILE")
FILE_SIZE_KB=$((FILE_SIZE / 1024))

END_EPOCH=$(date +%s)
ELAPSED_S=$((END_EPOCH - START_EPOCH))

echo "    Output: $OUTPUT_BIN_FILE (${FILE_SIZE_KB} KB)"
echo ""
echo "====================================================="
echo "BUILD SUCCESSFUL (completed in ${ELAPSED_S} seconds)"
echo "====================================================="
echo ""

exit 0
#!/usr/bin/bash

OUTPUT_DIR="./build"
OUTPUT_EXE_FILE="$OUTPUT_DIR/CoreStationHXAgent.exe"
HEADER_FILE="git_info.h"
VERSION_H="version.h"

mkdir -p "$OUTPUT_DIR"

if [ -f "$OUTPUT_EXE_FILE" ]; then
    if ! [ -w "$OUTPUT_EXE_FILE" ]; then
        echo "File $OUTPUT_EXE_FILE is not writable. Is it in use?"
        exit 1
    fi
fi

GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
GIT_HASH=$(git rev-parse --short HEAD)
MODIFICATIONS=0

if ! git diff --quiet || ! git diff --cached --quiet; then
    MODIFICATIONS=1
    GIT_HASH="${GIT_HASH}-mods"
fi

BUILD_TIME=$(date +"%Y-%m-%d_%H:%M:%S")

cat <<EOF > "$HEADER_FILE"
#pragma once
#include <string>
namespace GitInfo {
    const std::string BRANCH = "$GIT_BRANCH";
    const std::string HASH = "$GIT_HASH";
    const std::string BUILD_TIME = "$BUILD_TIME";
}
EOF

echo "Header file $HEADER_FILE generated."
echo "Branch: $GIT_BRANCH | Hash: $GIT_HASH | Time: $BUILD_TIME"

echo "Compiling Resources..."
x86_64-w64-mingw32-windres app.rc -O coff -o app.res

echo "Building EXE file..."
x86_64-w64-mingw32-g++-posix -O2 -DNDEBUG -static \
    -D_WIN32_WINNT=0x0601 \
    src/main.cpp \
    src/WindowsPlatform.cpp \
    app.res \
    -o "$OUTPUT_EXE_FILE" \
    -lws2_32 -liphlpapi -lwtsapi32 -lsetupapi -lpdh -lwbemuuid -lole32 -loleaut32 -lpsapi -ladvapi32 -luser32 -lgdi32 -lshell32 -lcomctl32 -lwinmm

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

echo "Finished!"
exit 0


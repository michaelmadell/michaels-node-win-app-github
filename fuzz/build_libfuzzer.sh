#!/usr/bin/env bash
# Build the CmcCommandHandler fuzz harness with clang's libFuzzer + ASan/UBSan.
# Needs clang++ (Linux, WSL, or the clang that ships inside a recent Visual
# Studio install under VC\Tools\Llvm\x64\bin — plain MinGW/MSVC don't carry
# libFuzzer).
#
# On Windows with VS's clang, ASan links as a DLL
# (clang_rt.asan_dynamic-x86_64.dll under
# VC\Tools\Llvm\x64\lib\clang\<ver>\lib\windows\) that isn't on PATH by
# default — the built exe fails to launch (exit 0xC0000135 / STATUS_DLL_NOT_FOUND,
# silently) until you copy that DLL next to cmc_fuzzer or add its dir to PATH.
# Confirmed working (164k+ execs, 20k exec/s) with that fix in place.
#
# Usage:
#   ./fuzz/build_libfuzzer.sh            # build only
#   ./fuzz/build_libfuzzer.sh --run      # build then fuzz until Ctrl-C
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

OUT=cmc_fuzzer

clang++ -std=c++17 -g -O1 \
    -fsanitize=fuzzer,address,undefined \
    -D_DISABLE_STRING_ANNOTATION -D_DISABLE_VECTOR_ANNOTATION \
    -DENABLE_C2A \
    -I ../src \
    harness_cmc.cpp \
    ../src/modules/cmc/CmcCommandHandler.cpp \
    -o "$OUT"
# (the two _DISABLE_*_ANNOTATION defines only matter on Windows/MSVC-STL
# builds of clang, where they fix an "annotate_string mismatch" link error
# against the prebuilt clang_rt.fuzzer lib; harmless no-ops elsewhere.)

echo "Built ./fuzz/$OUT"

if [[ "${1:-}" == "--run" ]]; then
    mkdir -p corpus_cmc
    exec ./"$OUT" corpus_cmc -dict=cmc.dict -max_len=256
fi

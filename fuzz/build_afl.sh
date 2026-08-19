#!/usr/bin/env bash
# Build the same harness for AFL++ instead of libFuzzer — useful once you
# want persistent-mode throughput or AFL++'s mutators/CmpLog. Needs AFL++
# installed (apt install afl++, or build from AFLplusplus/AFLplusplus).
#
# Usage:
#   ./fuzz/build_afl.sh
#   afl-fuzz -i fuzz/corpus_cmc -o fuzz/out_afl -x fuzz/cmc.dict -- ./fuzz/cmc_fuzzer_afl
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

: "${AFL_PATH:=/usr/lib/afl}"      # where aflpp_driver / libAFLDriver.a live
: "${CXX:=afl-clang-fast++}"

DRIVER_LIB=""
for candidate in \
    "$AFL_PATH/libAFLDriver.a" \
    "/usr/local/lib/afl/libAFLDriver.a" \
    "/usr/lib/AFLplusplus/libAFLDriver.a"; do
    if [[ -f "$candidate" ]]; then
        DRIVER_LIB="$candidate"
        break
    fi
done

if [[ -z "$DRIVER_LIB" ]]; then
    echo "libAFLDriver.a not found — set AFL_PATH to your AFL++ checkout/install" >&2
    echo "(it ships aflpp_driver.c under utils/aflpp_driver; 'make' there builds libAFLDriver.a)" >&2
    exit 1
fi

"$CXX" -std=c++17 -g -O1 \
    -fsanitize=address,undefined \
    -DENABLE_C2A \
    -I ../src \
    -c harness_cmc.cpp -o harness_cmc.o

"$CXX" -std=c++17 -g -O1 \
    -fsanitize=address,undefined \
    -DENABLE_C2A \
    -I ../src \
    -c ../src/modules/cmc/CmcCommandHandler.cpp -o CmcCommandHandler.o

"$CXX" -fsanitize=address,undefined harness_cmc.o CmcCommandHandler.o "$DRIVER_LIB" -o cmc_fuzzer_afl

echo "Built ./fuzz/cmc_fuzzer_afl"
echo "Run: afl-fuzz -i fuzz/corpus_cmc -o fuzz/out_afl -x fuzz/cmc.dict -- ./fuzz/cmc_fuzzer_afl"

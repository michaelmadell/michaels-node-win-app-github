# Testing + CI: Test Infrastructure Expansion

> **Status: implemented (2026-10-21).** This document was originally the task
> prompt; it has been updated to describe what was actually built, including
> the decisions taken where the original prompt conflicted with the codebase
> or with what CI can run. How-to: README "Running tests". See
> [Decisions and deviations](#decisions-and-deviations).

## Context (before this work)

- 4 test files (19 tests on Windows with the bridge enabled): `MetricCache`
  TTL, `NetworkInterface`/`SystemState` equality, and IPC Subject matching
  (Windows and Linux variants). googletest via `FetchContent`, gated by
  `ENABLE_TESTING`.
- CI (`bitbucket-pipelines.yml`, `.github/workflows/ci-build.yml`) built but
  **never ran tests** — and its Windows jobs were **broken**: they
  cross-compiled on Ubuntu 24.04, whose mingw-w64 is GCC 13, which has no
  C++23 `<print>`.
- The prompt's "Current State" overstated CI: there were no MSVC or native
  MinGW CI jobs. Bitbucket Cloud has no Windows runners, so everything was
  Linux-hosted.

## What was built

### Test files (`tests/`)

| File | Covers | Gated by |
|---|---|---|
| `test_errors.cpp` | Every error type's designated-init construction and defaults; the `core::Error` concept; `make_error_code` categories, values and messages; `is_error_code_enum` comparisons; a name for every code; `describe()` with and without an OS error; `std::expected` success, failure, `and_then`/`or_else`/`transform` and `void`; the `Logging.h` helpers (`LevelFor`, `LogError`, `LogExpectedError`, `LogErrorOnChange` dedupe per key/code/OS error, `ClearReportedError` recovery, min-level filtering) | — |
| `test_serialization.cpp` | Serial line framing: every terminator style, partial lines across reads, a CRLF split across reads, empty lines, verbatim payloads, NUL/binary bytes, oversized lines, 1000 lines in one read | — |
| `test_serial_manager.cpp` | `SerialManager` without hardware: starts closed, opening a missing port fails and is reported, closed-port I/O is rejected, idempotent close, nothing delivered when idle, reconnect pacing; on Windows, repeated open failures logged once (still printed to stderr every time) | — |
| `test_metrics.cpp` | CPU busy % (rounding, no elapsed time, counter reset), the Windows `GetSystemTimes` conversion (regression test for the bug below), `/proc/stat` and `/proc/meminfo` parsing, uptime and GiB formatting, `MetricCache` TTL with `MockClock`, and `MetricsCollector` against `MockPlatform` (field mapping, system drive, cache invalidation, formatted report, null platform) | `MetricsCollector` part: `BUILD_METRICS` |
| `test_command_handler.cpp` | Every C2A verb and its reply; case and whitespace handling; forced shutdown/restart with reasons; lock and logoff; missing or malformed timeout and time values (each with its logged reason); scheduled → cancelled, scheduled → executed at the deadline, past time → immediate; `cancel` with nothing pending; the unknown-command and empty-command dialogs; a `StrictMock` check that `ping` touches nothing else | `BUILD_C2A` |
| `test_ipc_bridge.cpp` | End-to-end client authentication over a real in-process named pipe (Windows) or socketpair (Linux). The unsigned test binary is rejected (on real Windows, `TRUST_E_NOSIGNATURE`); a non-pipe handle is unresolved; with `IPC_AUTH_DEV_DISABLE`, the dev bypass is used | `BUILD_SERIAL_BRIDGE_PIPE` |

Totals: 98 tests on Windows (MSVC, MinGW, and mingw-w64 under Wine) and 96
on Linux, with the `dev-ci` profile.

### Test infrastructure

- `tests/test_helpers.h`:
  - `OutputStreamCapture` captures any `ostream`.
  - `MockClock` is a static chrono clock you advance by hand.
  - `TempFile` is a temp file deleted on destruction.
  - `LogCapture` records `core::Log` calls, thread-safely.
  - `MessageSink` collects messages from other threads and can wait for one.
- `tests/mock_platform.h`: a gmock `test::MockPlatform` covering every
  `Platform` virtual, including the `ENABLE_METRICS` / `ENABLE_C2A` ones.
- `tests/CMakeLists.txt`:
  - Compiles in the production sources under test: `SerialManager.cpp`,
    plus `CmcCommandHandler.cpp`, `MetricsCollector.cpp` and the IPC auth
    files when their features are on.
  - Gives `unit_tests` the app's exact compile definitions
    (`$<TARGET_PROPERTY:CoreStationHXAgent,COMPILE_DEFINITIONS>`).
    `Platform.h` / `SystemState.h` change shape with them, so a mismatch
    would break vtables.
  - Defines `CORESTATION_LOG_CAPTURE`, so tests never write to the real
    Event Log or syslog.
  - Links gmock and, for MinGW, `stdc++exp`.
  - Adds `UNIT_TEST_TIMEOUT` (default 30 s per test, as a ctest `TIMEOUT`)
    and `UNIT_TEST_ARGS` (extra googletest flags).
  - Uses `gtest_discover_tests` with `DISCOVERY_TIMEOUT 120`, deferring
    discovery to test time when cross-compiling without an emulator.

### Small production changes (for testability, behaviour-preserving except the bug fix)

| Change | Why |
|---|---|
| `src/modules/metrics/MetricMath.h` (new): `CpuBusyPercent`, `CpuTimesFromSystemTimes`, `ParseProcStatCpuLine`, `MemInfoUsedPercent`, `FormatUptime`, `FormatGigabytes` | The CPU/RAM/uptime/disk maths was inline in the platform files with OS calls. Windows and Linux now share the tested functions; Linux keeps its exact previous definition (idle = idle field, total includes guest). |
| `src/modules/serial/LineFramer.h` (new): `serial::ExtractLines` | Line framing moved verbatim out of `SerialManager::ProcessIncomingData`. |
| `MetricCache<T, Clock = std::chrono::steady_clock>` | Lets tests drive the TTL with `MockClock` instead of sleeping. Also fixes the long-standing `-Wreorder` warning. |
| `core::LogCapture()` hook in `Logging.h`, compiled only with `CORESTATION_LOG_CAPTURE` | Tests assert on what was logged without touching the system log. |
| `mingw-w64-toolchain.cmake` sets `CMAKE_CROSSCOMPILING_EMULATOR` to Wine when installed | `ctest` and gtest discovery can run the cross-compiled test exe on Linux. |

**Bug found and fixed — Windows CPU usage.** `GetSystemTimes()` reports
kernel time *including* idle time. The old code subtracted idle from kernel,
then subtracted idle again from the total, in unsigned arithmetic. Whenever
idle time exceeded busy time (any load under ~50%) the subtraction wrapped,
so the CPU percentage sent to the BMC (`cpuUsage`, C2A `status`) was garbage
clamped to 0 or 100. It now uses `metrics::CpuTimesFromSystemTimes` +
`CpuBusyPercent`. A mutation check confirmed the regression tests fail
against the old formula. The wire format is unchanged; the values are now
correct.

### Coverage — `cmake/coverage.cmake`

- `-DENABLE_COVERAGE=ON` (GCC/Clang, needs `ENABLE_TESTING`) instruments
  `unit_tests` with `--coverage -O0`.
- The `coverage` target runs gcovr over `src/core/` + `src/modules/`:
  - HTML report: `<build>/coverage/index.html`
  - Cobertura XML: `coverage.xml`
  - Summary printed to the console
  - Fails below `COVERAGE_MIN_LINE` (default **75**)
- Baseline measured in the CI image (Ubuntu 24.04, gcovr 7.0, `dev-ci`):
  **78.6% lines** (574/730), 91.4% functions, 47.8% branches. The gate sits
  just below the baseline; raise it as coverage grows.

| File | Lines |
|---|---|
| `Errors.h` | 94% |
| `Logging.h` | 100% |
| `CmcCommandHandler.cpp` | 97% |
| `MetricCache.h` | 100% |
| `MetricMath.h` | 97% |
| `MetricsCollector.cpp` | 93% |
| `LineFramer.h` | 92% |
| `SerialManager.cpp` | 50% (the success paths need a real port) |

### CI

| Job | Bitbucket | GitHub Actions | Image / runner |
|---|---|---|---|
| Windows exe + Inno installer | ✔ (image changed) | ✔ (container changed) | `debian:trixie` |
| Windows unit tests, mingw-w64 cross under Wine | ✔ new | ✔ new | `debian:trixie` |
| Linux build + .deb | ✔ unchanged | ✔ unchanged | `ubuntu:24.04` / `ubuntu-latest` |
| Linux unit tests + coverage gate | ✔ new | ✔ new | `ubuntu:24.04` / `ubuntu-latest` |
| Windows unit tests, MSVC (`build.bat --profile dev-ci`) | — | ✔ new | `windows-latest` |
| Windows unit tests, MSYS2 UCRT64 MinGW | — | ✔ new | `windows-latest` |

- Every test job lists the tests (`ctest -N`), runs them with a timeout and
  `--output-on-failure`, and writes JUnit XML to `test-results/`.
  - Bitbucket picks that folder up for its Tests tab.
  - GitHub uploads it, with the coverage report, as artifacts, even when
    tests fail.
- Any test failure, or coverage below the gate, fails the job.
- The shipping artifacts are still built without a profile (plain option
  defaults), as before.

## Decisions and deviations

1. **The coverage gate is GCC-only and scoped to testable code** *(user
   decision)*. MSVC has no `/coverage` flag (it needs VS Enterprise or
   OpenCppCoverage). The platform layers and `main.cpp` can't be
   unit-tested without OS mocking, so a 60% whole-tree gate would fail every
   build. The gate is 75% of `src/core` + `src/modules` — what the tests
   compile in — just under the measured 78.6%.
2. **Windows test strategy** *(user decision)*. The prompt's Bitbucket
   `windowsservercore` image can't run on Bitbucket Cloud (no Windows
   runners). Instead:
   - Both CI systems run mingw-w64 cross-compiled tests under Wine.
   - GitHub additionally runs native MSVC and MinGW jobs on
     `windows-latest`.
   - All Linux-side CI steps were validated locally in their real Docker
     images. The GitHub Windows jobs were validated by running their
     commands on a Windows machine.
3. **`debian:trixie` for the Windows cross jobs.** Ubuntu 24.04–26.04 all
   ship mingw-w64 GCC 13 (no `<print>`). Debian 13 has GCC 14 with the same
   `-posix` toolchain names and `apt`, so `tools/build-inno-installer.sh`
   works unchanged; this also fixes the previously broken Windows CI jobs.
   The Linux/.deb job stays on Ubuntu 24.04 so the package keeps running on
   the Ubuntu releases it targets.
4. **"Serialization" = line framing.** The BMC protocol is newline-delimited
   text, not "start byte, length, payload, end byte". There is no maximum
   line length; the test documents that rather than inventing one.
5. **Not unit-tested, by constraint (no hardware, no OS mocking):**
   - serial port enumeration (it doesn't exist) and read/write timeouts
     (they need a real port)
   - `SerialBridgePipe`'s forwarding loop (bound to the concrete
     `WindowsPlatform`)
   - the periodic resend (a thread loop in `main.cpp`)
   - `EventLogger` initialisation and event writing (it would write to the
     developer's real Event Log; `core::Log` is tested through the capture
     hook instead)
   - the platform getters and `main.cpp`'s lifecycle
6. **`MockClock` is static** (`MockClock::now()`), not the prompt's
   instance-based class: chrono clocks are used through a static `now()`, so
   that's what `MetricCache<T, Clock>` needs. Call `MockClock::reset()` in
   `SetUp`.
7. **"`GTEST_OPTIONS`" and sharding** are `UNIT_TEST_ARGS` and
   `UNIT_TEST_TIMEOUT` (CMake cache variables), plus googletest's own
   `GTEST_TOTAL_SHARDS` / `GTEST_SHARD_INDEX`. Every test is its own ctest
   entry, so `ctest --parallel` also shards. The prompt's
   `cmake --build --config Test` doesn't exist (there's no Test
   configuration).
8. **Production code was refactored for testability** (the table above), and
   one real bug, the Windows CPU percentage, was fixed. The Linux CPU and RAM
   maths deliberately keeps its existing definitions.

## Acceptance Criteria

### Phase 1
- [x] `test_errors.cpp` covers all error types and `std::expected` paths
- [~] `test_serial_manager.cpp` covers port open/close — *open failure,
      close and reconnect pacing are covered; read/write timeouts need
      hardware*
- [~] `test_ipc_bridge.cpp` covers auth state — *real-pipe/socketpair
      authentication is covered; message forwarding is bound to
      `WindowsPlatform`*
- [x] `test_command_handler.cpp` covers command dispatch and response
      formatting
- [x] `test_metrics.cpp` covers CPU/memory/disk calculations
- [x] `test_serialization.cpp` covers message parsing and edge cases
- [x] All new tests pass on Windows (MSVC, MinGW, mingw-w64 under Wine) and
      Linux (GCC 13)

### Phase 2
- [x] `test_helpers.h` provides `OutputStreamCapture`, `MockClock` and
      `TempFile` (plus `LogCapture` and `MessageSink`)
- [x] `mock_platform.h` provides a gmock `Platform`
- [x] Test configuration: verbosity via `UNIT_TEST_ARGS`, timeouts via
      `UNIT_TEST_TIMEOUT`, failure output via `--output-on-failure`

### Phase 3
- [x] CI runs tests on Windows MSVC and MinGW (GitHub), mingw-w64 under Wine
      (both CI systems) and Linux GCC (both)
- [x] CI fails on any test failure
- [x] JUnit XML is produced and stored (Bitbucket Tests tab / GitHub
      artifacts)
- [~] Coverage reporting is configured for GCC, with a gate — *MSVC is not
      supported (see decision 1)*
- [x] The build matrix runs tests alongside the production builds
- [ ] *Not yet observed on the real Bitbucket/GitHub runners. The Linux
      steps ran in their exact Docker images; the GitHub Windows jobs' commands
      ran on a local Windows machine.*

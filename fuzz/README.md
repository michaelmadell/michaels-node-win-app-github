# Fuzzing CoreStationHXAgent

Two tiers here. If you want robustness confidence on the **shipped
`.exe`** for customer machines, start with tier 2 — that's what actually
runs on their box. Tier 1 is faster for shaking out the parser's logic bugs
first, but it's a rebuild from source, not the installed binary.

| Tier | Target | Script |
|---|---|---|
| 1 — source harness | `CmcCommandHandler::handle()` rebuilt standalone, mocked `Platform` | `harness_cmc.cpp` + `build_libfuzzer.sh` / `build_afl.sh` |
| 2 — **the real exe** | The actual built/installed `CoreStationHXAgent.exe`, spawned and driven exactly like it runs on a customer box | `cli_arg_fuzz.py`, `serial_blackbox_fuzz.py`, `pipe_blackbox_fuzz.py` |

## Tier 2: fuzzing the actual binary

### 0. One-time setup — crash dumps

The app has no `SetUnhandledExceptionFilter`/`MiniDumpWriteDump` of its
own, so an unhandled exception in the field just vanishes (service
restarts silently, or the user sees "has stopped working" and the dump
goes wherever Windows' default WER policy sends it — not necessarily
somewhere you can get to). Fix that once, for good:

```powershell
# elevated PowerShell
.\fuzz\setup_crash_dumps.ps1
```

This registers `HKLM\...\Windows Error Reporting\LocalDumps\CoreStationHXAgent.exe`
so every crash — however triggered — drops a full minidump in
`fuzz\crash_dumps\`. `.\fuzz\setup_crash_dumps.ps1 -Remove` undoes it.
`pip install psutil pyserial pywin32` for the scripts below.

### 1. CLI-argument fuzzing — cheapest, no wiring needed

```powershell
python fuzz\cli_arg_fuzz.py --exe "C:\path\to\CoreStationHXAgent.exe" --iterations 3000
```

Spawns the real exe repeatedly with mutated argv, watches for crashes/bad
exit codes via `monitor_common` + the crash-dump folder from step 0.
**Defaults to a safe subset** (`--tray-only`-prefixed argv only) — anything
without `--tray-only` runs the full `main()` path, which unconditionally
probes and can disable/re-enable a real AMT serial device via PnP/registry
before it even looks at the rest of argv (see
`src/modules/amt/AMTPortManager.cpp`). Pass `--full-launch` to cover that
path too, but only on a disposable VM — not a shared or customer-like
machine.

### 2. c2a serial-protocol fuzzing — the main external input surface

The agent reads chassis commands over a hardcoded port (COM3 on HX2000
CPUs, COM1 otherwise — see `src/main.cpp`). To fuzz the real exe without
real chassis hardware, give it a virtual COM port with that exact name:

```powershell
# com0com: create a pair and name one end to match what the exe will open.
# On a non-HX2000 dev/test box that's COM1 -- check your machine's own log
# line ("Detected HX2000 CPU..." / "No HX2000 CPU detected...") to be sure.
setupc.exe install PortName=COM1 PortName=COM9
```

Then, with the agent built with `-DBUILD_C2A` and running (as the service,
or interactively):

```powershell
python fuzz\serial_blackbox_fuzz.py --port COM9 --mode mutate --iterations 5000
python fuzz\serial_blackbox_fuzz.py --port COM9 --mode race
```

(Linux: `socat -d -d pty,raw,echo=0 pty,raw,echo=0` gives two `/dev/pts/N`
paths instead of com0com; point the agent's serial-open call at one, drive
the other with `--port /dev/pts/N`.)

Liveness is judged two ways: the c2a protocol's own `ping`→`pong` contract
(catches hangs even if the process is still alive), and — via
`monitor_common`/psutil — a direct process-alive check plus a diff against
the crash-dump folder, so a real crash gets logged as `[CRASH]` and a wedge
as `[HANG]` instead of lumping them together.

**`--mode race` targets a specific hypothesis**, not random mutation: reading
`CmcCommandHandler.cpp`, `beginScheduledAction()` holds `mutex_` while
joining the *previous* scheduled action's thread, but that thread runs
`showMessageDialog()` — a blocking `MessageBoxW()` on interactive builds —
*before* it ever touches the mutex. Two scheduled `shutdown`/`restart`
commands back-to-back, first dialog still unacknowledged, and the `join()`
never returns — wedging the whole c2a channel (it runs on the single serial
RX thread) until a human dismisses the dialog on the target machine. Worth
confirming for real before trusting the read-only analysis.

### 3. Named-pipe bridge fuzzing (Windows, admin-only)

Only relevant if built with `-DBUILD_SERIAL_BRIDGE_PIPE=ON`. The pipe's ACL
restricts connections to `BUILTIN\Administrators`, so run elevated — this
tests what an already-privileged-but-buggy local caller could trigger, not
a remote/unprivileged attack surface.

```powershell
python fuzz\pipe_blackbox_fuzz.py --iterations 5000
```

Every byte written lands verbatim in
`WindowsPlatform::forwardSerialBridgeMessage()` and gets written straight
to the real serial connection — run `serial_blackbox_fuzz.py`'s liveness
check (or just watch the target) at the same time to see what a malformed
forwarded payload does downstream.

## Tier 1: source-level harness (fast, parser-only)

```bash
./fuzz/build_libfuzzer.sh --run
# or AFL++:
./fuzz/build_afl.sh
afl-fuzz -i fuzz/corpus_cmc -o fuzz/out_afl -x fuzz/cmc.dict -- ./fuzz/cmc_fuzzer_afl
```

Builds `harness_cmc.cpp` against the real, unmodified
`CmcCommandHandler.cpp` with `Platform` mocked out — millions of
execs/second, ASan/UBSan-instrumented, but it's a separate binary from
`CoreStationHXAgent.exe`, not the shipped one. Good for quickly narrowing
in on parser-logic bugs (verified working: 164k+ execs in 8s on this repo,
no crash in that short a run — a real search needs hours, not seconds).
Confirmed-working note: on Windows with VS's bundled clang, the ASan
runtime links as a DLL not on `PATH` by default (silent
`STATUS_DLL_NOT_FOUND`) and needs
`-D_DISABLE_STRING_ANNOTATION -D_DISABLE_VECTOR_ANNOTATION` to link against
the prebuilt `clang_rt.fuzzer` lib — both already handled in
`build_libfuzzer.sh`.

`corpus_cmc/` (one file per grammar shape) and `cmc.dict` (verb/modifier/
unit tokens) feed either engine, source or exe-level.

## Extending

`SerialManager::ProcessIncomingData()`'s `\r`/`\n` line-reassembly loop
isn't unit-fuzzable as written (it calls `this->Read()`, which talks to a
real OS handle) — tier 2's serial fuzzing exercises it as a side effect,
which is arguably the right way to test it anyway given it's glued to a
family of raw stateful OS calls, not a pure function.

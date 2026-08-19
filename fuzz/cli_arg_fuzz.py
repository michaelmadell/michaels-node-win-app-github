#!/usr/bin/env python3
"""
Fuzzes the real CoreStationHXAgent.exe's command-line parsing directly --
no serial wiring, no admin pipe, just spawns the actual installed/built exe
repeatedly with mutated argv and watches for crashes. Cheapest and most
direct "does the shipped binary fall over on unexpected input" check.

Covers: --tray-only / --parent-pid parsing (src/main.cpp), --interactive /
--service (WindowsPlatform::hasSwitch, case-insensitive exact match against
CommandLineToArgvW), and whatever's left of argv after those are stripped.

Each child is killed after --child-timeout if it doesn't exit on its own --
some argv combinations legitimately start the full serial-monitoring loop
and run forever, that's not a bug by itself, just not interesting for this
script (use the interactive run + serial_blackbox_fuzz.py for that).

SAFETY: any argv WITHOUT --tray-only runs the full main() path, which -- on
Windows, unconditionally, before touching argv again -- probes for an AMT
serial device and may disable/re-enable it via PowerShell/PnP and rewrite
its COM port registry assignment (see GetAMTComPort/disableAMTComPort/
reassignComPort in src/modules/amt/AMTPortManager.cpp). That's real,
disruptive, machine-state-changing side effect, not just argv parsing.
By default this script only ever generates --tray-only-prefixed argv (that
branch returns before any of that runs) so it's safe to fire thousands of
times. Pass --full-launch to also generate non-tray-only argv -- only do
that on a disposable VM/test box you don't mind having its AMT COM port
state churned, never on a customer-representative or shared machine.

Requires: psutil (`pip install psutil`)
Run fuzz/setup_crash_dumps.ps1 once beforehand so a crash leaves a minidump.

Usage:
  python cli_arg_fuzz.py --exe "C:\\Program Files\\CoreStation\\CoreStationHXAgent.exe"
  python cli_arg_fuzz.py --exe .\\build\\CoreStationHXAgent.exe --iterations 2000
  python cli_arg_fuzz.py --exe .\\build\\CoreStationHXAgent.exe --full-launch   # disposable VM only
"""
import argparse
import random
import string
import subprocess
import sys
import time
from pathlib import Path

try:
    import monitor_common as mon
except ImportError:
    mon = None

# Real switches the app parses (see src/main.cpp, WindowsPlatform.cpp
# hasSwitch calls) plus values that are meaningful right after them.
KNOWN_SWITCHES = ["--tray-only", "--parent-pid", "--interactive", "--service"]
NASTY_VALUES = [
    "", "0", "-1", "99999999999999999999", "not-a-number",
    "A" * 8192, "-1" * 2000, "\x00", "--tray-only", "NUL", "..\\..\\..\\..",
]


def random_argv(rng: random.Random, full_launch: bool) -> list:
    kind = rng.random()

    if not full_launch:
        # Safe subset: always --tray-only-prefixed, so main() returns via
        # runAsTrayHelper() before the AMT/PnP probing code ever runs.
        argv = ["--tray-only"]
        for _ in range(rng.randrange(0, 5)):
            argv.append(rng.choice(["--parent-pid"] + NASTY_VALUES))
        return argv

    if kind < 0.3:
        # Plausible-but-wrong: real switch, garbage value.
        argv = [rng.choice(KNOWN_SWITCHES)]
        for _ in range(rng.randrange(0, 4)):
            argv.append(rng.choice(KNOWN_SWITCHES + NASTY_VALUES))
        return argv
    if kind < 0.5:
        # --parent-pid specifically, since atoi() on argv[j+1] is the one
        # actual numeric parse in the CLI path (src/main.cpp ~line 418).
        return ["--tray-only", "--parent-pid", rng.choice(NASTY_VALUES)]
    if kind < 0.7:
        # Duplicated/reordered/truncated known switches.
        argv = list(KNOWN_SWITCHES)
        rng.shuffle(argv)
        return argv[: rng.randrange(1, len(argv) + 1)]
    # Pure noise argv -- WITHOUT --tray-only, so this hits the full AMT/PnP
    # launch path. Only reachable with --full-launch.
    n = rng.randrange(0, 6)
    return ["".join(rng.choice(string.printable) for _ in range(rng.randrange(0, 32))) for _ in range(n)]


def run_once(exe: str, argv: list, child_timeout: float) -> dict:
    cmd = [exe] + argv
    start = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        return {"status": "spawn-failed", "error": str(e)}

    try:
        out, err = proc.communicate(timeout=child_timeout)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return {"status": "timeout (killed -- likely entered the normal run loop, not necessarily a bug)"}

    elapsed = time.time() - start
    # Negative return code on Windows means the process died from an
    # unhandled exception/signal (STATUS_ACCESS_VIOLATION etc show up as
    # large positive values interpreted as negative by Python's subprocess).
    crashed = code is not None and (code < 0 or code > 0x7FFFFFFF or code in (0xC0000005, -1073741819))
    return {
        "status": "crashed" if crashed else "exited",
        "code": code,
        "elapsed": elapsed,
        "stderr_tail": err[-500:].decode("utf-8", "replace") if err else "",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", required=True, help="path to the built/installed CoreStationHXAgent.exe")
    ap.add_argument("--iterations", type=int, default=3000)
    ap.add_argument("--child-timeout", type=float, default=3.0,
                     help="seconds to let each child run before killing it as a non-exiting case")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--log", default="cli_fuzz.log")
    ap.add_argument("--full-launch", action="store_true",
                     help="also generate non---tray-only argv, which runs the real AMT/PnP probing "
                          "code on Windows -- disposable VM only, see module docstring")
    args = ap.parse_args()

    exe_path = Path(args.exe)
    if not exe_path.is_file():
        sys.exit(f"{exe_path} not found")

    if args.full_launch:
        print("--full-launch set: this WILL repeatedly probe/disable/re-enable a real AMT serial "
              "device and rewrite its COM port registry assignment. Disposable VM/test box only.")
        time.sleep(3)

    if mon is None:
        print("monitor_common/psutil not available -- crash-dump attribution disabled "
              "(pip install psutil to fix).")

    rng = random.Random(args.seed)
    crashes = 0
    dumps_before = mon.snapshot_dumps() if mon is not None else set()

    with open(args.log, "a", encoding="utf-8") as log:
        for i in range(args.iterations):
            argv = random_argv(rng, args.full_launch)
            result = run_once(str(exe_path), argv, args.child_timeout)

            flagged = result["status"] in ("crashed", "spawn-failed")
            dump_names = []
            if flagged and mon is not None:
                mon.wait_for_dump_settle()
                dump_names = mon.new_dumps(dumps_before)
                dumps_before = mon.snapshot_dumps()

            if flagged or dump_names:
                crashes += 1
                line = f"iter={i} argv={argv!r} result={result} dumps={dump_names}"
                log.write(line + "\n")
                log.flush()
                print(f"!! {line}")

            if i % 200 == 0:
                print(f"iter {i}/{args.iterations}, flagged so far: {crashes}")

    print(f"Done. {crashes} flagged runs logged to {args.log}")


if __name__ == "__main__":
    main()

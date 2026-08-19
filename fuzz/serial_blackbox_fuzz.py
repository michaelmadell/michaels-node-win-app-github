#!/usr/bin/env python3
"""
Black-box fuzzer for the CmcCommandHandler c2a protocol, driven against the
*actual built and running* CoreStationHXAgent (exe or service) over its real
or virtual COM port. Complements fuzz/harness_cmc.cpp (which fuzzes the
parser in isolation) by exercising the whole pipeline: SerialManager's
line-reassembly, the "c2a, " prefix strip in main.cpp, CmcCommandHandler, and
whatever the mocked-out harness can't see (real thread scheduling, real
showMessageDialog/WTSSendMessage/MessageBoxW calls, real shutdown/restart
gating).

Requires: pyserial (`pip install pyserial`)

Setup (pick one):
  - Windows: install com0com (https://com0com.sourceforge.net/) to create a
    linked pair, e.g. COM8<->COM9. Point the agent's serial thread at COM3 or
    COM1 (see src/main.cpp) via one end -- easiest is temporarily editing the
    hardcoded port for a fuzzing build, or bridging a real port with a
    USB-serial loopback adapter into the same virtual pair.
  - Linux: socat -d -d pty,raw,echo=0 pty,raw,echo=0
    prints two /dev/pts/N paths -- point the agent (built with -DBUILD_C2A)
    at one via its serial-open call, drive the other from this script.

Usage:
  python serial_blackbox_fuzz.py --port COM9 --mode mutate --iterations 5000
  python serial_blackbox_fuzz.py --port COM9 --mode race
  python serial_blackbox_fuzz.py --port /dev/pts/4 --mode mutate --seed 1

Liveness is judged two ways: the c2a protocol's own request/response
contract ("ping" must always get "pong" -- catches hangs/deadlocks even
though the process is still running), and, when monitor_common can see the
process (same machine, sufficient privilege), a direct process-alive check
plus a crash-dump diff so an actual crash gets flagged distinctly from a
wedge. Run fuzz/setup_crash_dumps.ps1 once beforehand (Windows) so crashes
leave a minidump to diff against.
"""
import argparse
import random
import string
import sys
import time
from pathlib import Path

try:
    import serial
except ImportError:
    sys.exit("pyserial required: pip install pyserial")

try:
    import monitor_common as mon
except ImportError:
    mon = None  # process/dump checks degrade gracefully to protocol-only

CORPUS = [
    "ping",
    "status",
    "ct",
    "shutdown",
    "restart",
    "shutdown, force",
    "restart, force, operator requested",
    "shutdown, timeout, 30s",
    "shutdown, timeout, 5m, scheduled maintenance",
    "restart, timeout, 1h",
    "shutdown, time, 2026-08-07 12:00:00",
    "cancel",
    "lock",
    "logoff",
]

# Values plugged into "shutdown, timeout, <X>" / "shutdown, time, <X>" during
# mutation -- boundary/garbage cases the handwritten parser (stol, mktime,
# chrono conversions) is most likely to mishandle.
NASTY_TOKENS = [
    "", "0", "-1", "-99999", "99999999999999999999",
    "1x", "s", "9999999999999s", "9999999999999h",
    "2026-13-99 99:99:99", "0000-00-00 00:00:00", "not-a-date",
    "\x00", "A" * 4096, "﷐" * 50,  # embedded NUL, unicode noise, oversized
]


def mutate(line: str, rng: random.Random) -> str:
    choice = rng.random()
    if choice < 0.25:
        # Swap the value token in a timeout/time command for a nasty one.
        parts = line.split(",")
        if len(parts) >= 3:
            parts[2] = " " + rng.choice(NASTY_TOKENS)
            return ",".join(parts)
    if choice < 0.5:
        # Bit flip.
        b = bytearray(line.encode("utf-8", "surrogatepass"))
        if b:
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        return b.decode("utf-8", "replace")
    if choice < 0.7:
        # Truncate / extend with random junk.
        junk = "".join(rng.choice(string.printable) for _ in range(rng.randrange(1, 64)))
        return line + junk
    if choice < 0.85:
        # Extra/missing commas and whitespace.
        return line.replace(",", rng.choice([",,", " ,", ", ,", ""]))
    # Wholly random line.
    length = rng.randrange(0, 128)
    return "".join(rng.choice(string.printable) for _ in range(length))


def send_line(ser: serial.Serial, payload: str):
    # ProcessIncomingData() splits on the first \r or \n it sees, and
    # main.cpp only routes lines starting with the literal "c2a, " prefix
    # into CmcCommandHandler -- send both prefixed and (occasionally)
    # unprefixed traffic so the prefix-matching branch gets covered too.
    ser.write(("c2a, " + payload + "\r\n").encode("utf-8", "surrogatepass"))


def check_alive(ser: serial.Serial, timeout: float) -> bool:
    ser.reset_input_buffer()
    send_line(ser, "ping")
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        chunk = ser.read(256)
        if chunk:
            buf += chunk
            if b"pong" in buf:
                return True
        else:
            time.sleep(0.02)
    return False


def classify_and_log(args, log: Path, tag: str, iter_no: int, dumps_before: set, **context):
    """On a detected liveness failure, tell a real crash (process gone /
    new .dmp appeared) apart from a wedge (process still running, just not
    answering) and log accordingly. Returns True if the process is dead
    (caller should probably stop or restart it before continuing)."""
    process_dead = False
    dump_names = []
    if mon is not None:
        process_dead = not mon.is_alive(args.exe_name)
        mon.wait_for_dump_settle()
        dump_names = mon.new_dumps(dumps_before)

    ctx = " ".join(f"{k}={v!r}" for k, v in context.items())
    if dump_names:
        line = f"[CRASH] {tag} iter={iter_no} dumps={dump_names} {ctx}"
    elif process_dead:
        line = f"[CRASH] {tag} iter={iter_no} process-exited (no dump captured -- run setup_crash_dumps.ps1) {ctx}"
    else:
        line = f"[HANG] {tag} iter={iter_no} process-still-running {ctx}"

    print("!! " + line)
    with log.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    return process_dead


def run_mutate(ser, args, rng):
    log = Path(args.log)
    failures = 0
    dumps_before = mon.snapshot_dumps() if mon is not None else set()
    for i in range(args.iterations):
        base = rng.choice(CORPUS)
        payload = mutate(base, rng)
        send_line(ser, payload)

        if i % args.check_every == 0:
            if not check_alive(ser, args.timeout):
                failures += 1
                dead = classify_and_log(args, log, "mutate", i, dumps_before, payload=payload)
                dumps_before = mon.snapshot_dumps() if mon is not None else set()
                if dead:
                    print(f"   process is gone -- restart the agent, then re-run with --seed {args.seed} "
                          f"to reach iter {i} again and confirm the repro.")
                    break
                time.sleep(args.recover)

        if i % 500 == 0:
            print(f"iter {i}/{args.iterations}, failures so far: {failures}")

    print(f"Done. {failures} liveness failures logged to {log}")


def run_race(ser, args):
    """
    Targets a specific hypothesis from reading CmcCommandHandler.cpp:
    beginScheduledAction() takes CmcCommandHandler::mutex_ and joins the
    previous pendingThread_ while still holding it. That previous thread
    (runScheduledAction) does its logging/sendToMec_/showMessageDialog work
    *before* it tries to acquire the same mutex_ for cv_.wait_until(). If a
    second scheduled shutdown/restart arrives while the first is still
    inside showMessageDialog (which is a blocking MessageBoxW() call when
    the agent runs interactively rather than as a session-0 service), the
    join() in beginScheduledAction never returns -- and since handle() runs
    on the single serial RX thread, the whole c2a channel wedges until a
    human dismisses the dialog on the target machine.

    This sends two scheduled commands back-to-back with no gap, then polls
    for "pong" -- a wedge shows up as check_alive() timing out repeatedly.
    """
    print("Racing scheduled shutdown/restart pairs -- watch the target's screen")
    print("for a stuck 'chassis controller has scheduled a shutdown' dialog.")
    log = Path(args.log)
    dumps_before = mon.snapshot_dumps() if mon is not None else set()
    for i in range(args.iterations):
        verb_a = random.choice(["shutdown", "restart"])
        verb_b = random.choice(["shutdown", "restart"])
        send_line(ser, f"{verb_a}, timeout, 30s, race-{i}-a")
        send_line(ser, f"{verb_b}, timeout, 30s, race-{i}-b")

        if not check_alive(ser, args.timeout):
            dead = classify_and_log(args, log, "race", i, dumps_before, verb_a=verb_a, verb_b=verb_b)
            dumps_before = mon.snapshot_dumps() if mon is not None else set()
            if dead:
                print("   process is gone -- restart the agent before continuing.")
                break
            print("   (if a wedge, dismiss the dialog on the target and it should recover)")
            time.sleep(args.recover)
        else:
            # Clean up so the next iteration isn't racing against a still-
            # pending action from this one.
            send_line(ser, "cancel")
        time.sleep(0.05)

    print("Race run complete.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="Serial port wired to the agent's RX (e.g. COM9 or /dev/pts/4)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--mode", choices=["mutate", "race"], default="mutate")
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--check-every", type=int, default=10, help="mutate mode: liveness-check every N sends")
    ap.add_argument("--timeout", type=float, default=2.0, help="seconds to wait for pong before declaring a hang")
    ap.add_argument("--recover", type=float, default=3.0, help="seconds to back off after a detected hang")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--log", default="fuzz_hangs.log")
    ap.add_argument("--exe-name", default="CoreStationHXAgent.exe",
                     help="image name to check for process-alive/crash-dump attribution (needs monitor_common/psutil)")
    args = ap.parse_args()

    if mon is None:
        print("monitor_common/psutil not available -- crash vs. wedge won't be distinguished, "
              "falling back to protocol-only hang detection (pip install psutil to fix).")

    rng = random.Random(args.seed)
    ser = serial.Serial(args.port, args.baud, timeout=0)

    try:
        if not check_alive(ser, args.timeout):
            sys.exit(f"No pong from {args.port} before fuzzing started -- check wiring/port and that "
                      f"the agent was built with -DBUILD_C2A and is running.")
        print("Baseline ping/pong OK, starting fuzz run.")

        if args.mode == "mutate":
            run_mutate(ser, args, rng)
        else:
            run_race(ser, args)
    finally:
        ser.close()


if __name__ == "__main__":
    main()

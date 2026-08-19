#!/usr/bin/env python3
"""
Black-box fuzzer for SerialBridgePipe (\\\\.\\pipe\\corestation_serial_bridge),
built when -DBUILD_SERIAL_BRIDGE_PIPE=ON. Windows-only.

The pipe ACL restricts connections to BUILTIN\\Administrators (see
SerialBridgePipe.cpp's "D:(A;;GA;;;BA)" descriptor), so this must run
elevated -- it's testing what an already-privileged-but-compromised or
buggy local caller could do, not a remote/unprivileged attack surface.
Every byte written arrives verbatim at
WindowsPlatform::forwardSerialBridgeMessage() and gets written straight to
the real serial connection to the MEC -- so this mostly stresses buffer
handling (fixed 1024-byte ReadFile buffer, OVERLAPPED bookkeeping) rather
than a text parser. Run fuzz/serial_blackbox_fuzz.py against the far end
at the same time to see what a malformed forwarded payload does to the c2a
channel.

Requires: pywin32 (`pip install pywin32`), psutil (`pip install psutil`).
Run fuzz/setup_crash_dumps.ps1 once beforehand so a crash leaves a minidump.

Usage (elevated):
  python pipe_blackbox_fuzz.py --iterations 5000
"""
import argparse
import random
import string
import sys
import time

try:
    import win32file
    import win32pipe
    import pywintypes
except ImportError:
    sys.exit("pywin32 required: pip install pywin32")

try:
    import monitor_common as mon
except ImportError:
    mon = None

PIPE_NAME = r"\\.\pipe\corestation_serial_bridge"


def random_payload(rng: random.Random) -> bytes:
    choice = rng.random()
    if choice < 0.3:
        # Around the 1024-byte read buffer boundary.
        length = rng.choice([0, 1, 1023, 1024, 1025, 2048, 65536])
    elif choice < 0.6:
        length = rng.randrange(0, 256)
    else:
        length = rng.randrange(0, 8192)

    if choice < 0.5:
        return bytes(rng.randrange(0, 256) for _ in range(length))
    return "".join(rng.choice(string.printable) for _ in range(length)).encode("utf-8", "surrogatepass")


def one_connection(payload: bytes, connect_timeout_ms: int) -> str:
    """Opens a fresh handle (matches the real client contract -- the server
    accepts exactly one connection at a time, PIPE_TYPE_MESSAGE), writes the
    payload, closes. Returns a short status string for logging."""
    try:
        handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_WRITE,
            0, None,
            win32file.OPEN_EXISTING,
            0, None,
        )
    except pywintypes.error as e:
        return f"connect-failed: {e}"

    try:
        win32file.WriteFile(handle, payload)
        return "ok"
    except pywintypes.error as e:
        return f"write-failed: {e}"
    finally:
        win32file.CloseHandle(handle)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--delay", type=float, default=0.01, help="seconds between connections")
    ap.add_argument("--log", default="pipe_fuzz.log")
    ap.add_argument("--exe-name", default="CoreStationHXAgent.exe")
    args = ap.parse_args()

    if mon is None:
        print("monitor_common/psutil not available -- crash vs. busy-server won't be distinguished "
              "(pip install psutil to fix).")

    rng = random.Random(args.seed)
    fails = 0
    dumps_before = mon.snapshot_dumps() if mon is not None else set()
    with open(args.log, "a", encoding="utf-8") as log:
        for i in range(args.iterations):
            payload = random_payload(rng)
            status = one_connection(payload, connect_timeout_ms=2000)
            if status != "ok":
                fails += 1
                extra = ""
                if mon is not None:
                    mon.wait_for_dump_settle()
                    dumps = mon.new_dumps(dumps_before)
                    dumps_before = mon.snapshot_dumps()
                    if dumps:
                        extra = f" CRASH dumps={dumps}"
                    elif not mon.is_alive(args.exe_name):
                        extra = " CRASH process-exited (no dump captured -- run setup_crash_dumps.ps1)"
                log.write(f"iter={i} len={len(payload)} status={status}{extra} "
                          f"payload={payload[:64]!r}\n")
                log.flush()
                print(f"iter {i}: {status}{extra} (len={len(payload)})")
                if extra:
                    print("   process is gone or dumped -- restart the agent before continuing.")
                    break
            if i % 200 == 0:
                print(f"iter {i}/{args.iterations}, failures logged: {fails}")
            time.sleep(args.delay)

    print(f"Done. {fails} non-ok results logged to {args.log}")
    print("A failure without 'CRASH' just means the pipe server was busy/restarting -- "
          "cross-check against the agent's own log file and Windows Event Log "
          "(Application) for exception entries around the same timestamps.")


if __name__ == "__main__":
    main()

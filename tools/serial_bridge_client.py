#!/usr/bin/env python3
r"""
Test client for CoreStationHXAgent's authenticated serial bridge pipe.

Connects to \\.\pipe\corestation_serial_bridge and writes raw bytes,
which the agent forwards verbatim to the serial port. The pipe's ACL
only allows BUILTIN\Administrators to connect -- run this from an
elevated (Run as Administrator) prompt, or CreateFile fails with
"Access is denied" (WinError 5).

Usage:
    python serial_bridge_client.py "hello world"
    python serial_bridge_client.py --hex 41420D0A
    python serial_bridge_client.py --interactive
"""

import argparse
import sys

PIPE_PATH = r"\\.\pipe\corestation_serial_bridge"


def send(data: bytes) -> None:
    try:
        # Windows named pipes are openable via the regular CRT path on
        # Windows -- CPython's open() calls CreateFileW under the hood,
        # so no pywin32 dependency is needed for a simple write.
        with open(PIPE_PATH, "r+b", buffering=0) as pipe:
            pipe.write(data)
    except FileNotFoundError:
        print(f"Pipe not found: {PIPE_PATH}\n"
              "Is CoreStationHXAgent running with the serial bridge enabled?",
              file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print("Access denied connecting to the pipe.\n"
              "The pipe only allows BUILTIN\\Administrators -- "
              "re-run this from an elevated prompt.",
              file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("message", nargs="?", help="Text message to send (no newline added)")
    group.add_argument("--hex", help="Raw bytes to send, as a hex string (e.g. 41420D0A)")
    group.add_argument("--interactive", action="store_true",
                        help="Read lines from stdin and send each one, \\r\\n appended")
    args = parser.parse_args()

    if args.interactive:
        print(f"Connected target: {PIPE_PATH}")
        print("Type a line and press Enter to send. Ctrl+C to quit.")
        try:
            for line in sys.stdin:
                line = line.rstrip("\n").rstrip("\r")
                if not line:
                    continue
                send((line + "\r\n").encode("utf-8"))
                print(f"[sent] {line!r}")
        except KeyboardInterrupt:
            pass
        return

    if args.hex:
        try:
            payload = bytes.fromhex(args.hex)
        except ValueError:
            print("Invalid --hex value, must be an even-length hex string.", file=sys.stderr)
            sys.exit(1)
        send(payload)
        print(f"Sent {len(payload)} bytes (hex): {args.hex}")
        return

    if args.message is None:
        parser.print_help()
        sys.exit(1)

    send(args.message.encode("utf-8"))
    print(f"Sent {len(args.message)} bytes: {args.message!r}")


if __name__ == "__main__":
    main()

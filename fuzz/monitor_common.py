"""
Shared helpers for fuzzing the *actual built exe* rather than a source-level
harness: process liveness, crash-dump detection, and exit-code capture
against the real CoreStationHXAgent.exe (or its --tray-only child).

Requires: psutil (`pip install psutil`)
"""
import time
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:
    raise SystemExit("psutil required: pip install psutil")

DEFAULT_EXE_NAME = "CoreStationHXAgent.exe"
DEFAULT_DUMP_FOLDER = Path(__file__).parent / "crash_dumps"


def find_process(exe_name: str = DEFAULT_EXE_NAME) -> Optional["psutil.Process"]:
    """Locate the running agent by image name. Works whether it's running
    interactively, as a service host, or as the --tray-only child."""
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] and proc.info["name"].lower() == exe_name.lower():
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def is_alive(exe_name: str = DEFAULT_EXE_NAME) -> bool:
    proc = find_process(exe_name)
    return proc is not None and proc.is_running()


def snapshot_dumps(dump_folder: Path = DEFAULT_DUMP_FOLDER) -> set:
    """Call before a fuzz batch; diff against a later call (see new_dumps)
    to attribute a crash dump to the input that caused it. Requires
    setup_crash_dumps.ps1 to have been run first."""
    if not dump_folder.exists():
        return set()
    return {p.name for p in dump_folder.glob("*.dmp")}


def new_dumps(before: set, dump_folder: Path = DEFAULT_DUMP_FOLDER) -> list:
    if not dump_folder.exists():
        return []
    return sorted(set(p.name for p in dump_folder.glob("*.dmp")) - before)


def wait_for_dump_settle(dump_folder: Path = DEFAULT_DUMP_FOLDER, timeout: float = 5.0):
    """WER writes the .dmp asynchronously after the crash; give it a moment
    to finish before treating new_dumps() as authoritative."""
    time.sleep(min(timeout, 2.0))

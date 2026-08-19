# CoreStation Agent (C#)

A cross-platform .NET 8 service that reports system information to a serial
port, speaking the same wire protocol as the C++ agent in the repository root.
One codebase runs as a Windows Service and as a systemd daemon.

## Why this exists

The C++ agent achieves cross-platform support by compiling separate
`WindowsPlatform` and `LinuxPlatform` translation units behind `#ifdef`s, with
feature tiers (`ENABLE_METRICS`, `ENABLE_C2A`) selected at build time. This
port keeps the same shape but resolves those choices at runtime instead:
platform differences sit behind three interfaces, and the feature tiers are
configuration flags. A single build artifact therefore covers every
combination, which is the main practical difference between the two.

## Layout

| Path | Responsibility |
| --- | --- |
| `Core/` | Platform-neutral contracts and models |
| `Serial/` | Port selection, the byte-level link, line reassembly |
| `Protocol/` | Outbound channel abstraction, C2A command dispatch |
| `Platform/Linux/`, `Platform/Windows/` | The OS-specific halves |
| `Platform/Common/` | Helpers shared by both |
| `Workers/` | The hosted services that drive everything |

Three interfaces carry all platform variation:

- `ISystemInformation` — hostname, user, OS version, session state, network
  adapters, plus the cheap CPU/RAM/uptime trio that must work even when
  metrics collection is off, because the C2A `status` command depends on it.
- `IMetricsProvider` — the expensive tier (disk, network, GPU, update state).
- `IPowerActions` — shutdown, restart, lock, log off, user notification.

## Wire protocol

Every message is one `key, value` line terminated with CRLF, unchanged from the
C++ agent. Lines are paced 250 ms apart by default because the receiver's
buffer is small and drops input that arrives back to back.

On each new connection the agent sends a preamble, then reports changes as they
happen and a metrics block plus `HB` every 30 seconds:

```
appVersion, 1.0.0
winVersion, Ubuntu 24.04.4 LTS
osBuild, 6.18.5-fc-v20
sessionState, 6
hostname, NODE-30042-0023
username, labtest
network, 00:17:FD:60:02:E1, up, 192.168.203.82, fe80::98d7:656:a39:8ad3, dhcp, Ethernet 2
cpuUsage, 12%
ramUsage, 34%
freeDisk, 29.3GB
wuState, Up to Date
diskQueue, 0.00
netRetrans, 0.00/s
uptime, 0d 00h 21m 22s
gpuInfo, Unknown/Unsupported GPU Driver
gpuUsage, 0%
highRamProcs, 568 root 598884 chrome|13341 root 209940 code
HB
appExit, shutting down
```

Session state codes are the Windows `WTS_*` values; the Linux provider maps
logind states onto the same numbers so the controller sees one vocabulary.

`winVersion` is the friendly OS name and `osBuild` the numeric one, on both
platforms:

| | Windows | Linux |
| --- | --- | --- |
| `winVersion` | `Windows 11 Pro 24H2` | `Ubuntu 24.04.4 LTS` |
| `osBuild` | `10.0.26100` | `6.18.5-fc-v20` |

On Windows the friendly name comes from the registry's `ProductName` plus
`DisplayVersion`. Windows 11 still reports a `ProductName` of "Windows 10 …"
for application-compatibility reasons, so the agent rewrites it to "11" when
the build number is 22000 or higher — the same correction the C++ agent makes,
and the only reliable way to tell the two apart.

### Inbound commands

Lines prefixed `c2a, ` are commands. The serial link is a fixed PCB trace to
the MEC chip with no user-accessible endpoint, so input is treated as trusted
chassis input.

| Command | Reply | Effect |
| --- | --- | --- |
| `ping` | `pong` | — |
| `status` | `status, cpu=12%, ram=34%, uptime=...` | — |
| `ct` | `ct, 2026-08-15 08:51:35` | — |
| `shutdown` / `restart` | `<verb>Pending, <deadline>` | Acts after the default grace period |
| `shutdown, force` | `<verb>Executing` | Acts immediately |
| `shutdown, timeout, 5m[, reason]` | `<verb>Pending, <deadline>, reason` | Acts after the duration |
| `shutdown, time, 2026-08-15 17:00:00` | `<verb>Pending, <deadline>` | Acts at the wall-clock time |
| `cancel` | `<verb>Cancelled`, or `cancelled, none-pending` | Aborts a pending action |
| `lock` / `logoff` | `locking` / `loggingOff` | Acts on the console session |
| anything else | — | Shown to the signed-in user |

Malformed deadlines are rejected (`shutdownRejected, invalid-timeout`) rather
than coerced, so a typo cannot become an immediate shutdown.

## Configuration

`appsettings.json`, overridable by environment variables using `__` as the
separator (`Agent__PortName=/dev/ttyUSB0`).

| Setting | Default | Notes |
| --- | --- | --- |
| `PortName` | *(empty)* | Empty means auto-detect from the CPU model |
| `BaudRate` | `115200` | |
| `SendPacingMilliseconds` | `250` | Gap between lines |
| `ReconnectDelayMilliseconds` | `5000` | |
| `HeartbeatIntervalSeconds` | `30` | |
| `StatePollIntervalSeconds` | `30` | |
| `EnableMetrics` | `true` | The C++ `BUILD_METRICS` option |
| `EnableC2A` | `true` | The C++ `BUILD_C2A` option |
| `DefaultGracePeriodSeconds` | `15` | Warning window for a bare shutdown |
| `ReportedMacPrefixes` | Amulet Hotkey, Congatec, AAEON | Empty reports every adapter |
| `Hx2000CpuModels` | three Ultra models | Decides HX2000 vs HX3000 |

Port auto-detection follows the C++ agent: an HX2000 CPU means `COM3` on
Windows and `/dev/ttyS2` on Linux; anything else means `COM1` / `/dev/ttyS0`.

## Building

```bash
dotnet build                       # from csharp/
dotnet test                        # 64 tests
```

Self-contained single-file publishes:

```bash
dotnet publish src/CoreStationAgent -c Release -r win-x64   --self-contained \
    -p:PublishSingleFile=true -o publish/win-x64
dotnet publish src/CoreStationAgent -c Release -r linux-x64 --self-contained \
    -p:PublishSingleFile=true -o publish/linux-x64
```

## Installing

**Linux**

```bash
sudo mkdir -p /opt/corestation-agent
sudo cp -r publish/linux-x64/* /opt/corestation-agent/
sudo cp deploy/corestation-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now corestation-agent
journalctl -u corestation-agent -f
```

**Windows** (elevated)

```powershell
sc.exe create CoreStationAgent binPath= "C:\Program Files\CoreStationAgent\CoreStationAgent.exe" start= auto
sc.exe start CoreStationAgent
```

The host detects its environment, so the same binary also runs interactively
from a terminal for debugging.

## Testing against a virtual port

No hardware required — `socat` provides a pty pair:

```bash
socat PTY,raw,echo=0,link=./agent-port PTY,raw,echo=0,link=./bmc-port &
Agent__PortName=./agent-port dotnet run --project src/CoreStationAgent
```

Reading `./bmc-port` shows the traffic, and writing `c2a, ping` to it exercises
command dispatch. Note that pseudo-terminals have no DTR/RTS lines; the agent
asserts them best-effort and logs at debug level when they are unavailable,
which is what makes this work.

## Notes on the port

A few things differ from the C++ agent, deliberately:

- **All writes go through one queue.** In the C++ agent the heartbeat and
  serial threads both call `SerialManager::Write` concurrently. Here every
  line is queued to a single writer loop, so the port is only ever touched by
  one thread and partial lines cannot interleave.
- **The outbound queue is bounded** (256 lines, oldest dropped). A long outage
  cannot grow memory, and stale telemetry is the right thing to discard since a
  fresh reading supersedes it.
- **Shutdown ordering is explicit.** Hosted services stop in reverse
  registration order, which is what lets `appExit` be the genuinely last line:
  telemetry stops, then the notifier sends and waits for the queue to drain,
  then the port closes.
- **Line reassembly is separated** into `LineFramer` and unit-tested, since
  serial reads split at arbitrary boundaries.

Not carried over: the Windows tray helper, the named-pipe serial bridge, and
the AMT COM-port reassignment logic. These are Windows-specific and independent
of the telemetry path.

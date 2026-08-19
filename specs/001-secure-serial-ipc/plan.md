# Implementation Plan: Authenticated Serial IPC for Company Applications

**Branch**: `001-secure-serial-ipc` | **Date**: 2026-08-15 (re-planned after 2026-08-15 clarify session) | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-secure-serial-ipc/spec.md`

## Summary

Provide an authenticated local IPC channel for company applications to forward messages/status to
the serial port, on **all four** platform/agent combinations: the existing C++ agent on Windows
(hardening today's named-pipe bridge) and Linux (new), and the newer C# agent on Windows and
Linux (both new — it has no bridge today). Authentication verifies the connecting process's
executable is signed with the company's EV code-signing identity — Authenticode on Windows,
a detached CMS/PKCS#7 signature (same certificate, new signing step) on Linux — never OS
privilege alone. Each agent's own build system gets a compile-time-only dev flag
(`IPC_AUTH_DEV_DISABLE`) that is structurally absent from Release/RC/GA builds.

## Technical Context

**Language/Version**: C++17 (existing `src/` agent, MSVC/MinGW G++) **and** C# / .NET 8
(existing `csharp/src/CoreStationAgent`, Worker Service) — two independent implementations, per
spec FR-013.

**Primary Dependencies**:
- C++/Windows: `Wintrust.lib`, `Crypt32.lib` (already-available Windows SDK libs; unchanged from
  the Windows-only draft).
- C++/Linux: **new** — `OpenSSL::Crypto` (CMS verification), gated behind the bridge's build
  option; requires an SBOM entry (Constitution Principle II) before release (`research.md`
  Decision 4).
- C#/Windows: P/Invoke onto `WinVerifyTrust` (new native interop in `Platform/Windows/`,
  following the existing `NativeMethods.cs` pattern) — no new NuGet package.
- C#/Linux: `System.Security.Cryptography.Pkcs.SignedCms` + `UnixDomainSocketEndPoint`, both
  already part of the .NET 8 shared framework — no new NuGet package.

**Storage**: N/A — no persistence on either agent; trusted identity is a compiled-in constant,
per-connection identity is in-memory only (`data-model.md`).

**Testing**: GoogleTest (C++, existing `tests/`, `ENABLE_TESTING=ON`); xUnit (C#, existing
`csharp/tests/CoreStationAgent.Tests`).

**Target Platform**: Windows and Linux, for both agent implementations (was Windows-only/C++-only
before the clarify session).

**Project Type**: Two single native/managed background-service projects (existing `src/` C++
agent and `csharp/src/CoreStationAgent` C# agent) — no new top-level project.

**Performance Goals**: Authentication adds a bounded, one-time cost per new connection (process
identity + signature verification), not per message. Target: imperceptible against existing
per-connection setup cost, on all four combinations. No steady-state throughput change.

**Constraints**: Compile-time-only dev flag per build system (no runtime/config toggle, on either
agent); no new secret/credential storage; C++ raw-forward wire behavior for authenticated clients
must be unchanged; C# forwarding must go through the existing single-writer outbound channel
rather than a second writer touching `ISerialLink` directly (`research.md` Decision 5).

**Scale/Scope**: One agent process per node (running either the C++ or the C# agent, not both),
one bridge listener, one client connection at a time per existing single-instance
pipe/socket design — no concurrency model changes needed beyond what's already described.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Native-First, Minimal Footprint | ✅ PASS (one justified new dependency) | Windows and C# sides use OS/BCL-native APIs only. C++/Linux adds OpenSSL — justified in `research.md` Decision 4: no native syscall/libc equivalent exists, and shelling out to a CLI was rejected given this codebase's prior command-injection-shaped shell-out bug. |
| II. Dependency Transparency (SBOM Mandatory) | ✅ PASS (action required) | OpenSSL (C++/Linux) is a **new** third-party dependency and MUST get an SBOM entry before a release build ships it. No new dependency on the other three combinations. |
| III. Serial CSV Telemetry Contract | ✅ PASS / N/A | Untouched — this governs the inbound bridge, not the outbound CSV telemetry stream. |
| IV. Controlled C2A Command Execution | ✅ PASS / N/A | No C2A dispatch changes; the bridge remains a raw/line forward, not a command channel, on both agents. |
| V. IPC Boundary Discipline | ✅ PASS | Directly implements the principle's own forward-looking clause on all four combinations — explicit security descriptor/permissions PLUS the new signature-based control, superseding "ACL alone." |
| VI. Cross-Platform Parity via Platform Abstraction | ✅ PASS | This plan is what makes VI's parity concern moot for this feature — both platforms, both agents, get equivalent capability from the outset, going through each agent's existing `Platform`/`Platform.Windows`/`Platform.Linux` seam. |
| VII. Tray App Process Isolation | ✅ PASS / N/A | No tray app changes. |

No unjustified violations. One dependency addition is called out above and in Complexity
Tracking below, as the constitution requires.

## Project Structure

### Documentation (this feature)

```text
specs/001-secure-serial-ipc/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md         # Phase 1 output
├── quickstart.md         # Phase 1 output
├── contracts/
│   └── serial-bridge-ipc.md
└── tasks.md              # Phase 2 output (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
# --- C++ agent (src/) ---
src/
├── modules/
│   └── serialpipe/
│       ├── SerialBridgePipe.cpp        # MODIFIED (Windows): call identity check before read loop
│       ├── SerialBridgePipe.h          # MODIFIED (Windows)
│       ├── SerialBridgeSocket.cpp      # NEW (Linux): Unix domain socket listener, mirrors
│       │                               #   SerialBridgePipe's structure/lifecycle
│       ├── SerialBridgeSocket.h        # NEW (Linux)
│       ├── WindowsIpcClientAuth.h/.cpp # NEW: Authenticode identity resolution + Subject compare
│       └── LinuxIpcClientAuth.h/.cpp   # NEW: SO_PEERCRED + OpenSSL CMS verification + compare
├── platform/
│   ├── WindowsPlatform.cpp             # MODIFIED: wire WindowsIpcClientAuth into
│   │                                   #   forwardSerialBridgeMessage's admission path
│   └── LinuxPlatform.cpp/.h            # MODIFIED: override startSerialBridgePipe/
│                                       #   stopSerialBridgePipe/forwardSerialBridgeMessage
│                                       #   (currently only WindowsPlatform does), owning a
│                                       #   SerialBridgeSocket the same way WindowsPlatform
│                                       #   owns a SerialBridgePipe
└── core/Platform.h                     # Unchanged — forwardSerialBridgeMessage already virtual
                                        # with a default no-op; LinuxPlatform overriding it is
                                        # exactly what this seam is for

tests/
├── CMakeLists.txt                      # MODIFIED: add new test sources
├── test_ipc_client_auth.cpp            # NEW (Windows-side pure logic: Subject matching, dev-flag
│                                       #   branch, injected ConnectingClientIdentity values)
└── test_linux_ipc_client_auth.cpp      # NEW (Linux-side equivalent)

CMakeLists.txt                          # MODIFIED: extend BUILD_SERIAL_BRIDGE_PIPE to apply on
                                        #   UNIX AND NOT APPLE too (currently WIN32-gated only);
                                        #   add IPC_AUTH_DEV_DISABLE option (both platforms);
                                        #   find_package(OpenSSL) + link when
                                        #   BUILD_SERIAL_BRIDGE_PIPE AND UNIX

# --- C# agent (csharp/src/CoreStationAgent/) ---
csharp/src/CoreStationAgent/
├── Ipc/
│   ├── ISerialBridgeListener.cs         # NEW: platform-agnostic listener contract
│   ├── WindowsSerialBridgeListener.cs   # NEW: NamedPipeServerStream + WinVerifyTrust P/Invoke
│   ├── LinuxSerialBridgeListener.cs     # NEW: UnixDomainSocketEndPoint + SignedCms verify
│   └── ClientAuthenticator.cs           # NEW: shared Subject-matching logic (platform-agnostic
│                                        #   part of research.md Decision 3), takes a resolved
│                                        #   identity, returns authenticated/not
├── Workers/
│   └── SerialBridgeService.cs           # NEW: BackgroundService hosting the platform listener,
│                                        #   forwards authenticated messages via IBmcChannel
│                                        #   (research.md Decision 5) — not a new writer
├── Platform/Windows/NativeMethods.cs    # MODIFIED: add WinVerifyTrust + named-pipe client PID
│                                        #   P/Invoke declarations, alongside existing ones
├── Configuration/AgentOptions.cs        # MODIFIED: add EnableSerialBridge (default true) +
│                                        #   socket/pipe path overrides, mirroring existing option
│                                        #   patterns (e.g. PortName)
└── CoreStationAgent.csproj              # MODIFIED: DefineConstants for IPC_AUTH_DEV_DISABLE in a
                                        #   Debug-only PropertyGroup — no new PackageReference

csharp/tests/CoreStationAgent.Tests/
└── (new test files mirroring ClientAuthenticator's pure-logic Subject matching + dev-flag branch,
    same spirit as the C++ unit tests — no live pipe/socket or real signature verification in
    unit tests, per existing test conventions)
```

**Structure Decision**: Extend both existing single-project layouts in place — a new `serialpipe`
sibling module pair in the C++ agent (Windows pipe / Linux socket, each with its own auth helper,
wired through the `Platform` interface both classes already implement) and a new `Ipc` +
`Workers/SerialBridgeService` pair in the C# agent (which has no bridge module to extend, so this
is net-new there, built cross-platform from the start per the clarify-session decision). No new
top-level project/repo directory in either codebase.

## Complexity Tracking

| Addition | Why Needed | Simpler Alternative Rejected Because |
|----------|------------|----------------------------------------|
| OpenSSL dependency (C++, Linux build only) | CMS/PKCS#7 signature verification for the Linux authentication path — no native syscall/libc equivalent exists (`research.md` Decision 4) | Shelling out to `openssl`/`gpg` CLI and parsing output — this codebase already fixed one command-injection-shaped shell-out bug; re-introducing a parse-fragile subprocess call for a *security* check was rejected as the wrong trade for a marginal footprint saving |
| Building in both C++ and C# agents (4 combinations instead of 1) | Explicit user direction in the 2026-08-15 clarify session — both agents must reach parity, since the company applications that will connect are themselves cross-platform | Building once (either agent only) — rejected by the user; would leave two of the four platform/agent combinations with no channel at all, or a weaker one |

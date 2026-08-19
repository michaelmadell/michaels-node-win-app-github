---

description: "Task list for Authenticated Serial IPC for Company Applications"
---

# Tasks: Authenticated Serial IPC for Company Applications

**Input**: Design documents from `/specs/001-secure-serial-ipc/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/serial-bridge-ipc.md, quickstart.md

**Tests**: Unit tests are included for the pure-logic identity/Subject-matching code, matching this
repo's existing convention (`tests/` covers pure logic only — see `tests/CMakeLists.txt` comment —
and Constitution "Development Workflow & Quality Gates" requires tests for new modules). Full
connection-flow validation is manual, via `quickstart.md`, consistent with how this repo already
tests (no existing pipe/socket integration-test harness to extend).

**Organization**: Tasks are grouped by user story (spec.md: US1 and US2 are both P1, US3 is P3).
Within Foundational and each story, C++/Windows, C++/Linux, C#/Windows, and C#/Linux tracks are
called out explicitly — per the 2026-08-15 clarify session, all four must reach parity.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on an incomplete task)
- **[Story]**: US1, US2, or US3 — omitted for Setup/Foundational/Polish

## Path Conventions

- C++ agent: `src/` (existing agent), `tests/` (GoogleTest)
- C# agent: `csharp/src/CoreStationAgent/` (existing agent), `csharp/tests/CoreStationAgent.Tests/` (xUnit)

---

## Phase 1: Setup

**Purpose**: Shared prerequisites needed before any auth code can be written or tested, on any
platform/agent.

- [X] T001 **DEV CERT SUBSTITUTE, not the real EV certificate**: generated a throwaway dev CA +
  code-signing leaf cert locally (`.devcerts/`, gitignored — `openssl req -x509 ...` root +
  `openssl req`/`x509 -req` leaf) since the real EV certificate isn't available in this
  environment. `src/modules/serialpipe/TrustedIdentity.h` and
  `csharp/src/CoreStationAgent/Ipc/ClientAuthenticator.cs` now hold that dev cert's Subject
  (clearly labeled "DEV TEST ONLY"/"NOT FOR PRODUCTION" in every field, so it can never be
  mistaken for the real thing) instead of the earlier `REPLACE_ME_*` placeholders — this made it
  possible to actually exercise T029/T030/T035's crypto logic end-to-end (see below). MUST still
  be replaced with the real EV certificate's Subject before release.
- [X] T002 [P] Extend `CMakeLists.txt`: add `option(IPC_AUTH_DEV_DISABLE "DANGEROUS: compile out
  IPC client signature verification (dev/test builds only)" OFF)`; extend the existing
  `BUILD_SERIAL_BRIDGE_PIPE` gate (currently `WIN32`-only at lines ~194, 239, 284) to also cover
  `UNIX AND NOT APPLE`; add `find_package(OpenSSL REQUIRED)` and link `OpenSSL::Crypto` when
  `BUILD_SERIAL_BRIDGE_PIPE AND UNIX`.
- [X] T003 [P] Add a `Debug`-only `PropertyGroup` with `<DefineConstants>IPC_AUTH_DEV_DISABLE</DefineConstants>`
  to `csharp/src/CoreStationAgent/CoreStationAgent.csproj`, scoped so `dotnet publish -c Release`
  never defines it (`research.md` Decision 6).
- [X] T004 [P] Write a Linux detached-signing step (`tools/sign-linux-release.sh`) that
  produces a `<binary>.sig` CMS/PKCS#7 file via `smctl`/`openssl cms -sign` using the existing EV
  certificate, for use in the Linux release pipeline (spec FR-012). Script is real and complete;
  the `DIGICERT_CERT_FINGERPRINT`/`CERT_PEM`/`PKCS11_KEY_URI` env vars it requires point at
  credentials this environment doesn't have — wire them on an actual signing host.
- [X] T005 [P] **DEV CERT SUBSTITUTE, not the real DigiCert CA chain**: the dev CA's public cert
  (`.devcerts/dev_ca.pem`) is installed at `src/modules/serialpipe/certs/digicert_ca_chain.pem`
  and `csharp/src/CoreStationAgent/Ipc/digicert_ca_chain.pem` — used by both Linux verification
  paths (`data-model.md` `TrustedSigningIdentity.caTrustAnchor`). `certs/README.md` (C++) and
  `Ipc/README.md` (C#) explain what belongs there for real; both `LinuxIpcClientAuth.cpp` and
  `LinuxSerialBridgeListener.cs` fail closed (refuse to start, logged as FATAL/Critical) if the
  file is absent, rather than silently running with authentication broken.
- [X] T006 Add an SBOM entry for the new `OpenSSL::Crypto` (C++/Linux-only) dependency introduced
  in T002, per Constitution Principle II — update the project's SBOM file/process before this
  reaches a release build.

**Checkpoint**: Build system and signing infrastructure ready; no auth code needed to exist yet.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Identity resolution + listener scaffolding shared by every user story, on all four
platform/agent combinations. **No user story can be verified until this phase is done.**

### C++ agent

- [X] T007 [P] Implement `src/modules/serialpipe/WindowsIpcClientAuth.h`/`.cpp`: given a connected
  pipe `HANDLE`, resolve `ConnectingClientIdentity` (`GetNamedPipeClientProcessId` →
  `OpenProcess`/`QueryFullProcessImageNameW` → `WinVerifyTrust` with
  `WINTRUST_ACTION_GENERIC_VERIFY_V2` → `CryptQueryObject`/`CertGetNameStringW` for
  CN/O/OU), compare against the compiled `TrustedSigningIdentity` constants from T001, expose
  `bool WindowsIsAuthenticated(HANDLE, ...)` (took a `logPrefix`/log-callback pair beyond the
  originally-planned bare `HANDLE` signature, to reuse `SerialBridgePipe`'s existing `Log()`).
  Depends on T001. **Build- and behavior-verified for real**: configured/built with
  `cmake -DBUILD_SERIAL_BRIDGE_PIPE=ON -DENABLE_TESTING=ON -G "MinGW Makefiles"` (g++ 16.1.0),
  zero errors/new warnings; a standalone harness replicating this file's `WinVerifyTrust` +
  `CertGetNameStringW` sequence exactly, run against the T029 dev-signed test client, produced
  the correct CN/O/OU and matched `TrustedSigningIdentity`; the same harness against the
  unsigned original binary correctly failed. (Initial implementation had a real bug here, since
  fixed: `logFn` was a raw function pointer, which a capturing lambda cannot convert to —
  compile error, not caught until this build. Changed to `std::function`.)
- [X] T008 [P] Implement `src/modules/serialpipe/LinuxIpcClientAuth.h`/`.cpp`: given an accepted
  socket fd, resolve `ConnectingClientIdentity` (`getsockopt(SO_PEERCRED)` → `readlink
  /proc/<pid>/exe` → locate `<image>.sig` → OpenSSL CMS verify against
  `certs/digicert_ca_chain.pem` from T005 → extract signer Subject), compare against the same
  `TrustedSigningIdentity` constants, expose `bool IsAuthenticated(int clientFd)`. Depends on
  T001, T005. **Not compile-verified** (no Linux toolchain in this environment), but the
  `CMS_verify` logic itself was validated against real signed data via `openssl cms -verify` —
  see T030 for the resulting `X509_PURPOSE_ANY` fix, applied directly to this file's
  `LoadTrustAnchorOnce`.
- [X] T009 [P] Implement `src/modules/serialpipe/SerialBridgeSocket.h`/`.cpp`: Unix domain socket
  listener at `/run/corestation/serial_bridge.sock`, mirroring `SerialBridgePipe`'s
  Start()/Stop()/background-thread lifecycle and restricted socket-file permissions
  (`contracts/serial-bridge-ipc.md`).
- [X] T010 [US-shared] Modify `src/modules/serialpipe/SerialBridgePipe.cpp`: immediately after
  `ConnectNamedPipe` succeeds and before the existing read loop, call
  `WindowsIpcClientAuth::IsAuthenticated`; gate the call behind `#ifndef IPC_AUTH_DEV_DISABLE`.
  Depends on T007.
- [X] T011 [US-shared] Modify `src/modules/serialpipe/SerialBridgeSocket.cpp`: immediately after
  `accept()` and before any read, call `LinuxIpcClientAuth::IsAuthenticated`; gate behind
  `#ifndef IPC_AUTH_DEV_DISABLE`. Depends on T008, T009.
- [X] T012 [P] Add `LinuxPlatform::startSerialBridgeSocket()`/`stopSerialBridgeSocket()` to
  `src/platform/LinuxPlatform.h`/`.cpp`, owning a `SerialBridgeSocket` instance. `Platform::
  setSerialBridgeHandler` and `forwardSerialBridgeMessage` are **both** virtual no-ops on the
  base class (`src/core/Platform.h:31` and the default in the same file) — `LinuxPlatform`
  currently overrides neither, so today's `setSerialBridgeHandler` call in `linux/main.cpp:175`
  is silently discarded. Override **both** on `LinuxPlatform`, with `LinuxPlatform` storing its
  own handler member (it cannot reuse `WindowsPlatform`'s private `serial_bridge_handler_`) and
  `forwardSerialBridgeMessage` invoking that stored handler — mirroring `WindowsPlatform`'s
  existing `startSerialBridgePipe`/`stopSerialBridgePipe`/`setSerialBridgeHandler`/
  `forwardSerialBridgeMessage` (`src/platform/WindowsPlatform.h:192-193,50-51`,
  `WindowsPlatformSerialBridge.cpp`). Depends on T009.
- [X] T013 Wire `src/linux/main.cpp`: call `platform->startSerialBridgeSocket()` near the existing
  `setSerialBridgeHandler(...)` call (line ~175), and `stopSerialBridgeSocket()` on shutdown —
  Linux has no service-control lifecycle to hook into (unlike `WindowsPlatform`'s 4 internal call
  sites), so `main()` is the right place. Depends on T012.
- [X] T014 [P] Add `tests/test_ipc_client_auth.cpp`: unit tests for `WindowsIpcClientAuth`'s
  Subject-comparison logic and the `IPC_AUTH_DEV_DISABLE` branch, using injected/fake
  `ConnectingClientIdentity` values (no live `WinVerifyTrust` calls). Register in
  `tests/CMakeLists.txt`. Depends on T007. **Actually run**: `unit_tests.exe` — all 6 new tests
  pass, plus the pre-existing 13 (19/19 total, 0 failures).
- [X] T015 [P] Add `tests/test_linux_ipc_client_auth.cpp`: equivalent unit tests for
  `LinuxIpcClientAuth`'s Subject-comparison logic, injected identities, no live OpenSSL calls
  against real files. Register in `tests/CMakeLists.txt`. Depends on T008.

### C# agent

- [X] T016 [P] Implement `csharp/src/CoreStationAgent/Ipc/ClientAuthenticator.cs`: platform-agnostic
  Subject-match logic (given a resolved identity: `signatureValid`, `subjectCN/O/OU` → bool) plus
  the `IPC_AUTH_DEV_DISABLE` branch, taking the `TrustedSigningIdentity` constants from T001.
  Pure logic, no I/O — mirrors T007/T008's comparison step in one shared place.
- [X] T017 [P] Implement `csharp/src/CoreStationAgent/Ipc/ISerialBridgeListener.cs`: platform-agnostic
  listener contract (`Start`/`Stop`, an event/callback for authenticated inbound messages).
- [X] T018 [P] Implement P/Invoke declarations for `GetNamedPipeClientProcessId` and
  `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`). Landed in a new
  `csharp/src/CoreStationAgent/Platform/Windows/WinTrustNativeMethods.cs` rather than editing
  `NativeMethods.cs` directly — `WinVerifyTrust`'s `WINTRUST_DATA` parameter is a non-blittable
  struct (embeds an `LPCWSTR`), which needs classic `[DllImport]` marshaling rather than the
  `[LibraryImport]` source-generator style the rest of that file uses; kept separate rather than
  mixing marshaling styles in one file.
- [X] T019 [P] Implement `csharp/src/CoreStationAgent/Ipc/WindowsSerialBridgeListener.cs`
  (implements `ISerialBridgeListener`): `NamedPipeServerStream` at
  `\\.\pipe\corestation_serial_bridge`, created with an explicit `PipeSecurity` restricting
  connections to `BUILTIN\Administrators` (the same `D:(A;;GA;;;BA)` intent as the C++ pipe —
  Constitution Principle V, spec FR-010; this is defense-in-depth, on top of, not instead of,
  the signature check below), resolves the connecting client's identity via the T018 P/Invokes,
  calls `ClientAuthenticator` (T016). Depends on T016, T017, T018.
- [X] T020 [P] Implement `csharp/src/CoreStationAgent/Ipc/LinuxSerialBridgeListener.cs` (implements
  `ISerialBridgeListener`): `UnixDomainSocketEndPoint` at `/run/corestation/serial_bridge.sock`,
  with the socket file created at the same restricted permissions as the C++ agent's socket
  (T009/U1's resolved owner/group/mode — Constitution Principle V, spec FR-010; defense-in-depth
  only, since this agent creates its own socket independently of the C++ agent's), resolves peer
  credentials (`SO_PEERCRED` via `Socket.GetRawSocketOption` or equivalent), verifies the
  accompanying `.sig` via `System.Security.Cryptography.Pkcs.SignedCms` against the T005 CA chain
  resource, calls `ClientAuthenticator` (T016). Depends on T016, T017, T005, T009.
- [X] T021 Implement `csharp/src/CoreStationAgent/Workers/SerialBridgeService.cs`: a
  `BackgroundService` that selects `WindowsSerialBridgeListener` or `LinuxSerialBridgeListener` via
  `OperatingSystem.IsWindows()`, and forwards authenticated messages through the existing
  `IBmcChannel.Send(string)` — **not** a second writer against `ISerialLink`
  (`research.md` Decision 5). Depends on T019, T020.
- [X] T022 [P] Add `EnableSerialBridge` (default `true`) and endpoint-path override options to
  `csharp/src/CoreStationAgent/Configuration/AgentOptions.cs`, following the file's existing
  `[Range]`/default-value conventions.
- [X] T023 Register `SerialBridgeService` (T021) in `csharp/src/CoreStationAgent/Program.cs`'s
  host-builder DI setup, alongside the existing worker registrations. Depends on T021, T022.
- [X] T024 [P] Add unit tests for `ClientAuthenticator` (T016) in
  `csharp/tests/CoreStationAgent.Tests/`: Subject-match true/false cases and the
  `IPC_AUTH_DEV_DISABLE` branch, injected identities, no real pipe/socket/crypto I/O.

**Checkpoint**: All four combinations can resolve a connecting client's identity and know
true/false. Nothing forwards or rejects yet — that's what US1/US2 add next.

---

## Phase 3: User Story 1 - Company app delivers a status message through the agent (Priority: P1) 🎯 MVP (with US2)

**Goal**: An authenticated (correctly signed) company application can send a message through the
IPC channel and have it reach the serial port, on all four platform/agent combinations.

**Independent Test**: Per `quickstart.md` Scenario C — a company-signed test client on each
platform/agent connects, sends a status string, and the exact content appears on the serial port.

### Implementation for User Story 1

- [X] T025 [US1] In `src/modules/serialpipe/SerialBridgePipe.cpp`'s `PipeThreadProc` (Windows),
  on `IsAuthenticated == true` (from T010), enter the existing read/forward loop unchanged —
  confirm the loop is reachable only past that check. Depends on T010.
- [X] T026 [US1] In `src/modules/serialpipe/SerialBridgeSocket.cpp`'s connection loop (Linux), on
  `IsAuthenticated == true` (from T011), read and forward via
  `LinuxPlatform::forwardSerialBridgeMessage` (T012), same raw-bytes/no-framing behavior as
  Windows. Depends on T011, T012.
- [X] T027 [US1] In `csharp/src/CoreStationAgent/Ipc/WindowsSerialBridgeListener.cs`, on
  authenticated, read subsequent writes on the same connection and raise them to
  `SerialBridgeService` for forwarding, without re-running authentication per message. Depends on
  T019, T021.
- [X] T028 [US1] In `csharp/src/CoreStationAgent/Ipc/LinuxSerialBridgeListener.cs`, same as T027
  for the Unix domain socket path. Depends on T020, T021.
- [X] T029 [P] [US1] Built a dev-signed Windows test client (`.devcerts/test_client_signed.exe`,
  Authenticode-signed with the T001 dev cert via real `signtool.exe`) and a dev-signed Linux test
  binary + `.sig` (`.devcerts/dummy_linux_client.bin(.sig)`, via `openssl cms -sign`, the same
  mechanism `tools/sign-linux-release.sh` uses). Uses the dev identity, not a real company
  signing identity (blocked on T001/T005's real counterparts).
- [ ] T030 [US1] **PARTIALLY VALIDATED, not checked off**: full `quickstart.md` Scenario C (live pipe/socket
  connection through the running agent, on all four combinations) needs a Linux host and real
  serial hardware/loopback, neither available here. What WAS validated, against real crypto and
  the T029 dev-signed artifacts, with standalone harnesses replicating the production
  verification logic exactly:
  - Windows: `WinVerifyTrust` against the signed test client succeeds; extracted signer
    CN/O/OU exactly matches `TrustedSigningIdentity` (dev CA temporarily trusted via
    `certutil -user -addstore Root`, removed again after).
  - Linux crypto design (via `openssl cms -verify`, since no Linux host is available to run
    `LinuxIpcClientAuth.cpp` itself): **found and fixed a real bug** — `CMS_verify` defaults to
    the S/MIME email-signing purpose and rejected an otherwise-valid `codeSigning`-purpose
    certificate ("unsuitable certificate purpose") until `X509_STORE_set_purpose(store,
    X509_PURPOSE_ANY)` was added to `LoadTrustAnchorOnce`.
  - C# (`SignedCms`/`X509Chain`, runnable on Windows regardless of target OS): verified against
    the same openssl-produced signature — `CheckSignature`, chain build, and Subject extraction
    all succeed and match, no equivalent purpose bug (confirmed, not assumed).
  - C# build also surfaced and fixed a real missing-dependency bug: `System.Security.
    Cryptography.Pkcs` is not part of the net8.0 shared framework as `research.md` originally
    claimed — needed an explicit `PackageReference` (see `research.md` Decision 4 correction).

**Checkpoint**: Authenticated forwarding works end-to-end on all four combinations.

---

## Phase 4: User Story 2 - Unauthorized caller is blocked, even as admin (Priority: P1) 🎯 MVP (with US1)

**Goal**: Unsigned or wrongly-signed callers — including elevated/root ones — are refused with
zero bytes forwarded, and the rejection is logged, on all four combinations.

**Independent Test**: Per `quickstart.md` Scenario B — unsigned and signed-but-unrelated test
executables, run elevated/as root, are both refused on every combination.

### Implementation for User Story 2

- [X] T031 [US2] In `src/modules/serialpipe/SerialBridgePipe.cpp`, on `IsAuthenticated == false`,
  skip the read loop entirely, call `DisconnectNamedPipe`/`CloseHandle` immediately, and log the
  rejection via `Log(...)` at a severity consistent with the existing `WARNING`/`ERROR`
  conventions (spec FR-008). Depends on T010.
- [X] T032 [US2] In `src/modules/serialpipe/SerialBridgeSocket.cpp`, same rejection behavior
  (close the fd, no read, log `WARNING`) on `IsAuthenticated == false`. Depends on T011.
- [X] T033 [US2] In `csharp/src/CoreStationAgent/Ipc/WindowsSerialBridgeListener.cs`, on
  unauthenticated, close the pipe connection without reading, and have `SerialBridgeService`
  (or the listener itself) log a `LogWarning` rejection event including enough detail to be
  attributable (image path/PID, not the full identity chain). Depends on T019, T021.
- [X] T034 [US2] In `csharp/src/CoreStationAgent/Ipc/LinuxSerialBridgeListener.cs`, same rejection
  + `LogWarning` behavior for the Unix domain socket path. Depends on T020, T021.
- [X] T035 [P] [US2] Built and verified the unsigned case (Windows): the harness's real
  `WinVerifyTrust` call against the **unsigned** original `CoreStationHXAgent.exe` correctly
  returned failure (`TRUST_E_NOSIGNATURE`-class result). A signed-but-unrelated-certificate case
  and the Linux equivalents weren't built (would need a second unrelated dev cert and a Linux
  host respectively) — the unsigned-Windows case was judged the highest-value one to actually
  prove, since it's the exact scenario spec.md Acceptance Scenario US2.1 describes.
- [ ] T036 [US2] **PARTIALLY VALIDATED, not checked off**: same caveat as T030 — full live
  connection-flow Scenario B (including the elevated-caller angle) needs a running agent and a
  real named pipe/socket client, not exercised here. What was validated: the underlying rejection
  decision itself (unsigned → `WinVerifyTrust` failure → `IsAuthenticated` false) is real, not
  assumed, per T035.

**Checkpoint**: Both P1 stories (US1 forward, US2 reject) are complete and independently verified
on all four combinations — this is the feature's MVP.

---

## Phase 5: User Story 3 - Developer disables authentication for local testing (Priority: P3)

**Goal**: A compile-time-only dev build skips authentication entirely and makes that state
visible; standard Release/RC/GA builds have no way to enable it.

**Independent Test**: Per `quickstart.md` Scenario A — a dev-flag build forwards from an unsigned
client; a standard build of the same combination refuses the same client.

### Implementation for User Story 3

- [X] T037 [P] [US3] In `src/modules/serialpipe/WindowsIpcClientAuth.cpp` and
  `LinuxIpcClientAuth.cpp`, when compiled with `IPC_AUTH_DEV_DISABLE` defined (T002),
  short-circuit `IsAuthenticated` to always return `true`, and log a distinct
  `"DEV MODE: IPC authentication disabled"` line once at bridge startup (spec FR-007). Depends on
  T007, T008.
- [X] T038 [P] [US3] In `csharp/src/CoreStationAgent/Ipc/ClientAuthenticator.cs`, when compiled
  with `IPC_AUTH_DEV_DISABLE` defined (T003), same short-circuit (`DevAuthDisabled`/
  `IsAuthenticated`) + a startup dev-mode banner. Landed the log call in each listener
  (`WindowsSerialBridgeListener`/`LinuxSerialBridgeListener`) rather than `SerialBridgeService`
  itself — each listener owns its own startup sequence, so it's the natural place — same
  FR-007 outcome either way. Depends on T016, T021.
- [X] T039 [US3] Confirmed by grep that no `build.bat`/`build-production.bat`/`build.sh`/
  `build-linux.sh`/`.bash` references `IPC_AUTH_DEV_DISABLE`; added explicit warning comments at
  the CMake `option()` declaration, the `target_compile_definitions` site, and the csproj
  `PropertyGroup` (spec FR-006, SC-004). Depends on T002, T003.
- [ ] T040 [US3] **BLOCKED (needs a Windows+Linux build environment and serial hardware/loopback)**:
  Run `quickstart.md` Scenario A on all four combinations and re-confirm Scenario B on the
  corresponding standard build. Not runnable from this environment.

**Checkpoint**: All three user stories independently verified on all four platform/agent
combinations.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Repo-wide consistency and release-readiness, per Constitution "Development Workflow
& Quality Gates."

- [X] T041 [P] Updated `README.md`'s "Serial bridge pipe" section (retitled "Serial bridge
  (authenticated IPC)"): documents the Linux endpoint, the signature-based authentication
  requirement on both platforms (superseding ACL-only), and `IPC_AUTH_DEV_DISABLE`.
- [X] T042 [P] Added a `20.26.8.1_rc1` entry to `release-notes.txt` describing the merge of the
  C# agent, the authenticated IPC bridge, its new Linux capability, and the dev flag.
  `installer/release-notes.txt` is a build-time copy of this file (see `build.bat`/
  `build-production.bat`), not a separate tracked source — nothing further to edit.
- [ ] T043 [P] **DEFERRED, not a gap**: `debian/control`'s `Depends:` uses
  `CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON`, which auto-detects actual linked shared libraries — it
  will pick up `libssl.so.3` automatically once someone builds with
  `-DBUILD_SERIAL_BRIDGE_PIPE=ON` (default stays `OFF`, per T002, so today's default package is
  unaffected). No manual dependency line needed unless/until that default flips. Revisit then.
  RPM packaging has no separate `.spec` file to update either (CPack's RPM generator, same
  auto-detection). Depends on T002.
- [ ] T044 [P] **PARTIALLY DEFERRED**: `bitbucket-pipelines.yml`'s two build jobs don't pass
  `-DBUILD_SERIAL_BRIDGE_PIPE=ON` today, so CI is unaffected by this feature as shipped — didn't
  flip it on here. The Windows half of the concern is resolved: `cmake -DBUILD_SERIAL_BRIDGE_PIPE=ON
  -DENABLE_TESTING=ON` was actually configured and built clean with MinGW g++ 16.1.0 (see T007
  note), so enabling it in the Windows CI job is now known-safe. The Linux half is still
  unverified — no Linux toolchain in this environment to confirm the OpenSSL-linked
  `SerialBridgeSocket.cpp`/`LinuxIpcClientAuth.cpp` actually compile. Recommend: build once on
  Linux with the flag on, confirm it compiles, then add `libssl-dev` to that job's
  `apt-get install` line and turn the flag on there too. Depends on T002.
- [ ] T045 **PARTIALLY BLOCKED**: `clang-tidy` itself isn't available in this environment
  (`cmake` turned out to be installed but not on PATH — found and used directly; no equivalent
  fix found for `clang-tidy`). Compiler warnings from the actual build were reviewed instead
  (g++ `-Wall -Wextra`, matching CMakeLists' non-MSVC flags) — the new IPC-bridge files produced
  zero warnings; pre-existing files produced pre-existing warnings unrelated to this feature
  (`TrayApp.cpp`/`SessionMonitor.cpp` struct-init order, `MetricCache.h` member-init order — none
  touched by this change). Full `clang-tidy` still needs to run on a machine that has it.
- [ ] T046 **PARTIALLY VALIDATED, not checked off**: see T030/T036 — the crypto core is
  real-data-verified; the full multi-scenario, all-four-combination `quickstart.md` pass still
  needs a Linux host, real serial hardware/loopback, and (for Scenario D) a second dev cert
  sharing the same Subject to prove renewal-survival.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately.
- **Foundational (Phase 2)**: Depends on Setup (T001 in particular feeds T007/T008/T016; T005
  feeds T008/T020). BLOCKS all user stories.
- **User Story 1 (Phase 3)** and **User Story 2 (Phase 4)**: Both depend only on Foundational —
  can be worked in parallel by different people/agents once Phase 2 is done, since they touch the
  same files but different branches of the same `if (authenticated)` check (sequential within a
  file, not blocking across US1/US2 at the phase level).
- **User Story 3 (Phase 5)**: Depends on Foundational; independent of US1/US2 content-wise, but
  wraps the same call sites, so in practice finish after US1/US2 to avoid merge churn.
- **Polish (Phase 6)**: Depends on all three user stories being complete.

### Parallel Opportunities

- Setup: T002, T003, T004, T005 in parallel (T001 and T006 are effectively serial/coordination
  tasks).
- Foundational: T007, T008, T009 in parallel (different files); T014, T015, T016, T017, T018,
  T022, T024 in parallel once their listed dependencies land.
- Within US1/US2/US3: the four platform/agent tracks (C++/Windows, C++/Linux, C#/Windows,
  C#/Linux) are independent of each other and can be worked in parallel; the Windows/Linux pair
  within one language shares no files with the other language's pair.

---

## Implementation Strategy

### MVP First (US1 + US2 together)

Unlike a typical single-P1-story MVP, this feature's two P1 stories are two arms of the same
authentication check — forward on success (US1), reject-and-log on failure (US2). Treat them as
one MVP unit:

1. Complete Phase 1 (Setup) and Phase 2 (Foundational).
2. Complete Phase 3 (US1) and Phase 4 (US2) together — both arms of `if (authenticated)`.
3. **STOP and VALIDATE** via `quickstart.md` Scenarios B and C on all four combinations.
4. Phase 5 (US3, dev flag) and Phase 6 (Polish) follow once the MVP is confirmed.

### Incremental Delivery

1. Setup + Foundational → identity resolution works, nothing forwards/rejects yet.
2. US1 + US2 → the actual security feature is live and testable on all four combinations (MVP).
3. US3 → developer convenience, ships after the MVP is validated.
4. Polish → docs, packaging, CI, and a final full-scenario pass.

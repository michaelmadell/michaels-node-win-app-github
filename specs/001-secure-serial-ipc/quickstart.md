# Quickstart: Validating Authenticated Serial IPC (all four combinations)

## Prerequisites

- A currently-signed release binary (or access to the signing certificate) to extract the
  expected Subject CN/O/OU values (`research.md` Decision 1) — needed once, not per test run.
- The DigiCert EV certificate's root/intermediate CA chain, exported as PEM, to embed as the
  Linux trust anchor (`data-model.md` `TrustedSigningIdentity.caTrustAnchor`).
- A working detached-signing script/step producing a `.sig` file for Linux release binaries
  (spec FR-012) — needed for Scenarios C/D on Linux.
- Serial loopback or a monitored port to observe forwarded bytes (per README "Serial output").

Run each scenario below once per platform/agent combination you're validating:
**C++/Windows**, **C++/Linux**, **C#/Windows**, **C#/Linux**.

## Scenario A — dev build, auth disabled (fast local loop)

- **C++**: `cmake -B build -DBUILD_SERIAL_BRIDGE_PIPE=ON -DIPC_AUTH_DEV_DISABLE=ON` (works
  identically on Windows and Linux — same two flags).
- **C#**: build with the `IPC_AUTH_DEV_DISABLE` MSBuild constant defined (Debug configuration
  only — see `research.md` Decision 6), e.g. `dotnet build -c Debug`.
- Run the agent. Confirm the startup log shows the dev-mode notice (spec FR-007).
- Send a message with an unsigned test client (the existing `tools/serial_bridge_client.py` works
  for the Windows pipe; an equivalent trivial client against the Unix socket path for Linux).
- **Expected**: message is forwarded to the serial port. Validates User Story 3.

## Scenario B — standard build, unsigned caller rejected

- Build without the dev flag (default `OFF`/not defined) for the combination under test.
- Run the agent (service/systemd or interactively).
- From an elevated/root prompt, run the same unsigned test client against that platform's
  endpoint.
- **Expected**: connection is closed before any bytes are forwarded — nothing new on the serial
  port — even though the caller is elevated/root. Validates User Story 2.
- Check the log: a rejection event at `WARNING` severity or higher (spec FR-008).

> Note: an unsigned interpreter (`python.exe`, or a plain unsigned Linux binary) is *expected* to
> be rejected here — that's the feature working, not a test-tooling problem (`research.md`
> Decision 7).

## Scenario C — standard build, signed company client accepted

- Same build as Scenario B.
- Windows: use a small company-signed test executable (built/signed via the normal release
  process).
- Linux: use a small test binary plus its detached `.sig` file, produced by the release
  signing script (spec FR-012).
- **Expected**: message forwarded, no rejection logged for that connection. Validates User Story 1
  and SC-002 (delivery within ~1s), on whichever combination is under test.

## Scenario D — certificate renewal doesn't break auth

- Using two client builds signed by certificate instances that share the same Subject
  (before/after a renewal, or a test cert with matching Subject fields), repeat Scenario C for
  each, on both Windows (Authenticode) and Linux (detached CMS).
- **Expected**: both accepted with zero agent configuration change on either platform. Validates
  SC-003.

## Cross-combination check

- Confirm a single company client build for a given OS is accepted by **both** agent
  implementations on that OS (e.g., the same signed Windows test client works against a
  C++-agent-hosted pipe and a C#-agent-hosted pipe) — this is what "one shared endpoint identity
  per platform" (see `contracts/serial-bridge-ipc.md`) is meant to guarantee.

## What "done" looks like

- Scenarios A–D each produce their expected outcome, on a clean build, for all four
  platform/agent combinations actually being shipped in this change.
- Rejections are logged with attributable detail on every combination (spec FR-008/SC-005).
- Inspecting Release/RC/GA build configuration (CMake for C++, `dotnet publish -c Release` for
  C#) shows no path that enables `IPC_AUTH_DEV_DISABLE` (spec FR-006/SC-004).

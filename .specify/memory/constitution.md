<!--
Sync Impact Report
- Version change: (none, template unfilled) → 1.0.0
- Bump rationale: Initial ratification. No prior governing version existed — the file on disk
  was still the raw, placeholder-only template. Filling it with concrete, testable principles is
  a MAJOR change (0 → 1).
- Modified principles: n/a (first adoption; no renames)
- Added sections:
  - Core Principles: I. Native-First, Minimal Footprint; II. Dependency Transparency (SBOM
    Mandatory); III. Serial CSV Telemetry Contract; IV. Controlled C2A Command Execution;
    V. IPC Boundary Discipline; VI. Cross-Platform Parity via Platform Abstraction;
    VII. Tray App Process Isolation
  - Technology & Platform Constraints
  - Development Workflow & Quality Gates
  - Governance
- Removed sections: none
- Deferred / TODO placeholders: none — all bracket tokens resolved from user input and repo
  context (README.md, CLAUDE.md, docs/agents/*, src/ and csharp/ trees, git log).
- Templates requiring follow-up: none checked in this run (scope limited to constitution per
  command guard). Recommend a manual pass of `.specify/templates/plan-template.md` and
  `.specify/templates/spec-template.md` next time either is touched, to confirm their
  Constitution Check sections still reference these seven principles by name.
-->

# CoreStation HX Agent Constitution
<!-- Cross-platform service: system-info collection → CSV over serial, C2A command execution,
     tray UI, and company-app IPC. Covers both the C++ implementation (src/) and the parallel
     C# implementation (csharp/). -->

## Core Principles

### I. Native-First, Minimal Footprint
The agent MUST do as much of its work as possible through OS-native calls (Win32/WTS/IP Helper
on Windows; D-Bus/NetworkManager/procfs on Linux) rather than through general-purpose frameworks
or bundled runtimes. It runs as a background service on every managed node, so CPU, memory, and
disk footprint MUST stay small and MUST NOT grow silently release over release. External
dependencies ARE allowed when a native call cannot reasonably cover the need, but each one MUST
be justified in the PR/plan that introduces it — "it's easier" is not sufficient justification;
"the native API doesn't expose X" is.
**Rationale**: the agent runs unattended on every managed node, often on constrained hardware; a
heavy or bloated service defeats the product's purpose and competes with the workloads it's meant
to monitor.

### II. Dependency Transparency (SBOM Mandatory)
Every external dependency — C++ (vcpkg/CMake fetched), C# (NuGet), or build/test tooling — MUST be
recorded in a Software Bill of Materials (SPDX or CycloneDX format, either is acceptable). The
SBOM MUST be regenerated whenever a dependency is added, removed, or bumped, and MUST be reviewed
before a release build is signed and shipped. A dependency without a corresponding SBOM entry MUST
NOT reach a release build.
**Rationale**: the agent runs with elevated privileges (service/Administrators) on infrastructure
nodes; unaccounted-for third-party code is an unacceptable supply-chain and audit risk.

### III. Serial CSV Telemetry Contract
System information (session state, logged-in username, hostname, NIC info, app/OS version, etc.)
MUST be emitted to the serial port as CSV lines, one fact per line, matching the existing wire
format documented in `README.md` ("Serial output" section). Changes to the CSV schema MUST be
additive (new trailing fields/new line types) wherever possible; breaking an existing field's
position or meaning MUST be called out explicitly and coordinated with the Management Controller
(MC) side, since it is a hard external contract, not an internal implementation detail.
**Rationale**: the MC on the other end of the serial link parses this stream; an undocumented or
silently-changed format breaks a physical device that isn't in this repo and can't self-update.

### IV. Controlled C2A Command Execution
Commands arriving from the MC over serial (C2A) MUST be dispatched through a single, explicit
command processor (mirrored in both the C++ and C# implementations) — never through ad hoc
string-matching scattered across the codebase, and never via unsandboxed shell/`exec` of
attacker-influenced text. Each supported command MUST be an explicit, allow-listed entry (e.g.
`ping`, `status`, `shutdown`); unrecognized commands MUST fail safe (e.g. surfaced as a message,
not executed). Commands with system-level side effects (shutdown/restart) MUST be clearly marked
as such in the dispatch table and MUST be platform-gated where the underlying OS call differs.
**Rationale**: this is a remote-code-execution-shaped surface by design (an external controller
triggers actions on the host) — safety here comes from a closed allow-list, not from trusting the
serial peer.

### V. IPC Boundary Discipline
Every local IPC surface (tray tooltip pipe, serial bridge pipe, and any future channel opened for
other company applications to send messages to the serial port) MUST be created with an explicit
security descriptor that restricts which local principals may connect (the existing pattern:
`BUILTIN\Administrators`-only via `D:(A;;GA;;;BA)`). Anonymous or unauthenticated network listeners
are out of scope for this agent — IPC stays local-machine-only unless a future ADR says otherwise.
Bytes/text received over any IPC channel MUST be treated as untrusted input, same as serial C2A
input.
**Rationale**: the serial bridge pipe forwards arbitrary bytes straight onto a live hardware
link with no app-level secret — the OS-level ACL is the only control, so it must never be skipped
or weakened for convenience.

### VI. Cross-Platform Parity via Platform Abstraction
OS-specific behavior MUST live behind the `Platform` interface (`WindowsPlatform` /
`LinuxPlatform` in C++; the equivalent seam in the C# agent) — core logic (main loop, C2A dispatch,
CSV formatting, metrics aggregation) MUST stay platform-agnostic and MUST NOT contain `#ifdef`
soup or OS-specific branching outside the `platform/` layer. A feature landing on one OS MUST
either land on the other with an equivalent implementation, or be explicitly documented as
platform-limited (e.g. `shutdown` is currently Windows-only) with the reason recorded.
**Rationale**: the project explicitly targets both Windows and Linux nodes; parity drift turns
into silent behavioral gaps the MC operator can't see coming.

### VII. Tray App Process Isolation
The tray icon presented to the logged-in user MUST run as a separate, unprivileged, per-user-
session process/instance — launched in the interactive user's session, not inside the privileged
service process — and MUST communicate with the service only through the defined IPC channel
(currently the `corestation_tray` named pipe). The tray app MUST show only a curated subset of
information intended for the end user (host/IP/uptime today); it MUST NOT gain direct access to
the serial port, to C2A command dispatch, or to any data beyond what the service chooses to publish
to it.
**Rationale**: keeps the high-privilege service process's attack surface away from anything
running in an interactive, potentially-untrusted user session.

## Technology & Platform Constraints

- Supported OS targets: Windows (service via `StartServiceCtrlDispatcher`, MSVC or MSYS2 MinGW
  G++ toolchains) and Linux (systemd service, native GCC/G++, Debian and RPM packaging).
- Two parallel implementations currently exist — the original C++ agent (`src/`) and a newer C#
  agent (`csharp/`) — both MUST honor Principles I–VII; a capability added to one MUST be tracked
  for the other rather than left to diverge silently.
- Packaging MUST continue to produce installable artifacts per platform (Inno Setup installer for
  Windows, `.deb` for Debian/Ubuntu, `.rpm` for RHEL) with `version.h` (or the C# equivalent) as
  the single source of truth for the shipped version number.
- Code signing (Windows EV cert) applies to release builds distributed outside the dev machine;
  unsigned local/dev builds are acceptable during development.

## Development Workflow & Quality Gates

- CI pipelines (Windows/Linux/Debian, per `bitbucket-pipelines.yml`) MUST pass before a change is
  considered mergeable.
- `clang-tidy` (C++) MUST be run on touched files before a PR is raised; equivalent static
  analysis expectations apply to the C# agent as its tooling matures.
- New modules or non-trivial behavior changes MUST come with tests under `tests/` (C++) or
  `csharp/tests/` (C#) — this repo already treats "Split Windows/Linux platform files... add CI
  pipelines and tests" as an established norm, not an aspiration.
- Debug/verbose logging goes through the existing `LogMessage(...)` path; RC builds log
  everything, GA builds log only `ERROR`/`WARNING`/`FATAL` — new log call sites MUST pick the
  correct severity rather than defaulting to always-on verbose output.
- `release-notes.txt` and the relevant packaging metadata (`debian/changelog`, `debian/control`,
  `version.h`) MUST be updated as part of any change that ships in a release, not after the fact.

## Governance

This constitution supersedes ad hoc practice for this repository. Where a PR, plan, or spec
conflicts with a principle here, the conflict MUST be resolved or explicitly justified in that
PR/plan before merge — "we've always done it this way" does not override a ratified principle.

**Amendment procedure**: amendments are made by editing this file via the `/speckit-constitution`
workflow (or direct PR review by the project owner), and MUST update the Sync Impact Report at the
top of the file and the version/date line below in the same change.

**Versioning policy** (semantic versioning applied to this document):
- MAJOR: a principle is removed or redefined in a backward-incompatible way.
- MINOR: a new principle or materially expanded section is added.
- PATCH: wording, typo, or clarification changes with no semantic shift.

**Compliance review**: `/speckit-plan` and `/speckit-analyze` (and any manual review) MUST check
proposed work against these principles, in particular Principles II (SBOM), IV (command
allow-listing), and V (IPC ACLs), since those three are the ones most likely to be quietly skipped
under deadline pressure. Complexity or a new dependency MUST be justified against Principle I
before being accepted. Use `CLAUDE.md` and `docs/agents/*` for day-to-day runtime agent guidance;
this file governs the project's non-negotiables.

**Version**: 1.0.0 | **Ratified**: 2026-08-15 | **Last Amended**: 2026-08-15

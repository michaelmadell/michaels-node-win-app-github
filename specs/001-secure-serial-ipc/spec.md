# Feature Specification: Authenticated Serial IPC for Company Applications

**Feature Branch**: `001-secure-serial-ipc`

**Created**: 2026-08-15

**Status**: Draft

**Input**: User description: "Implement a secured IPC for other applications to send messages and statuses to the Serial Port through the agent. I don't want this IPC to be accessible from any other application or user, admin or not, unless authenticated. Add a dev flag for IPC so that this auth is disabled."

## Clarifications

### Session 2026-08-15

- Q: On Linux, what should establish a connecting client's identity in place of Windows'
  Authenticode certificate check? → A: A detached CMS/PKCS#7 signature over the Linux binary,
  produced with the *same* DigiCert EV code-signing certificate already used for Windows signing
  (via `smctl`/`openssl cms`, not GPG — DigiCert KeyLocker doesn't export key material, so a
  GPG keypair isn't an option), verified on the agent side with OpenSSL against the cert's
  Subject. This requires a new detached-signing build script (Linux release pipeline doesn't
  currently sign anything).
- Q: Which agent codebase should this cross-platform IPC channel live in — the existing C++
  agent, the newer C# agent, or both? → A: Both, in parallel. Each agent MUST cover both
  platforms: the C++ agent hardens its existing Windows pipe and gains a new Linux
  implementation; the C# agent gains new implementations on both Windows and Linux (it has
  neither today). All four combinations use the same per-platform identity mechanism
  (Authenticode on Windows, detached CMS signature on Linux) and the same authentication
  guarantee.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Company app delivers a status message through the agent (Priority: P1)

A locally installed, company-developed application wants to report a status or message out over
the node's serial link (to the Management Controller) without talking to the serial port directly.
It connects to the agent's IPC channel, is recognized as a legitimate company application, and its
message is forwarded to the serial port.

**Why this priority**: this is the entire reason the IPC channel exists — without it, no other
application can get a message onto the serial link at all. It is the MVP. This must hold on
whichever platform (Windows or Linux) and whichever agent implementation (C++ or C#) the node is
running, since the company applications connecting to it are themselves cross-platform.

**Independent Test**: on each of Windows and Linux, against each of the C++ and C# agent
implementations, launch a company-signed test app that opens the IPC channel and sends a sample
status string; confirm the exact bytes appear on the serial port with no manual configuration
beyond the app being present and correctly signed (embedded Authenticode signature on Windows, a
valid accompanying detached signature file on Linux).

**Acceptance Scenarios**:

1. **Given** the agent is running with authentication enabled, **When** a company-signed
   application connects to the IPC channel and sends a message, **Then** the message is forwarded
   to the serial port unchanged.
2. **Given** a company-signed application is mid-session on the IPC channel, **When** it sends
   multiple messages in sequence, **Then** each one is forwarded in order without requiring
   re-authentication per message.

---

### User Story 2 - Unauthorized caller is blocked, even as admin (Priority: P1)

An application that is not one of the company's signed applications — including one running with
Administrator privileges, or a user manually poking at the pipe — attempts to connect to the IPC
channel and send data. The agent refuses to forward anything from it.

**Why this priority**: this is the actual security requirement driving the feature — today,
Administrator rights alone are enough to use the channel, which is explicitly not acceptable
going forward. Without this, User Story 1 has no real protection.

**Independent Test**: on each platform/agent combination, attempt to connect to the IPC channel
from (a) an unsigned test executable, and (b) a signed-but-unrelated executable (elevated as
Administrator on Windows; run as root or the equivalent unrestricted local account on Linux);
confirm both connections are refused and nothing reaches the serial port.

**Acceptance Scenarios**:

1. **Given** the agent is running with authentication enabled, **When** an unsigned application
   (regardless of the OS user's privilege level) attempts to connect, **Then** the connection is
   refused and no data reaches the serial port.
2. **Given** the agent is running with authentication enabled, **When** an application signed by
   a certificate that isn't the company's code-signing identity attempts to connect, **Then** the
   connection is refused and no data reaches the serial port.
3. **Given** a rejected connection attempt of either kind above, **When** it occurs, **Then** the
   agent records the rejection in its log as a security-relevant event.

---

### User Story 3 - Developer disables authentication for local testing (Priority: P3)

A developer working on a company application that talks to the IPC channel, or on the agent
itself, needs to iterate locally without producing a fully signed build on every change. A
developer-only build of the agent can have IPC authentication disabled so any local test client
can connect.

**Why this priority**: pure developer convenience — it doesn't affect any end-user- or
production-facing behavior, and User Stories 1 and 2 must work correctly with or without it.

**Independent Test**: build the agent with the dev flag enabled, connect an unsigned test client,
and confirm the message is forwarded; then build the standard (non-dev) configuration with the
same test client and confirm the connection is refused.

**Acceptance Scenarios**:

1. **Given** the agent was built with the dev flag enabled, **When** any application (signed or
   not) connects to the IPC channel, **Then** its messages are forwarded without an authentication
   check.
2. **Given** the agent was built with the dev flag enabled, **When** it starts up or accepts a
   connection, **Then** it makes the disabled-authentication state visible (e.g., in its logs) so
   it is never mistaken for a production build.
3. **Given** a standard Release/RC/GA build of the agent, **When** its behavior is inspected,
   **Then** there is no way to enable the dev flag at runtime — it simply is not present.

---

### Edge Cases

- What happens when the company's code-signing certificate is renewed (new thumbprint/expiry,
  same organizational identity)? Existing deployed agents MUST keep accepting company-signed apps
  without a configuration change (see FR-004).
- What happens when the signing certificate is revoked or a client's signature can't be validated
  at all (e.g., broken chain of trust, expired with no valid renewal)? The connection MUST be
  treated as unauthorized (same as unsigned).
- What happens when a non-company admin tool (signed by a different, unrelated legitimate
  certificate) tries to connect while running elevated? It MUST still be refused — elevation is
  not a substitute for the correct signing identity.
- What happens if a client process is swapped out for a different (unsigned) binary between
  authentication and sending data? The agent MUST NOT assume trust persists beyond what it can
  verify about the currently connected caller.
- What happens when a dev-flag build is run outside of a developer's machine (e.g., accidentally
  installed on a real node)? It MUST remain visibly distinguishable (see FR-006) even though this
  spec doesn't add a way to prevent someone from installing the wrong build.
- What happens on Linux when a client binary's detached signature file is missing, doesn't match
  the binary (e.g., binary was rebuilt/patched after signing), or doesn't match the company's
  Subject identity? Treated as unauthenticated, same as an unsigned Windows caller (FR-005).
- **What happens on Linux when a legitimately signed client connects, writes its message, and
  exits immediately (a true fire-and-forget one-shot process) before the agent finishes resolving
  its identity?** Confirmed by live testing (WSL, real signed test client): the agent resolves
  identity via `/proc/<pid>/exe`, which can disappear once the client process has fully exited —
  a legitimately signed, correctly identified client can be spuriously rejected as unauthenticated
  purely due to this timing race, not any actual signature problem. `SO_PEERCRED`'s PID/UID/GID
  themselves are kernel-cached at connect time and not racy; only the `/proc` image-path lookup
  is. Client applications MUST keep the connection open until the write is acknowledged, or at
  minimum briefly after writing (a fixed short delay before exit is not a guarantee, only a
  mitigation) — this is a client-side integration requirement, not something the agent can fully
  eliminate on its own without a protocol change (e.g., a 1-byte ack) that's out of scope here.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The agent MUST require every application connecting to the serial-forwarding IPC
  channel to be authenticated before any of its data is forwarded to the serial port.
- **FR-002**: Authentication MUST be based on verifying that the connecting client's executable is
  signed with the company's code-signing identity (matching Subject fields such as Common Name,
  Organization, and Organizational Unit) — not on the OS user or group the client is running as.
  On Windows this is the executable's embedded Authenticode signature; on Linux this is a detached
  CMS/PKCS#7 signature file shipped alongside the executable, produced by the same code-signing
  certificate. Both MUST be verified against the same Subject identity, so a client's trust status
  doesn't depend on which platform it runs on.
- **FR-003**: Administrator-level OS privilege alone MUST NOT be sufficient to use the channel;
  an elevated but unsigned or wrongly-signed caller MUST be refused exactly like a non-elevated
  one.
- **FR-004**: Signature verification MUST match on the stable identity fields of the certificate
  (Subject: CN/O/OU) rather than the exact thumbprint/serial number of the currently active
  certificate, so that a routine renewal of the company's code-signing certificate does not
  require reconfiguring already-deployed agents.
- **FR-005**: The agent MUST reject and close connections from any application that is unsigned,
  signed by a certificate that doesn't match the company's signing identity, or whose signature
  cannot be validated — with zero bytes forwarded to the serial port for that connection.
- **FR-006**: The agent MUST support a developer/test build configuration ("dev flag") that
  disables this authentication check entirely. This flag MUST be a compile-time build option that
  is absent from Release/RC/GA builds — there MUST be no runtime switch, configuration value, or
  command-line argument capable of disabling authentication in a production build.
- **FR-007**: When a build has the dev flag enabled, the agent MUST make that state clearly visible
  (e.g., a distinct log line at startup and/or per connection) so a dev build is never mistaken for
  a production one.
- **FR-008**: The agent MUST log every rejected connection/authentication attempt as a
  security-relevant event, using the existing log-severity conventions (README: RC builds log
  everything, GA builds log `ERROR`/`WARNING`/`FATAL`).
- **FR-009**: Once a client is authenticated, the agent MUST continue forwarding its messages
  to the live serial connection exactly as today — raw bytes, no added framing — for the life of
  that connection.
- **FR-010**: Any existing OS-level access restriction on the IPC channel (e.g., the current
  named-pipe ACL limiting connections to Administrators, or the equivalent filesystem permissions
  on a Linux socket) MAY remain in place as an additional layer, but MUST NOT be relied upon as
  the sole or primary control now that signature-based authentication is required.
- **FR-011**: The agent MUST expose an equivalent IPC channel on Linux (no channel exists there
  today), enforcing the same authentication guarantee as Windows (FR-001 through FR-005) rather
  than a weaker fallback — a company application gets the same trust outcome regardless of which
  platform it and the agent are running on.
- **FR-012**: The release/build pipeline MUST produce a detached signature file for each Linux
  release binary that will act as an IPC client, signed with the company's existing EV
  code-signing certificate, published alongside the binary it covers. Without this, no Linux
  client can ever authenticate.
- **FR-013**: Both existing agent implementations (the C++ agent and the C# agent) MUST provide
  this authenticated IPC channel, each covering both Windows and Linux. A company application
  connecting to any of the four platform/agent combinations MUST get the same authentication
  guarantee — none is allowed to be a weaker or later-arriving fallback.

### Key Entities

- **IPC Client Application**: a locally running, company-developed application that wants to
  submit a message or status string to be relayed to the serial port. Identified/authenticated by
  the code-signing identity of its executable.
- **Serial Forwarding Channel**: the local IPC endpoint the agent exposes for client applications
  to submit data destined for the serial port; the target of this feature's authentication
  requirement.
- **Company Code-Signing Identity**: the trusted certificate Subject (CN/Organization/OU) used as
  the sole basis for authenticating IPC clients; distinct from, and renewable independently of, any
  single certificate instance (thumbprint). The same identity is asserted two ways depending on
  platform (embedded Authenticode signature on Windows, detached signature file on Linux).
- **Detached Signature File** (Linux only): a signature artifact published alongside a Linux
  client binary, produced by the company's EV certificate, that the agent checks against the
  binary at connection time in place of Windows' embedded Authenticode signature.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of connection attempts from unsigned executables, or executables signed by a
  non-matching certificate, are refused with zero data reaching the serial port, across all tested
  scenarios including elevated/Administrator (or root-equivalent) callers, on all four
  platform/agent combinations (C++/Windows, C++/Linux, C#/Windows, C#/Linux).
- **SC-002**: A legitimate, correctly signed company application can connect and have a status
  message delivered to the serial port in under 1 second under normal operating conditions, on
  any of the four platform/agent combinations.
- **SC-003**: After the company's code-signing certificate is renewed, previously deployed agents
  continue accepting correctly signed company applications with zero configuration changes, on
  both Windows (embedded signature) and Linux (detached signature file).
- **SC-004**: Standard Release/RC/GA builds produced by the normal build pipeline, for either
  agent, offer no way to disable IPC authentication — confirmed by inspecting the shipped build
  configuration.
- **SC-005**: 100% of rejected authentication attempts are visible in the agent's log output at the
  appropriate severity, on every platform/agent combination.

## Assumptions

- This feature hardens/extends the existing serial-forwarding IPC channel (today's Windows-only
  `\\.\pipe\corestation_serial_bridge`) rather than introducing a second, separate channel on
  Windows — that pipe already exists specifically to forward raw bytes from a local app to the
  serial port. Linux has no equivalent channel yet, so this feature is what introduces one there.
- Scope is cross-platform (Windows and Linux) per explicit direction — the company applications
  that will use this channel are themselves cross-platform, so each platform needs an equivalent,
  equally-strong authentication route rather than Linux being an afterthought or a weaker fallback.
- "Other applications developed by our company" means internal applications built and signed
  through the same EV code-signing process/certificate already used to sign this agent's own
  release binaries.
- No separate credential, token, or secret system is introduced — trust is rooted entirely in the
  company's existing code-signing certificate chain, per the user's direction that no
  credential system exists today.
- The "dev flag" is a compile-time build option in each agent's own build system — the spirit of
  the existing `BUILD_SERIAL_BRIDGE_PIPE` CMake option for the C++ agent, and an equivalent
  compile-time-only mechanism (e.g., a build constant excluded from Release configurations) for
  the C# agent — not a runtime or config-file toggle in either case, so it cannot be accidentally
  left active in a shipped build.
- The existing named-pipe ACL (Administrators-only) may be kept as defense-in-depth on the C++
  Windows path, but is superseded as the primary control by the signature check defined here; the
  three new implementations (C++/Linux, C#/Windows, C#/Linux) apply the equivalent OS-level
  restriction available on their platform as the same kind of defense-in-depth layer, not as the
  primary control.
- Both agents share the same conceptual identity check (verify the company's EV certificate
  Subject) but each implements it with the tools native to its language/platform — this spec does
  not require or assume shared verification code between the C++ and C# agents.

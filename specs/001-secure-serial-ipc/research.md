# Research: Authenticated Serial IPC for Company Applications

Scope per the 2026-08-15 clarification session: four platform/agent combinations —
C++ agent/Windows, C++ agent/Linux, C# agent/Windows, C# agent/Linux — all with the same
authentication guarantee and the same client-facing channel identity per platform.

## Decision 1: Authentication mechanism — Authenticode (Windows) / detached CMS via the same EV cert (Linux)

**Decision**: Windows keeps signer-identity verification via Authenticode (`WinVerifyTrust`).
Linux verifies a **detached CMS/PKCS#7 signature** file shipped alongside each client binary,
produced with the *same* DigiCert EV code-signing certificate (via `smctl` or `openssl cms`),
not a separate GPG key — DigiCert KeyLocker doesn't export private key material, so a GPG keypair
was never an option. Both platforms end at the same check: does the signer's certificate Subject
(CN/O/OU) match the company's known identity.

**Rationale**: reuses infrastructure the company already pays for and operates (one EV
certificate, one signing workflow) instead of standing up a second, parallel trust root. Matches
the user's explicit answer.

**Verify-by-chain, not by leaf-cert-pinning**: on both platforms, verification walks the
signature's certificate chain up to a trust anchor and then checks the **Subject** of the signer
certificate — not a pinned thumbprint/serial number of one specific certificate instance. On
Windows, the OS certificate store already carries the public CA chain, so this is "free." On
Linux, the agent must carry the DigiCert root/intermediate CA certificates (public information,
safe to embed) as its trust anchor for CMS chain validation. This is what makes certificate
renewal (spec FR-004/SC-003) a non-event on both platforms — the CA chain doesn't change on a
routine EV cert renewal, only the leaf does.

**Alternatives considered**: see the original research.md from the Windows-only draft (per-app
token, OS ACL alone, mutual-TLS-style channel) — still rejected for the same reasons, now applying
to both platforms equally.

## Decision 2: Linux transport — Unix domain socket, one shared path regardless of agent

**Decision**: Linux exposes a `SOCK_STREAM` Unix domain socket at a fixed path (working name
`/run/corestation/serial_bridge.sock`), created with filesystem permissions restricting it to
root/a dedicated system group — the direct functional analog of the Windows named pipe. The path
and behavior are identical whether the node is running the C++ agent or the C# agent, so a client
application never needs to know which implementation is on the other end.

**Rationale**: Unix domain sockets are the standard native local-IPC primitive on Linux (same
tier as named pipes on Windows — no new dependency, per Constitution Principle I). A single
well-known path per platform keeps the client-facing contract (`contracts/serial-bridge-ipc.md`)
one document instead of four.

**Alternatives considered**: abstract (unnamed) Linux sockets — rejected, no filesystem ACL
surface to restrict access, weaker defense-in-depth than a permissioned socket file.
FIFO/named pipe emulation on Linux — rejected, doesn't give duplex per-connection semantics or
`SO_PEERCRED`, which the auth check depends on.

## Decision 3: Resolving the connecting peer's identity, per platform

- **Windows** (unchanged from the original research): `GetNamedPipeClientProcessId` →
  `OpenProcess`/`QueryFullProcessImageNameW` → image path → `WinVerifyTrust`.
- **Linux**: `getsockopt(SO_PEERCRED)` on the accepted connection → peer PID (kernel-supplied,
  unspoofable by the client) → resolve `/proc/<pid>/exe` (readlink) → image path → locate the
  accompanying detached signature file (convention: `<binary>.sig` next to the binary, or a
  configured signature directory — a concrete choice for the implementation task, not pinned
  here) → verify via OpenSSL CMS against the embedded CA trust anchor → compare signer Subject.

**Rationale**: `SO_PEERCRED` is the Linux-native, kernel-enforced equivalent of
`GetNamedPipeClientProcessId` — both give a PID the *kernel* vouches for, not something the
client can lie about over the wire.

## Decision 4: New third-party dependency — OpenSSL, C++ agent, Linux build only

**Decision**: the C++ agent's Linux build links `OpenSSL::Crypto` (via `find_package(OpenSSL
REQUIRED)`) to perform CMS signature verification, gated behind the same build option that
enables the bridge (see Decision 6). This is a **new** dependency — nothing in the C++ agent
currently links OpenSSL — and MUST get an SBOM entry per Constitution Principle II before it
reaches a release build.

**Rationale (Constitution Principle I justification)**: Linux has no OS syscall or libc
equivalent of `WinVerifyTrust`/CMS verification; shelling out to the `openssl` CLI and parsing
its text output was considered and rejected — this codebase already fixed one command-injection-
shaped shell-out bug (see git history), and re-introducing a parse-fragile subprocess call for a
*security* check is the wrong trade. OpenSSL's `libcrypto` is the de facto native crypto library
on Linux (present on essentially every target distro, often already a transitive dependency of
other installed software), making it the closest available equivalent to a "native call" for this
specific gap.

**Alternatives considered**: GnuTLS/libgcrypt — rejected, no material advantage over OpenSSL and
less commonly already present; shelling out to `openssl`/`gpg` CLI — rejected per above.

**C# agent**: one small new dependency. Unix domain sockets (`UnixDomainSocketEndPoint`) are part
of the .NET 8 shared framework already. `System.Security.Cryptography.Pkcs.SignedCms`
(CMS/PKCS#7 verification) is **not** — confirmed by a failed build during implementation
(`CS1069`), despite being a first-party .NET assembly; it needs an explicit
`PackageReference Include="System.Security.Cryptography.Pkcs"` in `CoreStationAgent.csproj`. This
correction supersedes the original wording of this decision. The Windows Authenticode check has
no fully-managed API; it's a P/Invoke onto `WinVerifyTrust` (`Platform/Windows/
WinTrustNativeMethods.cs`, using classic `[DllImport]` rather than the project's usual
`[LibraryImport]` — see that file's header comment) — not a package dependency either way.

## Decision 5: C# bridge forwards through the existing single-writer outbound channel

**Decision**: the C# implementation does **not** write bridged bytes directly to `ISerialLink`
from the bridge-listener thread. It queues each authenticated message through the existing
`IBmcChannel`/`SerialTransportService` outbound `Channel<string>` — the same path telemetry and
C2A replies already use — so the port is still only ever touched by `SerialTransportService`'s
single writer loop.

**Rationale**: `SerialTransportService` is explicitly documented as the port's sole writer to
prevent interleaved/corrupted writes; a second thread writing directly to `ISerialLink` for
bridged messages would break that invariant — a real correctness regression, not a stylistic
concern. Practical effect on spec FR-009 ("raw bytes, no added framing"): the *content* of the
authenticated client's message is forwarded unmodified — nothing is reformatted, escaped, or
CSV-ified — but it goes out through the transport's standard line boundary (a trailing CRLF, the
same terminator the BMC already scans for per `LineFramer`), exactly like every other line this
transport sends. This is a deliberate, documented accommodation to the C# agent's existing
architecture, not a silent deviation.

**Alternatives considered**: a second dedicated writer with its own lock around `ISerialLink` —
rejected, adds real concurrency risk (two independent paced writers racing) for no behavioral
gain over reusing the channel that already exists for exactly this purpose.

**C++ agent**: unaffected — it already forwards through a single handler callback
(`forwardSerialBridgeMessage` → `serial_bridge_handler_`) wired to the one `SerialManager`
instance; this research doesn't change that existing single-writer path.

## Decision 6: Dev flag, per build system

- **C++ (both platforms)**: one CMake option, `IPC_AUTH_DEV_DISABLE` (default `OFF`), gating a
  `#ifdef` around the verification call in both `SerialBridgePipe` (Windows) and the new Linux
  socket module — consistent with the existing `BUILD_SERIAL_BRIDGE_PIPE` pattern, unchanged from
  the original research.
- **C#**: an MSBuild-level compile constant (working name `IPC_AUTH_DEV_DISABLE`) defined only in
  a `Debug`-only `PropertyGroup`/`DefineConstants`, guarding an `#if IPC_AUTH_DEV_DISABLE` block
  around the verification call. `dotnet publish -c Release` (the only configuration that ships)
  never defines it — structurally equivalent to the C++ option being compiled out of Release/RC/GA.

**Rationale**: preserves the user's explicit "compile-time only" answer in each agent's own
native build system, rather than inventing a shared cross-language flag file.

## Decision 7: Scope carried over unchanged from the Windows-only draft

Everything in the original research.md not superseded above still applies: no new
credential/token system; trusted Subject values (CN/O/OU) are sourced from the live EV cert as an
implementation task, not invented here; the manual Python test client
(`tools/serial_bridge_client.py`) will be rejected by any build with authentication enabled on
either platform, for the same reason (it isn't signed/counter-signed by the company).

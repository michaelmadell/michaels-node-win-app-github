# Data Model: Authenticated Serial IPC for Company Applications

Session/protocol-oriented, not storage-oriented — no database, nothing persisted across restarts,
in either agent. The shapes below are conceptual (both C++ and C# implement them their own way;
field names here are not a mandated API).

## ConnectingClientIdentity

Resolved once per accepted connection, before any client bytes are forwarded. Platform-specific
resolution, same shape.

| Field           | Type      | Windows source                                   | Linux source                                        |
|-----------------|-----------|---------------------------------------------------|-------------------------------------------------------|
| `processId`     | integer   | `GetNamedPipeClientProcessId`                     | `SO_PEERCRED` peer credentials                        |
| `imagePath`     | string    | `QueryFullProcessImageNameW`                      | `readlink /proc/<pid>/exe`                             |
| `signatureValid`| bool      | `WinVerifyTrust` result                           | OpenSSL/`SignedCms` CMS-verify of the detached `.sig`  |
| `subjectCN`     | string    | Signer cert Common Name (only meaningful if `signatureValid`) | same |
| `subjectO`      | string    | Signer cert Organization                          | same                                                    |
| `subjectOU`     | string    | Signer cert Organizational Unit                   | same                                                    |
| `authenticated` | bool      | Derived: `signatureValid && subject fields match trusted identity` (or unconditionally `true` when the dev flag is compiled in) | same |

**Validation rule**: `authenticated` MUST default to `false` and only become `true` through the
affirmative checks above, on every platform/agent combination. Any failure resolving any field
(process lookup fails, `.sig` file missing on Linux, chain doesn't validate, etc.) MUST leave
`authenticated == false` — never treated as "couldn't check, so allow."

**Lifecycle**: created after connection acceptance → populated synchronously before any read
loop/forwarding starts → used for exactly one connection → discarded on disconnect. Not cached or
reused across connections/PIDs, so a binary swapped out mid-session can't inherit a prior trust
decision.

## TrustedSigningIdentity (compile-time constant)

| Field        | Type   | Notes                                                                 |
|--------------|--------|--------------------------------------------------------------------------|
| `cn`/`o`/`ou`| string | Expected signer Subject fields — sourced from the live EV cert (research.md Decision 1), identical constant shared by all four platform/agent combinations. |
| `caTrustAnchor` | cert bundle | Linux only: the DigiCert root/intermediate CA chain embedded in the agent, used as the trust anchor for CMS chain validation (Windows gets this "for free" from the OS certificate store). |

Not runtime-loaded, not user-configurable on any platform — compiled in alongside the
verification code.

## DetachedSignatureFile (Linux only)

| Field   | Type   | Notes |
|---------|--------|-------|
| `path`  | string | Location convention relative to the signed binary (e.g. `<binary>.sig`) — a concrete implementation-task decision, not pinned in this plan. |
| `bytes` | binary | The CMS/PKCS#7 signature blob produced by the release signing script (research.md Decision 4/Assumptions) over the exact binary it accompanies. |

Produced once, at build/release-signing time, by the same pipeline step that already produces the
Windows Authenticode-signed binary — not generated or modified at runtime by the agent.

## Connection Lifecycle (state machine — same shape on all four combinations)

```
Listening
   │  connection accepted (ConnectNamedPipe / accept())
   ▼
ClientConnected
   │  dev flag compiled in? ──yes──► Authenticated (skip checks, log dev-mode notice)
   │  no
   ▼
Authenticating (resolve ConnectingClientIdentity for this platform)
   │
   ├─ authenticated == true ──► Authenticated ──► Forwarding ──► Closed
   │        (C++: direct call into the existing single serial-write handler)
   │        (C#: message queued onto the existing single-writer outbound channel —
   │              see research.md Decision 5)
   │
   └─ authenticated == false ─► Rejected (log WARNING, close connection, no bytes
                                            read/forwarded) ──► Closed
```

No new persistent entity, schema, or migration is introduced by this feature on either agent.

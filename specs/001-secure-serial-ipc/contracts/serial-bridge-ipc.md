# Contract: Serial Bridge IPC Channel (authenticated, cross-platform)

Two endpoints, one per OS — identical behavior, identical client-facing contract, regardless of
whether the node is running the C++ agent or the C# agent:

| Platform | Endpoint | Notes |
|----------|----------|-------|
| Windows  | Named pipe `\\.\pipe\corestation_serial_bridge` | Unchanged name/location from today. |
| Linux    | Unix domain socket `/run/corestation/serial_bridge.sock` (working path — see `data-model.md`) | New; no equivalent existed before this feature. |

## Who this contract is for

Any company-developed local application — on either OS — that wants to forward a message/status
string to the serial port through whichever agent is running on that node. No SDK or client
library is provided or required — this is a plain byte-stream contract per platform.

## Wire protocol — unchanged from today (Windows), newly established (Linux)

No new bytes, handshake, or framing on top of what the client sends:

1. Client opens the endpoint (`CreateFile` on Windows; `connect()` on Linux).
2. Client writes raw bytes — no length prefix, no client-side terminator required.
3. Agent forwards the message content to the serial port, unmodified. (On the C# agent, this
   happens via the agent's existing single-writer outbound path, which appends the same line
   terminator every other outbound message already gets — see `research.md` Decision 5. On the
   C++ agent, bytes go out exactly as received, matching today's behavior.)
4. Client may send multiple messages on one connection; each is forwarded independently, no
   re-authentication required per message.
5. Client closes the connection when done.

A correctly built and signed (Windows) / signed-with-accompanying-`.sig` (Linux) company
application requires **zero code changes** to keep working under this feature — authenticity is
established out-of-band, by the agent inspecting the connecting process, not by anything the
client sends in-band.

## What changes: connection admission

| Step | Before this feature | After this feature |
|------|---------------------|---------------------|
| OS-level access restriction | Windows: `BUILTIN\Administrators`-only pipe ACL. Linux: none (channel didn't exist). | Kept/added as defense-in-depth on both platforms (spec FR-010) — no longer the primary control. |
| App-level identity check | None on either platform | Windows: Authenticode signature check. Linux: detached CMS signature check. Both against the same company Subject identity. |
| Unauthenticated caller | Windows: any admin caller was implicitly trusted. Linux: N/A, channel didn't exist. | Connection is accepted at the OS/socket level, then closed by the agent before any payload is read/forwarded, on both platforms. |
| Dev-flag build | N/A | Identity check compiled out on whichever platform/agent the dev build targets; behaves like "before this feature." |

## Failure behavior (client-observable)

- **Signed, trusted client (either OS)**: behaves exactly like a normal connection — write
  succeeds, bytes reach the serial port.
- **Unsigned / wrong-signer / untrusted client (either OS)**: the connection is closed by the
  agent immediately after acceptance, before any read occurs. The client sees a broken/reset
  connection, not a protocol-level error message — no in-band error channel is introduced. The
  reason is recorded in the agent's own log (spec FR-008), not returned to the caller.

## Non-goals of this contract

- No acknowledgment/response channel — fire-and-forget forwarding, unchanged from today's Windows
  behavior and matched on Linux.
- No new endpoint beyond the one-per-platform pair above — this hardens/introduces exactly one
  channel per OS, not one per agent implementation.
- No message framing/delimiting added to the client-facing contract — CSV formatting
  (Constitution Principle III) governs the agent's own *outbound telemetry* stream, not this
  inbound bridge.

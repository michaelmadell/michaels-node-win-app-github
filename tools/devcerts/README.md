# Dev certs: local end-to-end testing for the authenticated serial IPC bridge

Tooling to exercise `specs/001-secure-serial-ipc`'s authentication logic against **real**
signatures and a **real** running agent, without the company's EV certificate. Everything here
was built and used to live-validate all four platform/agent combinations (C++/C# × Windows/Linux)
during that feature's implementation — see that feature's `tasks.md` for the results.

## What's here vs. what's gitignored

| Path | Committed? | Why |
|------|-----------|-----|
| `tools/devcerts/*.sh`, `*.ps1`, `test-clients/` | Yes | Scripts and tiny client sources — no secrets, fully reproducible. |
| `.devcerts/` (repo root, created by `generate-dev-certs.sh`) | **No, gitignored** | Private keys (`dev_ca.key`, `dev_signing.key`) and a PFX with a hardcoded password live here. Never commit private key material, even for a throwaway dev identity — anyone with repo access could then sign a binary that this agent would treat as trusted. |
| `src/modules/serialpipe/certs/digicert_ca_chain.pem`, `csharp/src/CoreStationAgent/Ipc/digicert_ca_chain.pem` | Yes (already committed) | The **public** cert of one specific dev CA, currently standing in for the real DigiCert chain. Safe to share — it's a public certificate, not a key. |

Because the CA's private key is never committed, only whoever generated the currently-committed
`digicert_ca_chain.pem` can issue new leaf certs that validate against it. If you need your own,
run `generate-dev-certs.sh` and, if you want your CA to become the new shared placeholder, copy
`.devcerts/dev_ca.pem` over both `digicert_ca_chain.pem` files yourself and commit that — these
scripts never do it for you.

## Workflow

1. **Generate a dev identity** (once, or anytime you want a fresh one):
   ```bash
   tools/devcerts/generate-dev-certs.sh
   ```
   Produces `.devcerts/dev_ca.{pem,key}`, `.devcerts/dev_signing.{pem,key,csr}`, and
   `.devcerts/dev_signing.pfx` (password `devtest123`, dev-only).

2. **Build a test client** for the platform you're testing:
   ```bash
   gcc -O0 -o windows_pipe_client.exe tools/devcerts/test-clients/windows_pipe_client.c   # Windows
   gcc -O0 -o linux_socket_client tools/devcerts/test-clients/linux_socket_client.c        # Linux
   ```

3. **Sign it** (skip this step entirely to test the *rejection* path instead):
   ```powershell
   .\tools\devcerts\sign-windows-client.ps1 -BinaryPath .\windows_pipe_client.exe
   ```
   ```bash
   tools/devcerts/sign-linux-client.sh linux_socket_client
   ```

4. **Build the agent** with the bridge enabled, against the same trust anchor already committed
   (`TrustedIdentity.h`/`ClientAuthenticator.cs` already hold this repo's current dev identity's
   Subject — no changes needed unless you replaced the trust anchor in step 1):
   ```bash
   cmake -S . -B build -DBUILD_SERIAL_BRIDGE_PIPE=ON -DENABLE_TESTING=ON
   cmake --build build
   ```
   or for the C# agent: `dotnet build -c Release` (Release, not Debug — Debug defines
   `IPC_AUTH_DEV_DISABLE`, which skips authentication entirely and defeats the point of this test).

5. **Run the agent** and connect your client. On Windows the pipe ACL restricts connections to
   Administrators; on Linux the socket lives under `/run/corestation`, which needs root to create.
   If you're not running elevated/as root, that's a real constraint you'll hit before
   authentication even gets a chance to run — this is defense-in-depth working as intended
   (spec.md FR-010), not a bug. To test locally without elevation:
   - **Do not weaken the ACL/permission logic in a commit.** If you need to test as a
     non-elevated/non-root user, apply a **temporary, local-only** edit (e.g. relax
     `SerialBridgePipe.cpp`'s SDDL string to `D:(A;;GA;;;WD)`, or redirect
     `SerialBridgeSocket.cpp`'s `kSocketPath`/`LinuxSerialBridgeListener.cs`'s `SocketPath` to
     somewhere under `/tmp`), rebuild, test, then `git checkout --` that file immediately after —
     confirm `git diff` is clean and the normal build still compiles before moving on.
   - Watch the agent's log for the outcome: Windows/C++ writes to
     `C:\ProgramData\ahk\node-win-app.log`; Windows/C# and Linux/C# log to the console; Linux/C++
     logs via `syslog()` (`journalctl` / `/var/log/syslog`), not stdout.

## Known limitation this testing surfaced

A client that writes and exits **immediately** can be spuriously rejected on Linux: the agent
resolves identity via `/proc/<pid>/exe`, which can disappear once the process has fully exited,
racing the server's lookup. Both test clients above linger 2 seconds after writing specifically to
avoid this — see `specs/001-secure-serial-ipc/spec.md`'s Edge Cases for the full writeup.

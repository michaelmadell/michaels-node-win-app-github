# C# agent IPC bridge trust anchor

`LinuxSerialBridgeListener` verifies a connecting client's detached CMS/PKCS#7 signature (see
`tools/sign-linux-release.sh`) by chaining it up to the company's DigiCert EV code-signing root
and intermediate certificates, then checking the signer leaf certificate's Subject (CN/O/OU) —
matching on Subject, not thumbprint, so a routine certificate renewal doesn't require touching
this file (see `specs/001-secure-serial-ipc/research.md` Decision 1).

**This directory intentionally does not ship a real certificate.** `digicert_ca_chain.pem` must
be placed here — a PEM bundle of DigiCert's public root + intermediate CA certificates for the
EV code-signing chain already in use for Windows signing. This is the exact same file used by
the C++ agent's `src/modules/serialpipe/certs/digicert_ca_chain.pem` — see that file's
`README.md` for where to obtain it. Keep both copies in sync.

**Fail-closed by design**: if `digicert_ca_chain.pem` is missing, empty, or fails to parse,
`LinuxSerialBridgeListener` logs at `Critical` and refuses to start the bridge, rather than
silently accepting every connection or silently rejecting every connection with no explanation.

This file must be present in the published output directory alongside `CoreStationAgent.dll`
(see `CoreStationAgent.csproj`'s `Ipc/digicert_ca_chain.pem` content item).

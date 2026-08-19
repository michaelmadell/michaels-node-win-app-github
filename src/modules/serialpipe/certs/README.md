# Linux IPC bridge trust anchor

`LinuxIpcClientAuth` (see `src/modules/serialpipe/LinuxIpcClientAuth.cpp`) verifies a connecting
client's detached CMS/PKCS#7 signature (see `tools/sign-linux-release.sh`) by chaining it up to
the company's DigiCert EV code-signing root/intermediate certificates, then checking the signer
leaf certificate's Subject (CN/O/OU) — matching on Subject, not thumbprint, so a routine
certificate renewal doesn't require touching this file (see
`specs/001-secure-serial-ipc/research.md` Decision 1).

**This directory intentionally does not ship a real certificate.** `digicert_ca_chain.pem` must
be placed here — a PEM bundle of DigiCert's public root + intermediate CA certificates for the
EV code-signing chain already in use for Windows signing (via `smctl`). These are public
certificates (not secret material), obtainable from:

- DigiCert's public CA repository (https://www.digicert.com/kb/digicert-root-certificates.htm), or
- `openssl x509` extracted from the chain returned by the existing Windows signing tooling.

**Fail-closed by design**: if `digicert_ca_chain.pem` is missing, empty, or fails to parse,
`LinuxIpcClientAuth::LoadTrustAnchor()` MUST return failure and the bridge MUST refuse to start
(logged at `FATAL`) rather than silently accepting every connection or silently rejecting every
connection with no explanation. See `src/modules/serialpipe/LinuxIpcClientAuth.cpp` for the
startup check.

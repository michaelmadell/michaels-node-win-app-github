#!/usr/bin/env bash
# Produces a detached CMS/PKCS#7 signature for a Linux release binary, using
# the company's existing DigiCert EV code-signing certificate -- the same
# certificate/identity already used to Authenticode-sign the Windows binary
# via smctl, not a separate GPG key (DigiCert KeyLocker doesn't export
# private key material, so GPG was never an option -- see
# specs/001-secure-serial-ipc/research.md Decision 1).
#
# The agent's IPC bridge (src/modules/serialpipe/LinuxIpcClientAuth.cpp)
# verifies this signature -- via OpenSSL CMS -- against the certificate's
# Subject before trusting a connecting client. Without a valid .sig file
# next to a Linux client binary, that binary can never authenticate
# (spec.md FR-012).
#
# Usage:
#   sign-linux-release.sh <binary>
#
# Produces:
#   <binary>.sig   (detached CMS/PKCS#7 signature, DER-encoded)
#
# Requires ONE of:
#   - smctl (DigiCert Software Trust Manager CLI), already used for the
#     Windows Authenticode signing step in build-production.bat, configured
#     with the same cloud-hosted EV certificate; or
#   - a local PEM copy of the EV certificate + a KeyLocker-issued PKCS#11
#     session usable by `openssl cms -sign -engine pkcs11 ...`
#
# Neither credential is available in this checkout/sandbox -- this script
# is the mechanism, not a working credential. Wire the actual smctl
# invocation/PKCS#11 engine config below once run on a machine with access
# to the DigiCert KeyLocker signing identity (the same one build-production
# already depends on for the Windows exe).

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <binary>" >&2
    exit 1
fi

BINARY="$1"
SIG_FILE="${BINARY}.sig"

if [[ ! -f "$BINARY" ]]; then
    echo "error: '$BINARY' does not exist" >&2
    exit 1
fi

if command -v smctl >/dev/null 2>&1; then
    # Mirrors the Windows Authenticode step's use of smctl (DigiCert
    # Software Trust Manager), but asks for a detached CMS signature
    # instead of embedding into a PE. Certificate alias/fingerprint is
    # intentionally left as a placeholder -- fill in from the same
    # DigiCert KeyLocker config used for Windows signing.
    echo "Signing '$BINARY' with smctl (detached CMS)..."
    smctl sign \
        --fingerprint "${DIGICERT_CERT_FINGERPRINT:?Set DIGICERT_CERT_FINGERPRINT to the EV cert's KeyLocker fingerprint}" \
        --input "$BINARY" \
        --output "$SIG_FILE" \
        --detached \
        --format cms
elif command -v openssl >/dev/null 2>&1; then
    # Fallback path: openssl cms against a PKCS#11-exposed KeyLocker
    # session. CERT_PEM/PKCS11_ENGINE_CONFIG must point at the actual
    # DigiCert-issued certificate and engine config on the signing host --
    # neither exists in this repo checkout.
    : "${CERT_PEM:?Set CERT_PEM to the path of the EV certificate's public cert (PEM)}"
    echo "Signing '$BINARY' with openssl cms (detached, DER)..."
    openssl cms -sign \
        -signer "$CERT_PEM" \
        -engine pkcs11 -keyform engine \
        -inkey "${PKCS11_KEY_URI:?Set PKCS11_KEY_URI to the KeyLocker PKCS#11 key URI}" \
        -in "$BINARY" \
        -binary \
        -outform DER \
        -out "$SIG_FILE" \
        -nosmimecap -noattr
else
    echo "error: neither smctl nor openssl found on PATH" >&2
    exit 1
fi

echo "Wrote detached signature: $SIG_FILE"

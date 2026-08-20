#!/usr/bin/env bash
# Signs a Linux test client binary with the dev cert produced by
# generate-dev-certs.sh, the same way tools/sign-linux-release.sh signs a
# real release binary with the company's EV cert. Run this from Linux (or
# WSL) against a binary built for Linux -- Authenticode/PE signing is a
# separate script (sign-windows-client.ps1).
#
# Usage:
#   tools/devcerts/sign-linux-client.sh <path-to-binary>
#
# Produces <path-to-binary>.sig (detached CMS/PKCS#7, DER), which
# LinuxIpcClientAuth.cpp / LinuxSerialBridgeListener.cs look for next to the
# binary at connection time.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="$REPO_ROOT/.devcerts"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <path-to-binary>" >&2
    exit 1
fi

BINARY="$1"

if [[ ! -f "$CERT_DIR/dev_signing.pem" || ! -f "$CERT_DIR/dev_signing.key" ]]; then
    echo "error: dev cert not found in $CERT_DIR -- run generate-dev-certs.sh first" >&2
    exit 1
fi

if [[ ! -f "$BINARY" ]]; then
    echo "error: '$BINARY' does not exist" >&2
    exit 1
fi

openssl cms -sign \
    -signer "$CERT_DIR/dev_signing.pem" \
    -inkey "$CERT_DIR/dev_signing.key" \
    -in "$BINARY" \
    -binary \
    -outform DER \
    -out "$BINARY.sig" \
    -nosmimecap -noattr

echo "Wrote detached signature: $BINARY.sig"

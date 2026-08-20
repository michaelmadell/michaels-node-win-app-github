#!/usr/bin/env bash
# Generates a throwaway dev CA + code-signing leaf certificate for locally
# exercising the authenticated serial IPC bridge (specs/001-secure-serial-ipc)
# without access to the company's real EV certificate.
#
# Output goes to .devcerts/ at the repo root -- gitignored, regenerate
# anytime, nothing here is precious. The private keys this script produces
# are NEVER committed (see .devcerts/README.md) -- only the public certs
# already baked into src/modules/serialpipe/certs/digicert_ca_chain.pem and
# csharp/src/CoreStationAgent/Ipc/digicert_ca_chain.pem are meant to be
# shared, and those are already checked in.
#
# The Subject fields below MUST match src/modules/serialpipe/TrustedIdentity.h
# and csharp/src/CoreStationAgent/Ipc/ClientAuthenticator.cs's
# TrustedSigningIdentity constants exactly, or a cert this script produces
# won't authenticate against the agent even once trusted.
#
# Usage:
#   tools/devcerts/generate-dev-certs.sh
#
# On Windows (Git Bash), path-looking arguments like "/CN=..." get mangled
# by MSYS's auto path-conversion -- this script sets MSYS_NO_PATHCONV=1
# itself so you don't have to remember it.

set -euo pipefail
export MSYS_NO_PATHCONV=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$REPO_ROOT/.devcerts"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Must match TrustedSigningIdentity in both TrustedIdentity.h and
# ClientAuthenticator.cs, field for field.
readonly SUBJECT_O="Amulet Hotkey Ltd (DEV TEST ONLY)"
readonly SUBJECT_OU="CoreStation Dev Signing"
readonly SUBJECT_CN="CoreStation Dev Code Signing (NOT FOR PRODUCTION)"
readonly CA_CN="CoreStation Dev Root CA (NOT FOR PRODUCTION)"
readonly CA_OU="CoreStation Dev CA"

echo "==> Generating dev root CA..."
openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
  -keyout dev_ca.key -out dev_ca.pem \
  -subj "/C=GB/O=${SUBJECT_O}/OU=${CA_OU}/CN=${CA_CN}"

echo "==> Generating dev code-signing leaf cert, issued by the dev CA..."
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout dev_signing.key -out dev_signing.csr \
  -subj "/C=GB/O=${SUBJECT_O}/OU=${SUBJECT_OU}/CN=${SUBJECT_CN}"

cat > dev_signing_ext.cnf <<'EOF'
[ext]
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=codeSigning
EOF

openssl x509 -req -in dev_signing.csr -CA dev_ca.pem -CAkey dev_ca.key -CAcreateserial \
  -out dev_signing.pem -days 1825 -sha256 -extfile dev_signing_ext.cnf -extensions ext

echo "==> Verifying chain..."
openssl verify -CAfile dev_ca.pem dev_signing.pem

echo "==> Exporting a PFX (Windows Authenticode signing needs one; password is a fixed dev-only value)..."
openssl pkcs12 -export -out dev_signing.pfx -inkey dev_signing.key -in dev_signing.pem \
  -certfile dev_ca.pem -passout pass:devtest123

echo
echo "Done. Output in $OUT_DIR (gitignored):"
echo "  dev_ca.pem        -- public CA cert. If you want THIS to become the shared trust anchor,"
echo "                        copy it over src/modules/serialpipe/certs/digicert_ca_chain.pem and"
echo "                        csharp/src/CoreStationAgent/Ipc/digicert_ca_chain.pem yourself and"
echo "                        commit that -- this script never does it for you."
echo "  dev_ca.key        -- CA private key. NEVER commit this."
echo "  dev_signing.pem   -- leaf (signer) public cert."
echo "  dev_signing.key   -- leaf private key. NEVER commit this."
echo "  dev_signing.pfx   -- leaf cert+key bundle for signtool.exe, password 'devtest123'."
echo "                        NEVER commit this either."
echo
echo "Next: sign-linux-client.sh or sign-windows-client.ps1 to sign a test client binary."

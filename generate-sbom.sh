#!/usr/bin/env bash
# Downloads syft/grype, generates SBOMs for the Debian build artifact,
# scans them for known vulnerabilities, and writes a report.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$REPO_ROOT/tools"
SPDX_OUT="$REPO_ROOT/sbom.spdx.json"
CYCLONE_OUT="$REPO_ROOT/sbom.cyclonedx.json"
REPORT_TXT="$REPO_ROOT/vulnerability-report.txt"
REPORT_JSON="$REPO_ROOT/vulnerability-report.json"
SKIP_BUILD="${SKIP_BUILD:-0}"

mkdir -p "$TOOLS_DIR"

install_tool() {
    local name="$1"
    if [ -x "$TOOLS_DIR/$name" ]; then
        echo "$name already present at $TOOLS_DIR/$name"
        return
    fi
    echo "Installing $name (official installer verifies its own checksum)..."
    curl -sSfL "https://raw.githubusercontent.com/anchore/$name/main/install.sh" | sh -s -- -b "$TOOLS_DIR"
}

install_tool syft
install_tool grype

SYFT="$TOOLS_DIR/syft"
GRYPE="$TOOLS_DIR/grype"

DEB_PATTERN="$REPO_ROOT/../corestationhxagent_*.deb"
DEB_PATH=""
for f in $DEB_PATTERN; do
    [ -e "$f" ] && DEB_PATH="$f"
done

if [ "$SKIP_BUILD" != "1" ] && [ -z "$DEB_PATH" ]; then
    echo "Building Debian package..."
    ( cd "$REPO_ROOT" && dpkg-buildpackage -us -uc -b )
    for f in $DEB_PATTERN; do
        [ -e "$f" ] && DEB_PATH="$f"
    done
fi

if [ -z "$DEB_PATH" ]; then
    echo "No .deb artifact found (and build was skipped or failed). Aborting." >&2
    exit 1
fi

SCAN_DIR="$(mktemp -d)"
trap 'rm -rf "$SCAN_DIR"' EXIT
cp "$DEB_PATH" "$SCAN_DIR/"
if [ -f "$REPO_ROOT/installer/CoreStationHXAgent.exe" ]; then
    cp "$REPO_ROOT/installer/CoreStationHXAgent.exe" "$SCAN_DIR/"
fi

echo "Generating SBOM from $(basename "$DEB_PATH")..."
"$SYFT" "$SCAN_DIR" -o "spdx-json=$SPDX_OUT" -o "cyclonedx-json=$CYCLONE_OUT" -o table

DISTRO_ID=""
DISTRO_VER=""
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-}"
    DISTRO_VER="${VERSION_ID:-}"
fi

GRYPE_ARGS=(sbom:"$CYCLONE_OUT")
if [ -n "$DISTRO_ID" ] && [ -n "$DISTRO_VER" ]; then
    GRYPE_ARGS+=(--distro "${DISTRO_ID}:${DISTRO_VER}")
fi

echo "Scanning SBOM for known vulnerabilities..."
"$GRYPE" "${GRYPE_ARGS[@]}" -o table | tee "$REPORT_TXT"
"$GRYPE" "${GRYPE_ARGS[@]}" -o json > "$REPORT_JSON"

echo ""
echo "Done."
echo "  SBOM (SPDX):      $SPDX_OUT"
echo "  SBOM (CycloneDX): $CYCLONE_OUT"
echo "  Report (text):    $REPORT_TXT"
echo "  Report (json):    $REPORT_JSON"
echo ""
echo "Note: this SBOM only covers the shipped artifact itself (no exploded"
echo "third-party dependency versions), so the vuln scan may show little/nothing."
echo "For real CVE coverage of runtime deps (libdbus-1-3, network-manager, ...),"
echo "scan an installed target instead (e.g. syft against /var/lib/dpkg on a box"
echo "with the package actually installed, then grype --distro <id>:<version>)."

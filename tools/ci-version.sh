#!/usr/bin/env bash
# Extracts the CoreStationHXAgent version string from src/version.h, mirroring
# the parsing logic in CMakeLists.txt. Meant to be sourced by CI:
#   source tools/ci-version.sh
# Sets: APP_VERSION (e.g. 20.26.8.1_rc1), APP_VERSION_SHORT (e.g. 20.26.8.1)
set -e

VERSION_FILE="${1:-src/version.h}"

VERSION_MAJOR=$(grep -oP '(?<=#define VERSION_MAJOR )\d+' "$VERSION_FILE")
VERSION_MINOR=$(grep -oP '(?<=#define VERSION_MINOR )\d+' "$VERSION_FILE")
VERSION_RELEASE=$(grep -oP '(?<=#define VERSION_RELEASE )\d+' "$VERSION_FILE")
VERSION_BUILD=$(grep -oP '(?<=#define VERSION_BUILD )\d+' "$VERSION_FILE")
VERSION_EXTRAVERSION=$(grep -oP '(?<=#define VERSION_EXTRAVERSION ")[a-zA-Z]+' "$VERSION_FILE")
VERSION_RC_NO=$(grep -oP '(?<=#define VERSION_RC_NO )\d+' "$VERSION_FILE" || echo "")

APP_VERSION_SHORT="${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_RELEASE}.${VERSION_BUILD}"

if [ "$VERSION_EXTRAVERSION" = "rc" ]; then
    APP_VERSION="${APP_VERSION_SHORT}_${VERSION_EXTRAVERSION}${VERSION_RC_NO}"
else
    APP_VERSION="${APP_VERSION_SHORT}_${VERSION_EXTRAVERSION}"
fi

export APP_VERSION
export APP_VERSION_SHORT

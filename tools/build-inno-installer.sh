#!/usr/bin/env bash
# Builds the Inno Setup installer under Wine on Linux CI (GitHub Actions and
# Bitbucket Pipelines both call this - keeps the apt/wine/ISCC steps in one
# place instead of duplicated across two YAML files).
#
# Expects CoreStationHXAgent.exe already built at build-win/bin/CoreStationHXAgent.exe
# (see cmake/mingw-w64-toolchain.cmake). Requires APP_VERSION / APP_VERSION_SHORT
# in the environment (source tools/ci-version.sh first).
#
# CoreStationAppInstaller.iss expects install.ps1/CoreStationHXAgent.exe/remove.ps1
# at the repo root (Source: ".\..."  is relative to the .iss file's own location,
# not to installer/ where these actually live) - this script stages copies at
# root and removes them again on exit.
set -euo pipefail

: "${APP_VERSION:?source tools/ci-version.sh first}"
: "${APP_VERSION_SHORT:?source tools/ci-version.sh first}"

INNO_URL="https://github.com/jrsoftware/issrc/releases/download/is-6_7_3/innosetup-6.7.3.exe"
INNO_DIR="$HOME/.wine/drive_c/Inno"
ISCC="$INNO_DIR/ISCC.exe"

# GitHub's ubuntu-latest runs as a non-root user with passwordless sudo;
# Bitbucket's ubuntu:24.04 image runs the step as root with no sudo binary.
SUDO=""
if [ "$(id -u)" != "0" ]; then
    SUDO="sudo"
fi

if [ ! -f "$ISCC" ]; then
    echo "Installing Wine + Inno Setup (one-time per runner)..."
    $SUDO dpkg --add-architecture i386
    $SUDO apt-get update
    $SUDO apt-get install -y wine wine32 xvfb wget curl

    curl -fsSL "$INNO_URL" -o /tmp/innosetup.exe
    xvfb-run -a wine /tmp/innosetup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- "/DIR=C:\\Inno"
fi

cleanup() {
    rm -f install.ps1 remove.ps1 CoreStationHXAgent.exe
}
trap cleanup EXIT

cp installer/install.ps1 install.ps1
cp installer/remove.ps1 remove.ps1
cp build-win/bin/CoreStationHXAgent.exe CoreStationHXAgent.exe

xvfb-run -a wine "$ISCC" \
    "/DMyAppVersion=${APP_VERSION}" \
    "/DMyAppVersionShort=${APP_VERSION_SHORT}" \
    CoreStationAppInstaller.iss

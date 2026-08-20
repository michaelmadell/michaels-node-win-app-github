# Authenticode-signs a Windows test client binary with the dev cert produced
# by generate-dev-certs.sh (the .pfx it exports), using the real
# signtool.exe from an installed Windows SDK -- so the signature this
# produces is exercised by WindowsIpcClientAuth.cpp / the C# agent's
# WinVerifyTrust P/Invoke exactly the way a real Authenticode signature
# would be, not a simulation.
#
# Usage:
#   .\tools\devcerts\sign-windows-client.ps1 -BinaryPath .\some_test_client.exe

param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$certDir = Join-Path $repoRoot ".devcerts"
$pfx = Join-Path $certDir "dev_signing.pfx"

if (-not (Test-Path $pfx)) {
    Write-Error "Dev cert not found at $pfx -- run generate-dev-certs.sh first."
    exit 1
}

if (-not (Test-Path $BinaryPath)) {
    Write-Error "'$BinaryPath' does not exist."
    exit 1
}

# signtool.exe isn't reliably on PATH -- search installed Windows Kits, most
# recent first, same as a developer would via a "Developer Command Prompt".
$signtool = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\10\bin" `
    -Filter "signtool.exe" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -like "*x64*" } |
    Sort-Object FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $signtool) {
    Write-Error "signtool.exe not found under Windows Kits 10 -- install the Windows SDK."
    exit 1
}

& $signtool sign /f $pfx /p devtest123 /fd SHA256 /t http://timestamp.digicert.com $BinaryPath
if ($LASTEXITCODE -ne 0) {
    Write-Error "signtool failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

Write-Host "Signed: $BinaryPath"

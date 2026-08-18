#!PowerShell

$ErrorActionPreference = "Stop"

Write-Host "Building CoreStationHXAgent (Windows) ..." -ForegroundColor Green

cargo build --release

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed." -ForegroundColor Red
    exit $LASTEXITCODE
}

$ExePath = ".\target\release\CoreStationHXAgent.exe"
if (-Not (Test-Path $ExePath)) {
    Write-Host "Executable not found at $ExePath" -ForegroundColor Red
    exit 1
}

Write-Host "Packaging with Inno Setup..." -ForegroundColor Green
$InnoCompiler = "C:\Users\michael.madell\AppData\Local\Programs\Inno Setup 7\ISCC.exe"

$InnoScript = ".\installer.iss"

if (-Not (Test-Path $InnoCompiler)) {
    Write-Host "Inno Setup Compiler not found at $InnoCompiler" -ForegroundColor Red
    exit 1
}

if (-Not (Test-Path $InnoScript)) {
    Write-Host "Inno Setup script not found at $InnoScript" -ForegroundColor Red
    exit 1
}

& $InnoCompiler $InnoScript

if ($LASTEXITCODE -ne 0) {
    Write-Host "Inno Setup packaging failed." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Build and packaging completed successfully." -ForegroundColor Green
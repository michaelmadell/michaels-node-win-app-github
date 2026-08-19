# Registers Windows Error Reporting LocalDumps for CoreStationHXAgent.exe so
# ANY unhandled exception in the real installed binary — however it's
# triggered (serial fuzzing, pipe fuzzing, CLI fuzzing, or just customer use)
# — drops a full minidump we can open in WinDbg/Visual Studio. The app has
# no SetUnhandledExceptionFilter/MiniDumpWriteDump of its own, so without
# this a crash just silently vanishes (service restarts, or Explorer shows
# "has stopped working" and the dump goes wherever WER's default policy
# sends it, which may not be locally accessible).
#
# Run elevated. Safe to leave enabled permanently; --remove undoes it.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File setup_crash_dumps.ps1
#   powershell -ExecutionPolicy Bypass -File setup_crash_dumps.ps1 -Remove
#   powershell -ExecutionPolicy Bypass -File setup_crash_dumps.ps1 -DumpFolder D:\fuzz-dumps

param(
    [switch]$Remove,
    [string]$DumpFolder = "$PSScriptRoot\crash_dumps",
    [string]$ExeName = "CoreStationHXAgent.exe"
)

$ErrorActionPreference = "Stop"
$key = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\$ExeName"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this elevated (Administrator PowerShell) — it writes under HKLM."
    exit 1
}

if ($Remove) {
    if (Test-Path $key) {
        Remove-Item -Path $key -Recurse -Force
        Write-Host "Removed LocalDumps registration for $ExeName."
    } else {
        Write-Host "No LocalDumps registration found for $ExeName — nothing to do."
    }
    exit 0
}

New-Item -Path $DumpFolder -ItemType Directory -Force | Out-Null
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name "DumpFolder" -PropertyType ExpandString -Value $DumpFolder -Force | Out-Null
New-ItemProperty -Path $key -Name "DumpCount" -PropertyType DWord -Value 50 -Force | Out-Null
New-ItemProperty -Path $key -Name "DumpType" -PropertyType DWord -Value 2 -Force | Out-Null   # 2 = full dump (1 = mini)

Write-Host "LocalDumps registered for $ExeName -> $DumpFolder (full dumps, keep last 50)."
Write-Host "Every crash — service, tray helper, interactive — now lands here regardless of which fuzz script triggered it."

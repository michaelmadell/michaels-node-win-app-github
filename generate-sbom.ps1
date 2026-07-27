#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads syft/grype, generates SBOMs for the Windows build artifact,
    scans them for known vulnerabilities, and writes a report.
#>
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoRoot     = $PSScriptRoot
$ToolsDir     = Join-Path $RepoRoot "tools"
$InstallerDir = Join-Path $RepoRoot "installer"
$SpdxOut      = Join-Path $RepoRoot "sbom.spdx.json"
$CycloneOut   = Join-Path $RepoRoot "sbom.cyclonedx.json"
$ReportTxt    = Join-Path $RepoRoot "vulnerability-report.txt"
$ReportJson   = Join-Path $RepoRoot "vulnerability-report.json"

New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

function Install-AnchoreTool {
    param(
        [Parameter(Mandatory)][string]$Name,   # "syft" or "grype"
        [Parameter(Mandatory)][string]$Repo    # "anchore/syft" etc
    )

    $exePath = Join-Path $ToolsDir "$Name.exe"
    if (Test-Path $exePath) {
        Write-Host "$Name already present at $exePath"
        return $exePath
    }

    Write-Host "Fetching latest $Name release metadata..."
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "sbom-script" }

    $zipAsset  = $release.assets | Where-Object { $_.name -match "^${Name}_.*_windows_amd64\.zip$" } | Select-Object -First 1
    $sumsAsset = $release.assets | Where-Object { $_.name -match "^${Name}_.*_checksums\.txt$" } | Select-Object -First 1
    if (-not $zipAsset) {
        throw "Could not find a windows_amd64 zip asset for $Name in the latest $Repo release"
    }

    $zipPath = Join-Path $ToolsDir $zipAsset.name
    Write-Host "Downloading $($zipAsset.name)..."
    Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zipPath -UseBasicParsing

    if ($sumsAsset) {
        Write-Host "Verifying checksum..."
        $sumsPath = Join-Path $ToolsDir $sumsAsset.name
        Invoke-WebRequest -Uri $sumsAsset.browser_download_url -OutFile $sumsPath -UseBasicParsing
        $expectedLine = Select-String -Path $sumsPath -Pattern $zipAsset.name -SimpleMatch
        if (-not $expectedLine) {
            throw "Checksum entry not found for $($zipAsset.name)"
        }
        $expectedHash = ($expectedLine.Line -split '\s+')[0].ToUpper()
        $actualHash   = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToUpper()
        if ($expectedHash -ne $actualHash) {
            throw "Checksum mismatch for $($zipAsset.name): expected $expectedHash, got $actualHash"
        }
        Remove-Item $sumsPath -Force
        Write-Host "Checksum OK."
    } else {
        Write-Warning "No checksums file found for $Name release; skipping verification."
    }

    $extractDir = Join-Path $ToolsDir "${Name}_extract"
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    Copy-Item -Path (Join-Path $extractDir "$Name.exe") -Destination $exePath -Force
    Remove-Item -Path $extractDir -Recurse -Force
    Remove-Item -Path $zipPath -Force

    return $exePath
}

$syft  = Install-AnchoreTool -Name "syft"  -Repo "anchore/syft"
$grype = Install-AnchoreTool -Name "grype" -Repo "anchore/grype"

$exeExists = Test-Path (Join-Path $InstallerDir "CoreStationHXAgent.exe")
if (-not $SkipBuild -and -not $exeExists) {
    Write-Host "Building Windows release binary..."
    # pushd handles UNC-path working directories that cmd.exe otherwise rejects
    cmd.exe /c "pushd `"$RepoRoot`" && build.bat"
    if ($LASTEXITCODE -ne 0) { throw "build.bat failed" }
}

if (-not (Test-Path $InstallerDir)) {
    throw "installer\ not found - nothing to scan. Run build.bat first, or drop artifacts in installer\."
}

Write-Host "Generating SBOM from $InstallerDir..."
& $syft $InstallerDir -o "spdx-json=$SpdxOut" -o "cyclonedx-json=$CycloneOut" -o "table"
if ($LASTEXITCODE -ne 0) { throw "syft scan failed" }

Write-Host "Scanning SBOM for known vulnerabilities..."
& $grype "sbom:$CycloneOut" -o table | Tee-Object -FilePath $ReportTxt
& $grype "sbom:$CycloneOut" -o json | Out-File -Encoding utf8 $ReportJson

Write-Host ""
Write-Host "Done."
Write-Host "  SBOM (SPDX):      $SpdxOut"
Write-Host "  SBOM (CycloneDX): $CycloneOut"
Write-Host "  Report (text):    $ReportTxt"
Write-Host "  Report (json):    $ReportJson"
Write-Host ""
Write-Host "Note: this SBOM only covers the shipped artifact itself (no exploded" -ForegroundColor Yellow
Write-Host "third-party dependency versions), so the vuln scan may show little/nothing." -ForegroundColor Yellow
Write-Host "For real CVE coverage of runtime deps, scan an installed target instead." -ForegroundColor Yellow

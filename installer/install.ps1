<#
.SYNOPSIS
    Installs and starts the CoreStation service.
.DESCRIPTION
    This script installs the CoreStation service from its executable. It must be run with
    Administrator privileges. If the service already exists, it will be cleanly removed
    before the new version is installed. The script also configures the service to restart
    automatically on failure and then starts it.
.PARAMETER ServiceName
    The name for the new service.
.PARAMETER ExePath
    The full path to the service's executable file. Defaults to 'nodeWinApp.exe' in the same
    directory as the script.
.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -ServiceName "MyTestService" -ExePath "C:\Path\To\My.exe"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter()]
    [string]$ServiceName = "CoreStationService",

    [Parameter()]
    [string]$ExePath = "$PSScriptRoot\nodeWinApp.exe"
)

# 1. Verify the script is running with Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Please open a new PowerShell terminal with 'Run as Administrator'."
    exit 1
}

# 2. Verify the executable file exists before we begin
if (-not (Test-Path -Path $ExePath -PathType Leaf)) {
    Write-Error "The service executable was not found at the expected location: '$ExePath'"
    exit 1
}

Write-Host "Starting installation for service: '$ServiceName'..."

try {
    # 3. Check for and remove any existing version of the service for a clean install
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $existingService) {
        Write-Host "An existing service named '$ServiceName' was found. Removing it first."
        
        if ($existingService.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force
            Wait-Service -Name $ServiceName -Timeout 30
        }
        
        sc.exe delete $ServiceName | Out-Null
        
        # Verify removal to prevent conflicts
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($stopwatch.Elapsed.TotalSeconds -lt 15) {
            if ($null -eq (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
                $stopwatch.Stop(); break
            }
            Start-Sleep -Seconds 1
        }
        if ($stopwatch.IsRunning) {
            throw "Timed out waiting for the existing service to be deleted."
        }
        Write-Host "Existing service removed successfully."
    }

    Copy-Item -Path $ExePath -Destination "C:\ProgramData\ahk"

    $NewExePath = "C:\ProgramData\ahk\nodeWinApp.exe"

    # 4. Create the new service
    Write-Host "Creating new service from executable: '$NewExePath'..."
    New-Service -Name $ServiceName `
                -BinaryPathName $NewExePath `
                -DisplayName "CoreStation HX Agent" `
                -StartupType Automatic `
                -Description "Passes network, session, and power status to the CoreStation management controller."
    
    # 5. Configure service recovery options
    Write-Host "Configuring service recovery options..."
    # On failure, restart after 1s, then 2s, then 5s for any subsequent failures.
    sc.exe failure $ServiceName reset= 0 actions= restart/1000/restart/2000/restart/5000 | Out-Null
    
    # 6. Start the service
    if ($pscmdlet.ShouldProcess($ServiceName, "Start Service")) {
        Write-Host "Starting service..."
        Start-Service -Name $ServiceName
    }

    Write-Host "Service '$ServiceName' installed and started successfully." -ForegroundColor Green
}
catch {
    Write-Error "An error occurred during installation: $_"
    # If the script fails, try to clean up the partially installed service
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Warning "Attempting to clean up partially installed service..."
        sc.exe delete $ServiceName | Out-Null
    }
    exit 1
}
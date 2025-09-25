<#
.SYNOPSIS
    Stops and removes a specified Windows service.
.DESCRIPTION
    This script uninstalls a Windows service from the system. It must be run with
    Administrator privileges. It will first stop the service if it is running,
    then delete it, and finally verify that it has been removed.
.PARAMETER ServiceName
    The name of the service you want to remove.
.EXAMPLE
    .\remove.ps1 -ServiceName "CoreStationService"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$ServiceName = "CoreStationService"
)

# 1. Verify the script is running with Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Please open a new PowerShell terminal with 'Run as Administrator'."
    exit 1
}

Write-Host "Attempting to remove service: '$ServiceName'..."

try {
    # 2. Check if the service actually exists
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($null -eq $service) {
        Write-Host "Service '$ServiceName' does not exist. No action needed." -ForegroundColor Green
        exit 0
    }

    # 3. Stop the service if it's not already stopped
    if ($service.Status -ne 'Stopped') {
        Write-Host "Service status is '$($service.Status)'. Stopping the service..."
        Stop-Service -Name $ServiceName -Force
        
        # --- MODIFIED BLOCK ---
        # Manually wait for the service to stop, since Wait-Service is not available
        Write-Host "Waiting for service to stop..."
        $timeout = 30 # seconds
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        while ($service.Status -ne 'Stopped') {
            if ($stopwatch.Elapsed.TotalSeconds -gt $timeout) {
                throw "Timed out waiting for service '$ServiceName' to stop."
            }
            Start-Sleep -Seconds 1
            $service.Refresh() # Get the latest service status
        }
        # --- END MODIFIED BLOCK ---
    }

    # 4. Delete the service
    Write-Host "Deleting service..."
    sc.exe delete $ServiceName | Out-Null
    
    # 5. Verify the service has been removed
    Write-Host "Verifying service removal..."
    $maxWaitSeconds = 15
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($stopwatch.Elapsed.TotalSeconds -lt $maxWaitSeconds) {
        if ($null -eq (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            $stopwatch.Stop()
            Write-Host "[✓] Service '$ServiceName' was successfully removed." -ForegroundColor Green
            exit 0
        }
        Start-Sleep -Seconds 1
    }
    
    throw "Timed out waiting for '$ServiceName' to be deleted. Please check 'services.msc' manually."

}
catch {
    Write-Error "[✕] An error occurred during service removal: $_"
    exit 1
}
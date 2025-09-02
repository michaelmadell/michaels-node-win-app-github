<#
.SYNOPSIS
    Stops and removes a specified windows service
.DESCRIPTION
    This script uninstalls a windows service from the system. It must be run with
    Administrator privileges. It will first stop the service if it is running,
    then delete it, and finally verify it has been removed
.PARAMETER ServiceName
    Name of the service you want to remove
.EXAMPLE
    .\remove.ps1 -ServiceName "CoreStationService"
#>
[CmdletBinding()]
param (
    [Parameter()]
    [string]$ServiceName = "CoreStationService"
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Please open a new PowerShell terminal with 'Run as Administrator'."
    exit 1
}

Write-Host "Attempting to remove service: '$ServiceName'..."

try {
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

    Write-Host "Deleting Service..."
    sc.exe delete $ServiceName | Out-Null

    Write-Host "Verifying service removal..."
    $maxWaitSeconds = 15
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($stopwatch.Elapsed.TotalSeconds -lt $maxWaitSeconds) {
        if ($null -eq (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
            $stopwatch.Stop()
            Write-Host "Service '$ServiceName' was successfully removed." -ForegroundColor Green
            exit 0
        }
        Start-Sleep -Seconds 1
    }

    throw "Timed out waiting for '$ServiceName' to be deleted. Please check 'services.msc' manually."
}
catch {
    Write-Error "An error occurred during service removal: $_"
    exit 1
}


# # This PowerShell  script will install the app as a Windows 11 service
# # install.ps1

# # Check for admin rights
# if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
#     Write-Host "This script must be run as Administrator." -ForegroundColor Red
#     exit 1
# }

# $serviceName = "CoreStationService"

# Write-Host "Installing $serviceName..."
# $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
# if ($existingService) {
#     Write-Host "Service $serviceName already exists. Stopping and deleting..."
#     Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
#     sc.exe delete $serviceName | Out-Null

#     # Wait until the service is truly gone
#     $maxWait = 15
#     $elapsed = 0
#     while (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
#         Start-Sleep -Seconds 1
#         $elapsed++
#         if ($elapsed -ge $maxWait) {
#             throw "Timed out waiting for $serviceName to be deleted."
#         }
#     }
#     Write-Host "$serviceName successfully deleted."
# }
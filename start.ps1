# Start CoreStationService

$serviceName = "CoreStationService"

# Check for admin rights, relaunch as admin if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {

    Write-Output "Restarting script with administrator privileges..."

    $currentDir = Convert-Path .
    $script = "`"$PSCommandPath`""
    
    $arguments = "-NoExit -ExecutionPolicy Bypass -Command `"Set-Location '$currentDir'; & $script`""

    Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
    exit
}

# Actual logic
try {
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        Start-Service -Name $serviceName 
        Write-Output "Service '$serviceName' started successfully."
    } else {
        Write-Output "Service '$serviceName' is already running."
    }
} catch {
    Write-Error "Failed to start service '$serviceName': $_"
}

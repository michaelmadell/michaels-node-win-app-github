# Stop CoreStationService

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

$serviceName = "CoreStationService"

try {
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        Write-Output "Service '$serviceName' stopped successfully."
    } else {
        Write-Output "Service '$serviceName' is already stopped."
    }
} catch {
    Write-Error "Failed to stop service '$serviceName': $_"
}

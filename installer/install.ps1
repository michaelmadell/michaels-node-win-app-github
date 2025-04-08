# This PowerShell  script will install the app as a Windows 11 service
# Before deploying it can be tested localy by running   
#    Set-ExecutionPolicy Bypass -Scope Process
#    .\install.ps1





# install.ps1
$serviceName = "CoreStationService"
$exePath = "$PSScriptRoot\nodeWinApp.exe"

Write-Host "Installing $serviceName..."

# Check if service already exists
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Write-Host "Service $serviceName already exists. Attempting to remove it..."
    sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create the service
New-Service -Name $serviceName `
            -BinaryPathName "`"$exePath`"" `
            -DisplayName "Core Station Service" `
            -StartupType Automatic `
            -Description "Pass network, session and power status to CoreStation management contoller " `
            -ErrorAction Stop

# Set service recovery options (restart on failure 1st/2nd/3rd+ time in ms)
sc.exe failure $serviceName reset= 0 actions= restart/1000/restart/2000/restart/5000

# Start the service
Start-Service -Name $serviceName

Write-Host "$serviceName installed and started successfully."

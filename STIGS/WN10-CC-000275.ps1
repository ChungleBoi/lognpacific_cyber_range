<#
.SYNOPSIS
    Prevent Local Drives from Sharing with Remote Desktop Session Hosts.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-10
    Last Modified   : 2025-08-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000275

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000275.ps1 
#>

Write-Host "=== WN10-CC-000275: Preventing Drive Redirection in Remote Desktop Sessions ===" -ForegroundColor Green

try {
    # Registry path for Terminal Services settings
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "fDisableCdm"
    $regValue = 1
    
    # Create the registry path if it doesn't exist
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
        Write-Host "Created registry path: $regPath" -ForegroundColor Yellow
    }
    
    # Set the registry value to disable drive redirection
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord
    
    # Verify the setting
    $currentValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    
    if ($currentValue.$regName -eq 1) {
        Write-Host "SUCCESS: Drive redirection for Remote Desktop Sessions has been disabled." -ForegroundColor Green
        Write-Host "Registry setting: $regPath\$regName = $($currentValue.$regName)" -ForegroundColor Green
    } else {
        Write-Host "WARNING: Failed to verify drive redirection disable setting." -ForegroundColor Red
    }
    
    # Additional information
    Write-Host "`nConfiguration Details:" -ForegroundColor Cyan
    Write-Host "  Policy: Computer Configuration >> Administrative Templates >> Windows Components" -ForegroundColor Yellow
    Write-Host "          >> Remote Desktop Services >> Remote Desktop Session Host" -ForegroundColor Yellow
    Write-Host "          >> Device and Resource Redirection >> 'Do not allow drive redirection'" -ForegroundColor Yellow
    Write-Host "  Status: ENABLED" -ForegroundColor Yellow
    
    # Note about Group Policy refresh
    Write-Host "`nNOTE: Changes will take effect immediately for new RDP sessions." -ForegroundColor Yellow
    Write-Host "      Existing RDP sessions may need to be disconnected and reconnected." -ForegroundColor Yellow
}
catch {
    Write-Host "ERROR: Failed to disable drive redirection - $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== STIG WN10-CC-000275 Remediation Complete ===" -ForegroundColor Cyan

# Optional: Force Group Policy refresh
$refreshGP = Read-Host "`nWould you like to force a Group Policy refresh? (y/n)"
if ($refreshGP -eq 'y' -or $refreshGP -eq 'Y') {
    try {
        Start-Process "gpupdate" -ArgumentList "/force" -Wait -NoNewWindow
        Write-Host "Group Policy refresh completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to refresh Group Policy: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "You can manually run: gpupdate /force" -ForegroundColor Yellow
    }
}

<#
.SYNOPSIS
    The user must be prompted for a password on resume from sleep (plugged in)

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-06
    Last Modified   : 2025-08-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000150

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000150.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$ValueName = "ACSettingIndex"
$ValueData = 1
$ValueType = "DWord"

Write-Host "WN10-CC-000150 Remediation: Password Required on Resume from Sleep (Plugged In)" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

try {
    # Check if the registry path exists
    if (-not (Test-Path $RegistryPath)) {
        Write-Host "Registry path does not exist. Creating: $RegistryPath" -ForegroundColor Yellow
        New-Item -Path $RegistryPath -Force | Out-Null
        Write-Host "Successfully created registry path." -ForegroundColor Green
    } else {
        Write-Host "Registry path already exists." -ForegroundColor Green
    }
    
    # Get current value for comparison
    $CurrentValueBefore = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($CurrentValueBefore) {
        Write-Host "Current value before change: $($CurrentValueBefore.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Host "Value did not exist before." -ForegroundColor Gray
    }
    
    # Set the registry value
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type $ValueType
    Write-Host "Successfully set $ValueName to $ValueData" -ForegroundColor Green
    
    # Verify the value was set correctly
    $CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($CurrentValue.$ValueName -eq $ValueData) {
        Write-Host "✓ Verification successful: STIG WN10-CC-000150 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
    # Check if the companion setting (battery) is also configured
    $DCValue = Get-ItemProperty -Path $RegistryPath -Name "DCSettingIndex" -ErrorAction SilentlyContinue
    if ($DCValue -and $DCValue.DCSettingIndex -eq 1) {
        Write-Host "✓ Companion setting (WN10-CC-000145 - Battery) is also configured" -ForegroundColor Green
    } else {
        Write-Host "⚠ Note: Consider also configuring WN10-CC-000145 (Battery setting)" -ForegroundColor Yellow
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000150" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Users will be prompted for password when resuming from sleep on AC power" -ForegroundColor Gray

Write-Host "`nRelated Settings:" -ForegroundColor Cyan
Write-Host "• WN10-CC-000145: Password on resume from sleep (Battery) - DCSettingIndex" -ForegroundColor Gray
Write-Host "• WN10-CC-000150: Password on resume from sleep (Plugged In) - ACSettingIndex" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Do not require a password (Not STIG Compliant)" -ForegroundColor Red
Write-Host "• 1 = Require a password (STIG Compliant)" -ForegroundColor Green

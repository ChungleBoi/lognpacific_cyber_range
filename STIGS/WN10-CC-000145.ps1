<#
.SYNOPSIS
    Authentication must always be required when accessing a system. This setting ensures the user is prompted for a password on resume from sleep (on battery).

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-05
    Last Modified   : 2025-08-05
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000145

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000145.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$ValueName = "DCSettingIndex"
$ValueData = 1
$ValueType = "DWord"

Write-Host "WN10-CC-000145 Remediation: Password Required on Resume from Sleep (Battery)" -ForegroundColor Cyan
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
    
    # Set the registry value
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type $ValueType
    Write-Host "Successfully set $ValueName to $ValueData" -ForegroundColor Green
    
    # Verify the value was set correctly
    $CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($CurrentValue.$ValueName -eq $ValueData) {
        Write-Host "✓ Verification successful: STIG WN10-CC-000145 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000145" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Note: Users will now be prompted for password when resuming from sleep on battery power" -ForegroundColor Gray

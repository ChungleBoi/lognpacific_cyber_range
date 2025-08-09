<#
.SYNOPSIS
     Automatically signing in the last interactive user after a system-initiated restart must be disabled.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000325

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000325.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "DisableAutomaticRestartSignOn"
$ValueData = 1
$ValueType = "DWord"

Write-Host "WN10-CC-000325 Remediation: Disable Automatic Restart Sign-On" -ForegroundColor Cyan
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
        if ($CurrentValueBefore.$ValueName -eq 1) {
            Write-Host "  Current status: Automatic restart sign-on is already disabled" -ForegroundColor Green
        } else {
            Write-Host "  Current status: Automatic restart sign-on is enabled (NOT STIG COMPLIANT)" -ForegroundColor Red
        }
    } else {
        Write-Host "Value did not exist before." -ForegroundColor Gray
    }
    
    # Set the registry value
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type $ValueType
    Write-Host "Successfully set $ValueName to $ValueData" -ForegroundColor Green
    
    # Verify the value was set correctly
    $CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($CurrentValue.$ValueName -eq $ValueData) {
        Write-Host "✓ Verification successful: STIG WN10-CC-000325 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000325" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Automatic restart sign-on is now disabled" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents automatic credential caching for restart scenarios" -ForegroundColor Gray
Write-Host "• Ensures users are aware when system restarts occur" -ForegroundColor Gray
Write-Host "• Requires explicit user authentication after system-initiated restarts" -ForegroundColor Gray
Write-Host "• Reduces risk of unauthorized access during restart cycles" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Allow automatic restart sign-on (NOT STIG Compliant)" -ForegroundColor Red
Write-Host "• 1 = Disable automatic restart sign-on (STIG Compliant)" -ForegroundColor Green

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• Change takes effect after next system restart" -ForegroundColor Gray
Write-Host "• Users must manually sign in after Windows Updates and restarts" -ForegroundColor Gray

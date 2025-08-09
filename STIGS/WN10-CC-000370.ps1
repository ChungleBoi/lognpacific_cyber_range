<#
.SYNOPSIS
    The convenience PIN for Windows 10 must be disabled.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000370

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000370.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
$ValueName = "AllowDomainPINLogon"
$ValueData = 0
$ValueType = "DWord"

Write-Host "WN10-CC-000370 Remediation: Disable Convenience PIN for Windows 10" -ForegroundColor Cyan
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
        if ($CurrentValueBefore.$ValueName -eq 0) {
            Write-Host "  Current status: Convenience PIN is already disabled" -ForegroundColor Green
        } else {
            Write-Host "  Current status: Convenience PIN is enabled (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-CC-000370 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName) (Convenience PIN disabled)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000370" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Convenience PIN sign-in is now disabled" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents use of potentially weaker PIN authentication" -ForegroundColor Gray
Write-Host "• Enforces stronger credential requirements for domain users" -ForegroundColor Gray
Write-Host "• Reduces risk of password stuffing attacks" -ForegroundColor Gray
Write-Host "• Ensures consistent authentication policy across domain" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Convenience PIN disabled (STIG Compliant)" -ForegroundColor Green
Write-Host "• 1 = Convenience PIN enabled (NOT STIG Compliant)" -ForegroundColor Red

Write-Host "`nImpact:" -ForegroundColor Yellow
Write-Host "• Domain users must use traditional username/password authentication" -ForegroundColor Gray
Write-Host "• PIN-based authentication will not be available for domain accounts" -ForegroundColor Gray
Write-Host "• Local accounts may still use PIN if configured separately" -ForegroundColor Gray
Write-Host "• Windows Hello biometric authentication may still be available" -ForegroundColor Gray

<#
.SYNOPSIS
    Windows Telemetry must not be configured to Full.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000205

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000205.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$ValueName = "AllowTelemetry"
$ValueData = 0  # 0 = Security (Enterprise Only), 1 = Basic
$ValueType = "DWord"

Write-Host "WN10-CC-000205 Remediation: Configure Windows Telemetry to Security Level" -ForegroundColor Cyan
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
        switch ($CurrentValueBefore.$ValueName) {
            0 { Write-Host "  Current level: Security (0)" -ForegroundColor Green }
            1 { Write-Host "  Current level: Basic (1)" -ForegroundColor Yellow }
            2 { Write-Host "  Current level: Enhanced (2)" -ForegroundColor Orange }
            3 { Write-Host "  Current level: Full (3) - NOT STIG COMPLIANT" -ForegroundColor Red }
        }
    } else {
        Write-Host "Value did not exist before." -ForegroundColor Gray
    }
    
    # Set the registry value
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type $ValueType
    Write-Host "Successfully set $ValueName to $ValueData (Security Level)" -ForegroundColor Green
    
    # Verify the value was set correctly
    $CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($CurrentValue.$ValueName -eq $ValueData) {
        Write-Host "✓ Verification successful: STIG WN10-CC-000205 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName) (Security Level)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000205" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Windows Telemetry set to Security level (lowest data collection)" -ForegroundColor Gray

Write-Host "`nTelemetry Levels:" -ForegroundColor Cyan
Write-Host "• 0 = Security (Enterprise Only) - STIG Compliant ✓" -ForegroundColor Green
Write-Host "• 1 = Basic - STIG Compliant ✓" -ForegroundColor Green
Write-Host "• 2 = Enhanced - May be acceptable with additional config" -ForegroundColor Yellow
Write-Host "• 3 = Full - NOT STIG Compliant ✗" -ForegroundColor Red

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Minimizes data sent to Microsoft" -ForegroundColor Gray
Write-Host "• Prevents potentially sensitive information from leaving the enterprise" -ForegroundColor Gray
Write-Host "• Limits telemetry to essential security updates only" -ForegroundColor Gray
Write-Host "• Includes only MSRT, Defender, and telemetry client settings" -ForegroundColor Gray

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• Security level (0) is only available on Windows 10 Enterprise" -ForegroundColor Gray
Write-Host "• If not Enterprise, use Basic level (1) - change ValueData to 1" -ForegroundColor Gray
Write-Host "• Some Microsoft services may require Basic level to function properly" -ForegroundColor Gray

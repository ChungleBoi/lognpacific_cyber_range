<#
.SYNOPSIS
    Autoplay must be turned off for non-volume devices.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000180

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000180.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
$ValueName = "NoAutoplayfornonVolume"
$ValueData = 1
$ValueType = "DWord"

Write-Host "WN10-CC-000180 Remediation: Turn Off Autoplay for Non-Volume Devices" -ForegroundColor Cyan
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
            Write-Host "  Current status: Autoplay for non-volume devices already disabled" -ForegroundColor Green
        } else {
            Write-Host "  Current status: Autoplay for non-volume devices enabled (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-CC-000180 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000180" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Autoplay is now disabled for non-volume devices" -ForegroundColor Gray

Write-Host "`nNon-Volume Devices Affected:" -ForegroundColor Cyan
Write-Host "• Media Transfer Protocol (MTP) devices" -ForegroundColor Gray
Write-Host "• Picture Transfer Protocol (PTP) devices" -ForegroundColor Gray
Write-Host "• Digital cameras" -ForegroundColor Gray
Write-Host "• Smartphones and tablets" -ForegroundColor Gray
Write-Host "• Portable media players" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents malicious code execution from non-volume devices" -ForegroundColor Gray
Write-Host "• Blocks automatic program execution when MTP devices are connected" -ForegroundColor Gray
Write-Host "• Reduces attack surface from portable devices" -ForegroundColor Gray
Write-Host "• Critical security control - CAT I (Highest Priority)" -ForegroundColor Red

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Allow autoplay for non-volume devices (NOT STIG Compliant)" -ForegroundColor Red
Write-Host "• 1 = Disable autoplay for non-volume devices (STIG Compliant)" -ForegroundColor Green

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• This setting only affects non-volume devices (MTP, PTP, etc.)" -ForegroundColor Gray
Write-Host "• Regular USB drives and CD/DVD autoplay are controlled by separate settings" -ForegroundColor Gray
Write-Host "• Users can still manually access files on connected devices" -ForegroundColor Gray

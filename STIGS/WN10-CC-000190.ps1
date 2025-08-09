<#
.SYNOPSIS
    Autoplay must be disabled for all drives.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000190

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000190.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"
$ValueName = "NoDriveTypeAutorun"
$ValueData = 255  # Disables autoplay for all drive types
$ValueType = "DWord"

Write-Host "WN10-CC-000190 Remediation: Disable Autoplay for All Drives" -ForegroundColor Cyan
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
        if ($CurrentValueBefore.$ValueName -eq 255) {
            Write-Host "  Current status: Autoplay is already disabled for all drives" -ForegroundColor Green
        } else {
            Write-Host "  Current status: Autoplay is not fully disabled (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-CC-000190 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName) (All drives disabled)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000190" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Autoplay is now disabled for all drive types" -ForegroundColor Gray

Write-Host "`nDrive Types Disabled:" -ForegroundColor Cyan
Write-Host "• Unknown drives" -ForegroundColor Gray
Write-Host "• Removable drives (USB, floppy)" -ForegroundColor Gray
Write-Host "• Fixed drives (hard drives)" -ForegroundColor Gray
Write-Host "• Network drives" -ForegroundColor Gray
Write-Host "• CD-ROM drives" -ForegroundColor Gray
Write-Host "• RAM drives" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents malicious code execution from all media types" -ForegroundColor Gray
Write-Host "• Blocks automatic program execution from autorun.inf files" -ForegroundColor Gray
Write-Host "• Reduces risk of malware infection from any removable media" -ForegroundColor Gray
Write-Host "• Critical security control - CAT I (Highest Priority)" -ForegroundColor Red

Write-Host "`nValue Reference:" -ForegroundColor Cyan
Write-Host "• 255 (0xFF) = All drive types disabled (STIG Compliant)" -ForegroundColor Green
Write-Host "• Other values = Partial protection (NOT STIG Compliant)" -ForegroundColor Red

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• Users must manually run programs from all media types" -ForegroundColor Gray
Write-Host "• This setting affects all users on the system" -ForegroundColor Gray

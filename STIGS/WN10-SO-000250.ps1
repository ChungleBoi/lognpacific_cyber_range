<#
.SYNOPSIS
    User Account Control must, at minimum, prompt administrators for consent on the secure desktop.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000250

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-SO-000250.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "ConsentPromptBehaviorAdmin"
$ValueData = 2  # Prompt for consent on the secure desktop
$ValueType = "DWord"

Write-Host "WN10-SO-000250 Remediation: UAC Prompt Administrators for Consent on Secure Desktop" -ForegroundColor Cyan
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
            0 { Write-Host "  Current level: Elevate without prompting (NOT STIG COMPLIANT)" -ForegroundColor Red }
            1 { Write-Host "  Current level: Prompt for credentials on secure desktop" -ForegroundColor Yellow }
            2 { Write-Host "  Current level: Prompt for consent on secure desktop (STIG COMPLIANT)" -ForegroundColor Green }
            3 { Write-Host "  Current level: Prompt for credentials" -ForegroundColor Yellow }
            4 { Write-Host "  Current level: Prompt for consent" -ForegroundColor Yellow }
            5 { Write-Host "  Current level: Prompt for consent for non-Windows binaries" -ForegroundColor Yellow }
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
        Write-Host "✓ Verification successful: STIG WN10-SO-000250 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName) (Prompt for consent on secure desktop)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-SO-000250" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: UAC now prompts administrators for consent on secure desktop" -ForegroundColor Gray

Write-Host "`nUAC Behavior Settings:" -ForegroundColor Cyan
Write-Host "• 0 = Elevate without prompting (NOT STIG COMPLIANT)" -ForegroundColor Red
Write-Host "• 1 = Prompt for credentials on the secure desktop" -ForegroundColor Yellow
Write-Host "• 2 = Prompt for consent on the secure desktop (STIG COMPLIANT)" -ForegroundColor Green
Write-Host "• 3 = Prompt for credentials" -ForegroundColor Yellow
Write-Host "• 4 = Prompt for consent" -ForegroundColor Yellow
Write-Host "• 5 = Prompt for consent for non-Windows binaries" -ForegroundColor Yellow

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Ensures administrators must acknowledge elevation requests" -ForegroundColor Gray
Write-Host "• Uses secure desktop to prevent UI spoofing attacks" -ForegroundColor Gray
Write-Host "• Provides audit trail for administrative actions" -ForegroundColor Gray
Write-Host "• Reduces risk of unintended privilege escalation" -ForegroundColor Gray

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• Secure desktop dims the screen and shows only UAC prompt" -ForegroundColor Gray
Write-Host "• Setting takes effect immediately for new elevation requests" -ForegroundColor Gray
Write-Host "• Administrators will see consent prompts for elevated operations" -ForegroundColor Gray

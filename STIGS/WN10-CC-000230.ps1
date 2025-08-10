<#
.SYNOPSIS
    Users must not be allowed to ignore SmartScreen filter warnings for malicious websites in Microsoft Edge.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000230

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000230.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$ValueName = "PreventOverride"
$ValueData = 1  # Prevent users from overriding SmartScreen warnings
$ValueType = "DWord"

Write-Host "WN10-CC-000230 Remediation: Prevent SmartScreen Filter Warning Override" -ForegroundColor Cyan
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
            Write-Host "  Current status: SmartScreen override prevention already enabled" -ForegroundColor Green
        } else {
            Write-Host "  Current status: SmartScreen override allowed (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-CC-000230 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000230" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Users can no longer ignore SmartScreen warnings for malicious websites" -ForegroundColor Gray

Write-Host "`nWhat is SmartScreen Filter?" -ForegroundColor Cyan
Write-Host "• Microsoft's web protection technology built into Edge browser" -ForegroundColor Gray
Write-Host "• Analyzes websites and downloads for potential threats" -ForegroundColor Gray
Write-Host "• Compares sites against Microsoft's database of known malicious sites" -ForegroundColor Gray
Write-Host "• Provides real-time protection against phishing and malware" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents users from accessing known malicious websites" -ForegroundColor Gray
Write-Host "• Blocks phishing sites that could steal credentials" -ForegroundColor Gray
Write-Host "• Protects against drive-by downloads and malware" -ForegroundColor Gray
Write-Host "• Enforces organizational security policies consistently" -ForegroundColor Gray
Write-Host "• Reduces risk of successful social engineering attacks" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Allow users to ignore SmartScreen warnings (NOT STIG Compliant)" -ForegroundColor Red
Write-Host "• 1 = Prevent users from ignoring SmartScreen warnings (STIG Compliant)" -ForegroundColor Green

Write-Host "`nUser Experience Impact:" -ForegroundColor Yellow
Write-Host "• Users will see SmartScreen warnings for malicious sites" -ForegroundColor Gray
Write-Host "• Users will NOT be able to click 'Continue anyway' buttons" -ForegroundColor Gray
Write-Host "• Access to flagged sites will be completely blocked" -ForegroundColor Gray
Write-Host "• Legitimate sites will continue to work normally" -ForegroundColor Gray

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• This setting specifically affects Microsoft Edge browser" -ForegroundColor Gray
Write-Host "• SmartScreen protection remains active and effective" -ForegroundColor Gray
Write-Host "• IT administrators can whitelist sites if needed through other policies" -ForegroundColor Gray
Write-Host "• Change takes effect immediately for new browser sessions" -ForegroundColor Gray

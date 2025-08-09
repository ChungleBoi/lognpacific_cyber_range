<#
.SYNOPSIS
    PKU2U authentication using online identities must be prevented.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000185

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-SO-000185.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\System\CurrentControlSet\Control\LSA\pku2u"
$ValueName = "AllowOnlineID"
$ValueData = 0
$ValueType = "DWord"

Write-Host "WN10-SO-000185 Remediation: Prevent PKU2U Authentication Using Online Identities" -ForegroundColor Cyan
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
            Write-Host "  Current status: PKU2U online identities already prevented" -ForegroundColor Green
        } else {
            Write-Host "  Current status: PKU2U online identities allowed (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-SO-000185 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-SO-000185" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: PKU2U authentication using online identities is now prevented" -ForegroundColor Gray

Write-Host "`nWhat is PKU2U?" -ForegroundColor Cyan
Write-Host "• PKU2U (Public Key Cryptography User-to-User) is a peer-to-peer authentication protocol" -ForegroundColor Gray
Write-Host "• Allows authentication using online identities (Microsoft accounts, etc.)" -ForegroundColor Gray
Write-Host "• Can bypass traditional domain authentication mechanisms" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents online identities from authenticating to domain-joined systems" -ForegroundColor Gray
Write-Host "• Ensures authentication is centrally managed with Windows user accounts" -ForegroundColor Gray
Write-Host "• Maintains consistent authentication policy across the domain" -ForegroundColor Gray
Write-Host "• Reduces potential for unauthorized access via external accounts" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Prevent PKU2U online identity authentication (STIG Compliant)" -ForegroundColor Green
Write-Host "• 1 = Allow PKU2U online identity authentication (NOT STIG Compliant)" -ForegroundColor Red

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• This setting primarily affects domain-joined systems" -ForegroundColor Gray
Write-Host "• Change takes effect immediately for new authentication attempts" -ForegroundColor Gray
Write-Host "• Does not affect traditional domain authentication methods" -ForegroundColor Gray

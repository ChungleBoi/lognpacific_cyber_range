<#
.SYNOPSIS
    Anonymous enumeration of shares must be restricted.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000150

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-SO-000150.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$ValueName = "RestrictAnonymous"
$ValueData = 1
$ValueType = "DWord"

Write-Host "WN10-SO-000150 Remediation: Restrict Anonymous Enumeration of Shares" -ForegroundColor Cyan
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
            Write-Host "  Current status: Anonymous enumeration already restricted" -ForegroundColor Green
        } else {
            Write-Host "  Current status: Anonymous enumeration allowed (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-SO-000150 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-SO-000150" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Anonymous enumeration of SAM accounts and shares is now restricted" -ForegroundColor Gray

Write-Host "`nWhat This Prevents:" -ForegroundColor Cyan
Write-Host "• Anonymous users from enumerating SAM account names" -ForegroundColor Gray
Write-Host "• Anonymous users from enumerating network shares" -ForegroundColor Gray
Write-Host "• Unauthorized information gathering about system resources" -ForegroundColor Gray
Write-Host "• Reconnaissance activities by potential attackers" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents unauthorized information transfer via shared system resources" -ForegroundColor Gray
Write-Host "• Reduces system reconnaissance capabilities for attackers" -ForegroundColor Gray
Write-Host "• Enforces authentication requirements for resource discovery" -ForegroundColor Gray
Write-Host "• Critical security control - CAT I (Highest Priority)" -ForegroundColor Red

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Allow anonymous enumeration (NOT STIG Compliant)" -ForegroundColor Red
Write-Host "• 1 = Restrict anonymous enumeration (STIG Compliant)" -ForegroundColor Green

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• Change takes effect immediately for new network connections" -ForegroundColor Gray
Write-Host "• May affect some legacy applications that rely on anonymous access" -ForegroundColor Gray
Write-Host "• This is a fundamental network security hardening measure" -ForegroundColor Gray

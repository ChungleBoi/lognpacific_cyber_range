<#
.SYNOPSIS
    Solicited Remote Assistance must not be allowed.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000155

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000155.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
$ValueName = "fAllowToGetHelp"
$ValueData = 0
$ValueType = "DWord"

Write-Host "WN10-CC-000155 Remediation: Disable Solicited Remote Assistance" -ForegroundColor Cyan
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
            Write-Host "  Current status: Solicited Remote Assistance already disabled" -ForegroundColor Green
        } else {
            Write-Host "  Current status: Solicited Remote Assistance enabled (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-CC-000155 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000155" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Solicited Remote Assistance is now disabled" -ForegroundColor Gray

Write-Host "`nWhat is Solicited Remote Assistance?" -ForegroundColor Cyan
Write-Host "• Allows users to request help from another user" -ForegroundColor Gray
Write-Host "• Remote user can view or take control of the local session" -ForegroundColor Gray
Write-Host "• Help is specifically requested by the local user" -ForegroundColor Gray
Write-Host "• Creates invitation files that can be sent to helpers" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents unauthorized remote access to user sessions" -ForegroundColor Gray
Write-Host "• Eliminates risk of remote control by unauthorized parties" -ForegroundColor Gray
Write-Host "• Protects sensitive information from being viewed remotely" -ForegroundColor Gray
Write-Host "• Reduces attack surface for social engineering attempts" -ForegroundColor Gray
Write-Host "• Critical security control - CAT I (Highest Priority)" -ForegroundColor Red

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Disable solicited remote assistance (STIG Compliant)" -ForegroundColor Green
Write-Host "• 1 = Enable solicited remote assistance (NOT STIG Compliant)" -ForegroundColor Red

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• This disables user-initiated remote assistance requests" -ForegroundColor Gray
Write-Host "• IT administrators should use enterprise remote management tools instead" -ForegroundColor Gray
Write-Host "• Change takes effect immediately for new remote assistance attempts" -ForegroundColor Gray
Write-Host "• Does not affect other remote desktop or management solutions" -ForegroundColor Gray

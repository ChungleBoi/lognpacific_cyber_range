<#
.SYNOPSIS
    Web publishing and online ordering wizards must be prevented from downloading a list of providers.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000105

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000105.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ValueName = "NoWebServices"
$ValueData = 1
$ValueType = "DWord"

Write-Host "WN10-CC-000105 Remediation: Prevent Web Publishing and Online Ordering Wizards from Downloading Providers" -ForegroundColor Cyan
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
            Write-Host "  Current status: Web services already disabled" -ForegroundColor Green
        } else {
            Write-Host "  Current status: Web services enabled (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-CC-000105 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000105" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Web publishing and online ordering wizards can no longer download provider lists" -ForegroundColor Gray

Write-Host "`nFeatures Disabled:" -ForegroundColor Cyan
Write-Host "• Internet download for Web publishing wizards" -ForegroundColor Gray
Write-Host "• Internet download for online ordering wizards" -ForegroundColor Gray
Write-Host "• Automatic downloading of service provider lists" -ForegroundColor Gray
Write-Host "• External vendor communication for wizard services" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents potentially sensitive information from being sent outside the enterprise" -ForegroundColor Gray
Write-Host "• Blocks uncontrolled updates to the system via wizard downloads" -ForegroundColor Gray
Write-Host "• Reduces external communication that could expose system information" -ForegroundColor Gray
Write-Host "• Maintains tighter control over system's internet communications" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Allow web services (NOT STIG Compliant)" -ForegroundColor Red
Write-Host "• 1 = Disable web services (STIG Compliant)" -ForegroundColor Green

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• This setting affects Windows built-in web publishing and ordering wizards" -ForegroundColor Gray
Write-Host "• Users will need to manually configure any web publishing services" -ForegroundColor Gray
Write-Host "• Change takes effect immediately for new wizard sessions" -ForegroundColor Gray

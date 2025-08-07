<#
.SYNOPSIS
    Microsoft consumer experiences must be turned off.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-06
    Last Modified   : 2025-08-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000197

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000197.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$ValueName = "DisableWindowsConsumerFeatures"
$ValueData = 1
$ValueType = "DWord"

Write-Host "WN10-CC-000197 Remediation: Turn Off Microsoft Consumer Experiences" -ForegroundColor Cyan
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
    } else {
        Write-Host "Value did not exist before." -ForegroundColor Gray
    }
    
    # Set the registry value
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type $ValueType
    Write-Host "Successfully set $ValueName to $ValueData" -ForegroundColor Green
    
    # Verify the value was set correctly
    $CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($CurrentValue.$ValueName -eq $ValueData) {
        Write-Host "✓ Verification successful: STIG WN10-CC-000197 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000197" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Microsoft consumer experiences are now disabled" -ForegroundColor Gray

Write-Host "`nFeatures Disabled:" -ForegroundColor Cyan
Write-Host "• Windows spotlight on lock screen" -ForegroundColor Gray
Write-Host "• Suggestions for third-party apps in Start menu" -ForegroundColor Gray
Write-Host "• App suggestions in Settings" -ForegroundColor Gray
Write-Host "• Automatic installation of suggested apps" -ForegroundColor Gray
Write-Host "• Windows tips and suggestions" -ForegroundColor Gray

Write-Host "`nBusiness Benefits:" -ForegroundColor Cyan
Write-Host "• Reduces distractions in business environments" -ForegroundColor Gray
Write-Host "• Prevents unauthorized app installations" -ForegroundColor Gray
Write-Host "• Maintains focus on essential business capabilities" -ForegroundColor Gray
Write-Host "• Improves system performance by reducing background processes" -ForegroundColor Gray

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• Windows 10 v1507 LTSB version does not include this setting (N/A)" -ForegroundColor Gray
Write-Host "• Some changes may require a restart to take full effect" -ForegroundColor Gray

<#
.SYNOPSIS
    Users must be prevented from changing installation options.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000310

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000310.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
$ValueName = "EnableUserControl"
$ValueData = 0  # Disable user control of installation options
$ValueType = "DWord"

Write-Host "WN10-CC-000310 Remediation: Prevent Users from Changing Installation Options" -ForegroundColor Cyan
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
            Write-Host "  Current status: User control of installation options already disabled" -ForegroundColor Green
        } else {
            Write-Host "  Current status: User control of installation options enabled (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-CC-000310 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000310" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Users can no longer change Windows Installer options" -ForegroundColor Gray

Write-Host "`nWhat This Controls:" -ForegroundColor Cyan
Write-Host "• User ability to change installation directories" -ForegroundColor Gray
Write-Host "• User access to advanced installer options" -ForegroundColor Gray
Write-Host "• User control over installation features and components" -ForegroundColor Gray
Write-Host "• User ability to modify installer logging settings" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents users from bypassing security features during installation" -ForegroundColor Gray
Write-Host "• Maintains consistent installation policies across the organization" -ForegroundColor Gray
Write-Host "• Reduces risk of malicious software installation with elevated privileges" -ForegroundColor Gray
Write-Host "• Ensures installations follow enterprise security standards" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Disable user control of installation options (STIG Compliant)" -ForegroundColor Green
Write-Host "• 1 = Enable user control of installation options (NOT STIG Compliant)" -ForegroundColor Red

Write-Host "`nImpact:" -ForegroundColor Yellow
Write-Host "• Users will not be able to customize installation locations" -ForegroundColor Gray
Write-Host "• Advanced installation options will be hidden from users" -ForegroundColor Gray
Write-Host "• System administrators retain full control over installer behavior" -ForegroundColor Gray
Write-Host "• Standard software installations will still work normally" -ForegroundColor Gray

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• This setting affects Windows Installer (.msi) packages" -ForegroundColor Gray
Write-Host "• Does not affect other installation methods (exe installers, etc.)" -ForegroundColor Gray
Write-Host "• Change takes effect for new installation attempts" -ForegroundColor Gray

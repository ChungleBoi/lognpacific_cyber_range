<#
.SYNOPSIS
    Toast notifications to the lock screen must be turned off.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-UC-000015

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-UC-000015.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings for system-wide policy (HKLM)
$RegistryPathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$RegistryPathHKCU = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$ValueName = "NoToastApplicationNotificationOnLockScreen"
$ValueData = 1
$ValueType = "DWord"

Write-Host "WN10-UC-000015 Remediation: Turn Off Toast Notifications to Lock Screen" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

try {
    # Set system-wide policy (HKLM) - affects all users
    Write-Host "Configuring system-wide policy (HKLM)..." -ForegroundColor Yellow
    
    if (-not (Test-Path $RegistryPathHKLM)) {
        Write-Host "HKLM registry path does not exist. Creating: $RegistryPathHKLM" -ForegroundColor Yellow
        New-Item -Path $RegistryPathHKLM -Force | Out-Null
        Write-Host "Successfully created HKLM registry path." -ForegroundColor Green
    } else {
        Write-Host "HKLM registry path already exists." -ForegroundColor Green
    }
    
    # Set the system-wide registry value
    Set-ItemProperty -Path $RegistryPathHKLM -Name $ValueName -Value $ValueData -Type $ValueType
    Write-Host "Successfully set HKLM $ValueName to $ValueData" -ForegroundColor Green
    
    # Set current user policy (HKCU) - affects current user immediately
    Write-Host "`nConfiguring current user policy (HKCU)..." -ForegroundColor Yellow
    
    if (-not (Test-Path $RegistryPathHKCU)) {
        Write-Host "HKCU registry path does not exist. Creating: $RegistryPathHKCU" -ForegroundColor Yellow
        New-Item -Path $RegistryPathHKCU -Force | Out-Null
        Write-Host "Successfully created HKCU registry path." -ForegroundColor Green
    } else {
        Write-Host "HKCU registry path already exists." -ForegroundColor Green
    }
    
    # Set the current user registry value
    Set-ItemProperty -Path $RegistryPathHKCU -Name $ValueName -Value $ValueData -Type $ValueType
    Write-Host "Successfully set HKCU $ValueName to $ValueData" -ForegroundColor Green
    
    # Verify the values were set correctly
    $CurrentValueHKLM = Get-ItemProperty -Path $RegistryPathHKLM -Name $ValueName -ErrorAction SilentlyContinue
    $CurrentValueHKCU = Get-ItemProperty -Path $RegistryPathHKCU -Name $ValueName -ErrorAction SilentlyContinue
    
    $HKLMCompliant = $CurrentValueHKLM.$ValueName -eq $ValueData
    $HKCUCompliant = $CurrentValueHKCU.$ValueName -eq $ValueData
    
    if ($HKLMCompliant -and $HKCUCompliant) {
        Write-Host "✓ Verification successful: STIG WN10-UC-000015 is now compliant" -ForegroundColor Green
        Write-Host "HKLM Registry Value: $($CurrentValueHKLM.$ValueName)" -ForegroundColor Gray
        Write-Host "HKCU Registry Value: $($CurrentValueHKCU.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: One or more registry values may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-UC-000015" -ForegroundColor Gray
Write-Host "• HKLM Registry Path: $RegistryPathHKLM" -ForegroundColor Gray
Write-Host "• HKCU Registry Path: $RegistryPathHKCU" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Toast notifications to lock screen are now disabled" -ForegroundColor Gray

Write-Host "`nWhat Are Toast Notifications on Lock Screen?" -ForegroundColor Cyan
Write-Host "• Pop-up notifications that appear on the lock screen" -ForegroundColor Gray
Write-Host "• Display content from applications like email, messages, calendar" -ForegroundColor Gray
Write-Host "• May show sensitive information without authentication" -ForegroundColor Gray
Write-Host "• Can be viewed by anyone who can see the screen" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents sensitive information from being displayed on lock screen" -ForegroundColor Gray
Write-Host "• Reduces information disclosure to unauthorized personnel" -ForegroundColor Gray
Write-Host "• Protects privacy when system is locked but visible" -ForegroundColor Gray
Write-Host "• Prevents shoulder surfing of notification content" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Allow toast notifications on lock screen (NOT STIG Compliant)" -ForegroundColor Red
Write-Host "• 1 = Disable toast notifications on lock screen (STIG Compliant)" -ForegroundColor Green

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• HKLM setting applies to all users on the system" -ForegroundColor Gray
Write-Host "• HKCU setting applies to current user immediately" -ForegroundColor Gray
Write-Host "• Applications can still send notifications - they just won't show on lock screen" -ForegroundColor Gray
Write-Host "• Notifications will be visible after user unlocks the system" -ForegroundColor Gray

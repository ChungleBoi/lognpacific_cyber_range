<#
.SYNOPSIS
    Insecure logons to an SMB server must be disabled.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000040

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000040.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$ValueName = "AllowInsecureGuestAuth"
$ValueData = 0
$ValueType = "DWord"

Write-Host "WN10-CC-000040 Remediation: Disable Insecure Logons to SMB Server" -ForegroundColor Cyan
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
            Write-Host "  Current status: Insecure guest authentication already disabled" -ForegroundColor Green
        } else {
            Write-Host "  Current status: Insecure guest authentication enabled (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-CC-000040 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000040" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: Insecure guest logons to SMB servers are now disabled" -ForegroundColor Gray

Write-Host "`nWhat Are Insecure Guest Logons?" -ForegroundColor Cyan
Write-Host "• SMB connections that allow unauthenticated access" -ForegroundColor Gray
Write-Host "• Guest logons without requiring credentials" -ForegroundColor Gray
Write-Host "• Anonymous access to shared network resources" -ForegroundColor Gray
Write-Host "• Typically used for public file shares or legacy systems" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents unauthenticated access to shared folders" -ForegroundColor Gray
Write-Host "• Ensures proper authentication is required for network resources" -ForegroundColor Gray
Write-Host "• Reduces risk of unauthorized data access" -ForegroundColor Gray
Write-Host "• Protects against lateral movement by attackers" -ForegroundColor Gray
Write-Host "• Helps prevent ransomware from accessing network shares" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = Disable insecure guest authentication (STIG Compliant)" -ForegroundColor Green
Write-Host "• 1 = Enable insecure guest authentication (NOT STIG Compliant)" -ForegroundColor Red

Write-Host "`nImpact on Network Access:" -ForegroundColor Yellow
Write-Host "• Network shares will require proper authentication" -ForegroundColor Gray
Write-Host "• Guest access to SMB shares will be blocked" -ForegroundColor Gray
Write-Host "• May affect access to some NAS devices or legacy systems" -ForegroundColor Gray
Write-Host "• Users will need valid credentials for all network resources" -ForegroundColor Gray

Write-Host "`nRecommendations:" -ForegroundColor Yellow
Write-Host "• Configure proper user accounts for network resource access" -ForegroundColor Gray
Write-Host "• Use domain authentication where possible" -ForegroundColor Gray
Write-Host "• Avoid anonymous/guest shares in production environments" -ForegroundColor Gray
Write-Host "• Consider SMB signing for additional security" -ForegroundColor Gray

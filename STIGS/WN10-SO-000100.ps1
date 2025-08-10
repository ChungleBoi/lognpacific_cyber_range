<#
.SYNOPSIS
    The Windows SMB client must be configured to always perform SMB packet signing.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000100

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-SO-000100.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$ValueName = "RequireSecuritySignature"
$ValueData = 1  # Always require SMB packet signing
$ValueType = "DWord"

Write-Host "WN10-SO-000100 Remediation: SMB Client Must Always Perform Packet Signing" -ForegroundColor Cyan
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
            Write-Host "  Current status: SMB packet signing already required" -ForegroundColor Green
        } else {
            Write-Host "  Current status: SMB packet signing not required (NOT STIG COMPLIANT)" -ForegroundColor Red
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
        Write-Host "✓ Verification successful: STIG WN10-SO-000100 is now compliant" -ForegroundColor Green
        Write-Host "Registry Value: $($CurrentValue.$ValueName)" -ForegroundColor Gray
    } else {
        Write-Warning "Verification failed: Registry value may not have been set correctly."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-SO-000100" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = $ValueData (DWORD)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: SMB client will now always require packet signing" -ForegroundColor Gray

Write-Host "`nWhat is SMB Packet Signing?" -ForegroundColor Cyan
Write-Host "• Digital signatures applied to SMB (Server Message Block) network packets" -ForegroundColor Gray
Write-Host "• Cryptographic verification of packet authenticity and integrity" -ForegroundColor Gray
Write-Host "• Prevents tampering with network file sharing communications" -ForegroundColor Gray
Write-Host "• Ensures packets come from legitimate sources" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Prevents man-in-the-middle attacks on SMB traffic" -ForegroundColor Gray
Write-Host "• Protects against SMB packet tampering and injection" -ForegroundColor Gray
Write-Host "• Ensures integrity of file sharing communications" -ForegroundColor Gray
Write-Host "• Prevents SMB relay attacks and session hijacking" -ForegroundColor Gray
Write-Host "• Required for secure domain communications" -ForegroundColor Gray

Write-Host "`nValue Meanings:" -ForegroundColor Cyan
Write-Host "• 0 = SMB packet signing not required (NOT STIG Compliant)" -ForegroundColor Red
Write-Host "• 1 = Always require SMB packet signing (STIG Compliant)" -ForegroundColor Green

Write-Host "`nNetwork Impact:" -ForegroundColor Yellow
Write-Host "• SMB client will only connect to servers that support packet signing" -ForegroundColor Gray
Write-Host "• May prevent connections to legacy or misconfigured SMB servers" -ForegroundColor Gray
Write-Host "• Slight performance overhead due to cryptographic operations" -ForegroundColor Gray
Write-Host "• Essential for secure enterprise network environments" -ForegroundColor Gray

Write-Host "`nCompatibility:" -ForegroundColor Yellow
Write-Host "• Modern Windows servers support SMB signing by default" -ForegroundColor Gray
Write-Host "• Some legacy devices or NAS systems may not support signing" -ForegroundColor Gray
Write-Host "• Domain controllers typically require SMB signing" -ForegroundColor Gray
Write-Host "• Check compatibility with third-party SMB implementations" -ForegroundColor Gray

Write-Host "`nNote:" -ForegroundColor Yellow
Write-Host "• This affects SMB client behavior (outgoing connections)" -ForegroundColor Gray
Write-Host "• Configure companion setting for SMB server signing if hosting shares" -ForegroundColor Gray
Write-Host "• Change takes effect for new SMB connections" -ForegroundColor Gray
Write-Host "• May require restart for full effect in some scenarios" -ForegroundColor Gray

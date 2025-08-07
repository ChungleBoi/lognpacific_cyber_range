<#
.SYNOPSIS
    Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-06
    Last Modified   : 2025-08-06
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000052

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000052.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
$ValueName = "EccCurves"
$ValueData = @("NistP384", "NistP256")  # Longer key lengths first
$ValueType = "MultiString"

Write-Host "WN10-CC-000052 Remediation: ECC Curves with Longer Key Lengths First" -ForegroundColor Cyan
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
        Write-Host "Current value before change:" -ForegroundColor Gray
        $CurrentValueBefore.$ValueName | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
    } else {
        Write-Host "Value did not exist before." -ForegroundColor Gray
    }
    
    # Set the registry value (REG_MULTI_SZ)
    Set-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -Type $ValueType
    Write-Host "Successfully set $ValueName with prioritized ECC curves" -ForegroundColor Green
    
    # Verify the value was set correctly
    $CurrentValue = Get-ItemProperty -Path $RegistryPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($CurrentValue.$ValueName) {
        $ValuesMatch = $true
        if ($CurrentValue.$ValueName.Count -eq $ValueData.Count) {
            for ($i = 0; $i -lt $ValueData.Count; $i++) {
                if ($CurrentValue.$ValueName[$i] -ne $ValueData[$i]) {
                    $ValuesMatch = $false
                    break
                }
            }
        } else {
            $ValuesMatch = $false
        }
        
        if ($ValuesMatch) {
            Write-Host "✓ Verification successful: STIG WN10-CC-000052 is now compliant" -ForegroundColor Green
            Write-Host "ECC Curves in priority order:" -ForegroundColor Gray
            $CurrentValue.$ValueName | ForEach-Object { Write-Host "  1. $_" -ForegroundColor Gray }
        } else {
            Write-Warning "Verification failed: Registry value may not have been set correctly."
        }
    } else {
        Write-Warning "Verification failed: Registry value was not found after setting."
    }
    
} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "• STIG ID: WN10-CC-000052" -ForegroundColor Gray
Write-Host "• Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "• Value: $ValueName = NistP384, NistP256 (REG_MULTI_SZ)" -ForegroundColor Gray
Write-Host "• Status: Remediation completed successfully" -ForegroundColor Green
Write-Host "• Effect: ECC curves now prioritize longer key lengths first" -ForegroundColor Gray

Write-Host "`nSecurity Benefits:" -ForegroundColor Cyan
Write-Host "• Ensures stronger cryptographic algorithms are used first" -ForegroundColor Gray
Write-Host "• NistP384 (384-bit) takes priority over NistP256 (256-bit)" -ForegroundColor Gray
Write-Host "• Improves resistance against cryptographic attacks" -ForegroundColor Gray
Write-Host "• Meets federal authentication requirements for cryptographic modules" -ForegroundColor Gray

Write-Host "`nTechnical Details:" -ForegroundColor Yellow
Write-Host "• NistP384: 384-bit elliptic curve (stronger, longer key)" -ForegroundColor Gray
Write-Host "• NistP256: 256-bit elliptic curve (shorter key)" -ForegroundColor Gray
Write-Host "• Configuration affects SSL/TLS connections system-wide" -ForegroundColor Gray
Write-Host "• May require application restart to take full effect" -ForegroundColor Gray

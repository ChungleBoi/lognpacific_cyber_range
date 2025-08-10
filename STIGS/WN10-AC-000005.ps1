<#
.SYNOPSIS
    Configure Account Lockout Duration to 15 minutes or greater.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-10
    Last Modified   : 2025-08-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-AC-000005.ps1 
#>

Write-Host "=== WN10-AC-000005: Configuring Account Lockout Duration ===" -ForegroundColor Green

try {
    # Set account lockout duration to 15 minutes (900 seconds)
    $lockoutDuration = 15
    
    Write-Host "Setting account lockout duration to $lockoutDuration minutes..." -ForegroundColor Yellow
    
    # Use net accounts command to set the lockout duration
    $result = net accounts /lockoutduration:$lockoutDuration 2>&1
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SUCCESS: Account lockout duration set to $lockoutDuration minutes." -ForegroundColor Green
    } else {
        Write-Host "ERROR: Failed to set account lockout duration using net accounts." -ForegroundColor Red
        Write-Host "Error output: $result" -ForegroundColor Red
    }
    
    # Verify the current settings
    Write-Host "`nVerifying current account policy settings..." -ForegroundColor Cyan
    
    $accountInfo = net accounts 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nCurrent Account Policy:" -ForegroundColor Yellow
        $accountInfo | ForEach-Object {
            if ($_ -match "Lockout duration|Lockout threshold|Lockout observation window") {
                Write-Host "  $_" -ForegroundColor White
            }
        }
    } else {
        Write-Host "WARNING: Could not retrieve current account policy settings." -ForegroundColor Red
    }
    
    # Additional security configuration information
    Write-Host "`nSecurity Configuration Details:" -ForegroundColor Cyan
    Write-Host "  Policy Location: Computer Configuration >> Windows Settings >> Security Settings" -ForegroundColor Yellow
    Write-Host "                   >> Account Policies >> Account Lockout Policy" -ForegroundColor Yellow
    Write-Host "  Setting: Account lockout duration" -ForegroundColor Yellow
    Write-Host "  Required Value: 15 minutes or greater (0 is also acceptable)" -ForegroundColor Yellow
    Write-Host "  Current Setting: $lockoutDuration minutes" -ForegroundColor Green
    
    # Note about related settings
    Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Red
    Write-Host "- Account lockout threshold should also be configured (recommended: 3-5 attempts)" -ForegroundColor Yellow
    Write-Host "- Account lockout observation window should be set (recommended: 15 minutes)" -ForegroundColor Yellow
    Write-Host "- Setting lockout duration to 0 requires administrator intervention to unlock accounts" -ForegroundColor Yellow
    Write-Host "- Changes take effect immediately for new authentication attempts" -ForegroundColor Yellow
}
catch {
    Write-Host "ERROR: Failed to configure account lockout duration - $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n=== STIG WN10-AC-000005 Remediation Complete ===" -ForegroundColor Cyan

# Optional: Configure related account lockout settings
$configureAdditional = Read-Host "`nWould you like to configure recommended lockout threshold (3 attempts) and observation window (15 min)? (y/n)"
if ($configureAdditional -eq 'y' -or $configureAdditional -eq 'Y') {
    try {
        Write-Host "`nConfiguring additional account lockout settings..." -ForegroundColor Yellow
        
        # Set lockout threshold to 3 attempts
        net accounts /lockoutthreshold:3 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "SUCCESS: Account lockout threshold set to 3 invalid attempts." -ForegroundColor Green
        }
        
        # Set lockout observation window to 15 minutes
        net accounts /lockoutwindow:15 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "SUCCESS: Account lockout observation window set to 15 minutes." -ForegroundColor Green
        }
        
        # Display final configuration
        Write-Host "`nFinal Account Lockout Configuration:" -ForegroundColor Cyan
        net accounts | Select-String "Lockout"
    }
    catch {
        Write-Host "WARNING: Failed to configure additional settings - $($_.Exception.Message)" -ForegroundColor Red
    }
}

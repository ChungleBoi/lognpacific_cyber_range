<#
.SYNOPSIS
    Configure process creation auditing and include command line in events.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000066

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000066.ps1 
#>

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Administrator privileges required."
    exit 1
}

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$Name = "ProcessCreationIncludeCmdLine_Enabled"
$Value = 1

Write-Host "Applying $($MyInvocation.MyCommand.Name): Enable Process Creation auditing and include command line" -ForegroundColor Cyan

try {
    # enable subcategory auditing for Process Creation
    & auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null

    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
    $before = (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue).$Name
    Write-Host "Before: $before" -ForegroundColor Gray

    Set-ItemProperty -Path $RegPath -Name $Name -Value $Value -Type DWord -Force

    $after = (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($after -eq $Value) { Write-Host "✓ Command line inclusion enabled for process creation events" -ForegroundColor Green }
    else { Write-Warning "Change may not have applied." }
} catch {
    Write-Error $_.Exception.Message
}

Write-Host "Note: enabling auditing may require group policy management in domain environments." -ForegroundColor Yellow
Write-Host "Summary: $RegPath -> $Name = $Value" -ForegroundColor Gray

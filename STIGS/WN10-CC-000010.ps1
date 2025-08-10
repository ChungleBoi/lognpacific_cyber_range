<#
.SYNOPSIS
    Prevent lock screen slide show via policy.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000010.ps1 
#>

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Administrator privileges required."
    exit 1
}

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$Name = "NoLockScreenSlideshow"
$Value = 1

Write-Host "Applying $($MyInvocation.MyCommand.Name): Disable lock screen slideshow" -ForegroundColor Cyan

try {
    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
    $before = (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue).$Name
    Write-Host "Before: $before" -ForegroundColor Gray

    Set-ItemProperty -Path $RegPath -Name $Name -Value $Value -Type DWord -Force

    $after = (Get-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($after -eq $Value) { Write-Host "✓ Lock screen slideshow disabled (policy)" -ForegroundColor Green }
    else { Write-Warning "Change may not have applied." }
} catch {
    Write-Error $_.Exception.Message
}

Write-Host "Summary: $RegPath -> $Name = $Value" -ForegroundColor Gray

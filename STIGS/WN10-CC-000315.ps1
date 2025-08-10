<#
.SYNOPSIS
    Ensure AlwaysInstallElevated is disabled under both HKLM and HKCU.

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000315

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000315.ps1 
#>

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Administrator privileges required."
    exit 1
}

$Paths = @(
    "HKLM:\Software\Policies\Microsoft\Windows\Installer",
    "HKCU:\Software\Policies\Microsoft\Windows\Installer"
)
$Name = "AlwaysInstallElevated"
$Value = 0

Write-Host "Applying $($MyInvocation.MyCommand.Name): Disable AlwaysInstallElevated (HKLM & HKCU)" -ForegroundColor Cyan

try {
    foreach ($p in $Paths) {
        if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
        $before = (Get-ItemProperty -Path $p -Name $Name -ErrorAction SilentlyContinue).$Name
        Write-Host "Before ($p): $before" -ForegroundColor Gray

        Set-ItemProperty -Path $p -Name $Name -Value $Value -Type DWord -Force

        $after = (Get-ItemProperty -Path $p -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($after -eq $Value) { Write-Host "✓ $p : $Name set to $Value" -ForegroundColor Green }
        else { Write-Warning "Change may not have applied for $p." }
    }
} catch {
    Write-Error $_.Exception.Message
}

Write-Host "Summary: Disabled AlwaysInstallElevated under HKLM and HKCU." -ForegroundColor Gray


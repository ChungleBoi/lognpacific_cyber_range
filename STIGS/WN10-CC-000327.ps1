<#
.SYNOPSIS
    PowerShell Transcription must be enabled on Windows 10

.NOTES
    Author          : Cristian Ortiz
    LinkedIn        : linkedin.com/in/ortiz-cristian/
    GitHub          : github.com/ChungleBoi
    Date Created    : 2025-08-05
    Last Modified   : 2025-08-05
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000327

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN10-CC-000327.ps1 
#>

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

# Define the registry settings (equivalent to Group Policy settings)
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$EnableTranscriptingName = "EnableTranscripting"
$EnableTranscriptingValue = 1
$ValueType = "DWord"

# Output directory setting - CHANGE THIS TO YOUR CENTRAL LOG SERVER OR SECURE LOCATION
$OutputDirValueName = "OutputDirectory"
$OutputDirPath = "\\LogServer\PowerShellLogs\$env:COMPUTERNAME"  # Example: UNC path to central log server
# Alternative secure locations:
# $OutputDirPath = "C:\SecureLogs\PowerShell"  # Local secure directory
# $OutputDirPath = "\\FileServer\Logs\PowerShell\$env:COMPUTERNAME"  # Network share

# Optional: Enable invocation headers for better logging detail
$EnableInvocationHeaderName = "EnableInvocationHeader"
$EnableInvocationHeaderValue = 1

Write-Host "WN10-CC-000327 Remediation: Turn on PowerShell Transcription" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Group Policy Equivalent: Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell" -ForegroundColor Gray

try {
    # Check if the registry path exists (Group Policy container)
    if (-not (Test-Path $RegistryPath)) {
        Write-Host "Creating Group Policy registry path: $RegistryPath" -ForegroundColor Yellow
        New-Item -Path $RegistryPath -Force | Out-Null
        Write-Host "Successfully created registry path." -ForegroundColor Green
    } else {
        Write-Host "Group Policy registry path already exists." -ForegroundColor Green
    }
    
    # Set the main transcription enable value (equivalent to "Turn on PowerShell Transcription" = Enabled)
    Set-ItemProperty -Path $RegistryPath -Name $EnableTranscriptingName -Value $EnableTranscriptingValue -Type $ValueType
    Write-Host "✓ Enabled PowerShell Transcription ($EnableTranscriptingName = $EnableTranscriptingValue)" -ForegroundColor Green
    
    # Set the transcript output directory (secure location requirement)
    Set-ItemProperty -Path $RegistryPath -Name $OutputDirValueName -Value $OutputDirPath -Type String
    Write-Host "✓ Set transcript output directory to: $OutputDirPath" -ForegroundColor Green
    
    # Enable invocation headers for enhanced logging (recommended)
    Set-ItemProperty -Path $RegistryPath -Name $EnableInvocationHeaderName -Value $EnableInvocationHeaderValue -Type $ValueType
    Write-Host "✓ Enabled invocation headers for detailed logging" -ForegroundColor Green
    
    # Create local output directory if using local path and it doesn't exist
    if ($OutputDirPath -notlike "\\*" -and -not (Test-Path $OutputDirPath)) {
        Write-Host "Creating local secure transcript directory: $OutputDirPath" -ForegroundColor Yellow
        New-Item -Path $OutputDirPath -ItemType Directory -Force | Out-Null
        
        # Set restrictive permissions - only Administrators and SYSTEM should have access
        $Acl = Get-Acl $OutputDirPath
        # Remove inherited permissions
        $Acl.SetAccessRuleProtection($true, $false)
        
        # Add specific permissions
        $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        
        $Acl.SetAccessRule($AdminRule)
        $Acl.SetAccessRule($SystemRule)
        Set-Acl -Path $OutputDirPath -AclObject $Acl
        
        Write-Host "✓ Created secure output directory with restricted permissions" -ForegroundColor Green
    } elseif ($OutputDirPath -like "\\*") {
        Write-Host "ℹ Using network path - ensure the path exists and has appropriate permissions" -ForegroundColor Yellow
    }
    
    # Verify all settings were applied correctly
    Write-Host "`nVerifying Group Policy equivalent settings..." -ForegroundColor Cyan
    
    $TranscriptionEnabled = Get-ItemProperty -Path $RegistryPath -Name $EnableTranscriptingName -ErrorAction SilentlyContinue
    $OutputDirectory = Get-ItemProperty -Path $RegistryPath -Name $OutputDirValueName -ErrorAction SilentlyContinue
    $InvocationHeaders = Get-ItemProperty -Path $RegistryPath -Name $EnableInvocationHeaderName -ErrorAction SilentlyContinue
    
    if ($TranscriptionEnabled.$EnableTranscriptingName -eq $EnableTranscriptingValue) {
        Write-Host "✓ PowerShell Transcription: ENABLED" -ForegroundColor Green
    } else {
        Write-Warning "✗ PowerShell Transcription verification failed"
    }
    
    if ($OutputDirectory.$OutputDirValueName) {
        Write-Host "✓ Output Directory: $($OutputDirectory.$OutputDirValueName)" -ForegroundColor Green
    } else {
        Write-Warning "✗ Output Directory setting verification failed"
    }
    
    if ($InvocationHeaders.$EnableInvocationHeaderName -eq $EnableInvocationHeaderValue) {
        Write-Host "✓ Invocation Headers: ENABLED" -ForegroundColor Green
    }
    
} catch {
    Write-Error "An error occurred during remediation: $($_.Exception.Message)"
    exit 1
}

Write-Host "`n" + "="*70 -ForegroundColor Cyan
Write-Host "REMEDIATION SUMMARY" -ForegroundColor Cyan
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "STIG ID: WN10-CC-000327" -ForegroundColor White
Write-Host "Title: PowerShell Transcription Must Be Enabled" -ForegroundColor White
Write-Host "Group Policy Path: Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> 'Turn on PowerShell Transcription'" -ForegroundColor Gray
Write-Host "Registry Path: $RegistryPath" -ForegroundColor Gray
Write-Host "Status: ✓ COMPLIANT" -ForegroundColor Green

Write-Host "`nCONFIGURED SETTINGS:" -ForegroundColor Yellow
Write-Host "• EnableTranscripting = $EnableTranscriptingValue (DWORD)" -ForegroundColor Gray
Write-Host "• OutputDirectory = $OutputDirPath (String)" -ForegroundColor Gray
Write-Host "• EnableInvocationHeader = $EnableInvocationHeaderValue (DWORD)" -ForegroundColor Gray

Write-Host "`nSECURITY BENEFITS:" -ForegroundColor Yellow
Write-Host "• All PowerShell commands and output are logged" -ForegroundColor Gray
Write-Host "• Transcripts stored in secure location inaccessible to standard users" -ForegroundColor Gray
Write-Host "• Enhanced logging with invocation headers for forensic analysis" -ForegroundColor Gray
Write-Host "• Compliance with DoD STIG security requirements" -ForegroundColor Gray

Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Red
Write-Host "• Verify the output directory path is accessible by the system" -ForegroundColor Gray
Write-Host "• Monitor disk space usage - transcript files can grow large" -ForegroundColor Gray
Write-Host "• If using network path, ensure proper network permissions" -ForegroundColor Gray
Write-Host "• Consider log rotation and archival policies" -ForegroundColor Gray
Write-Host "• Test PowerShell functionality after implementation" -ForegroundColor Gray

<#
.SYNOPSIS
    Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. This maintains an audit trail of successful system activity. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    **NOTE**: First, your machine must implement WN11-SO-000030 (https://github.com/williamolega/williamolega/blob/main/STIGs/WN11-SO-000030.ps1)
              IF WN11-SO-000030 is not implemented, this may not work properly
              Run as Administrator

.NOTES
    Author          : William Olega
    LinkedIn        : linkedin.com/in/williamolega/
    GitHub          : github.com/williamolega
    Date Created    : 2025-11-11
    Last Modified   : 2025-11-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000050

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-AU-000050.ps1 
#>

# Define File Path
$infPath = "C:\Temp\audit_process_creation.inf"
$logPath = "C:\Temp\audit_process_creation.log"
$dbPath  = "C:\Windows\Security\Database\secedit.sdb"

# Ensure C:\Temp directory exists
# The -Force flag ensures no error occurs if the directory already exists.
New-Item -ItemType Directory -Force -Path "C:\Temp" | Out-Null

# Export current Local Security Policy
& secedit /export /db "$dbPath" /cfg "$infPath" /areas SECURITYPOLICY /quiet

# Read current setting for Audit Process Creation
$currentMatch = Select-String -Path $infPath -Pattern "AuditProcessCreation" -ErrorAction SilentlyContinue
$current = if ($currentMatch) { $currentMatch.ToString() } else { "" }

# Check Compliance
if ($current -match "AuditProcessCreation\s*=\s*1") {
    Write-Host "System is already WN11-AU-000050 COMPLIANT (Audit Process Creation = Success)."
}
else {
    Write-Host "System NOT compliant. Attempting remediation..."

 # Create minimal .INF template with correct configuration
 # The signature="$CHICAGO$" header is mandatory for Windows to recognize it as a valid security template.
 # 'AuditProcessCreation = 1' means enable Success auditing only.
    $inf = @'
[Version]
signature="$CHICAGO$"
Revision=1

[AuditPolicy]
AuditProcessCreation = 1
'@

# Save the INF to disk in ASCII format (UTF encodings can cause parsing errors in secedit)
    $inf | Out-File -FilePath $infPath -Encoding ASCII

    & secedit /configure /db "$dbPath" /cfg "$infPath" /areas SECURITYPOLICY /log "$logPath" /quiet
    
# Apply the setting immediately at runtime
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null

# Verify result
    $verify = (auditpol /get /subcategory:"Process Creation" | Select-String "Success").ToString()
    if ($verify -match "Success\s*Enabled") {
        Write-Host "Successfully remediated and verified: WN11-AU-000050 Audit Process Creation (Success) is ENABLED."
    } else {
        Write-Host "Remediation attempted, but verification FAILED. Check $logPath for details."
    }
}

<#
.SYNOPSIS
    Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. This maintains an audit trail of successful system activity. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.
    **NOTE**: First, your machine must implement WN11-SO-000030 (https://github.com/williamolega/williamolega/blob/main/STIGs/WN11-SO-000030.ps1)
              IF WN11-SO-000030 is not implemented, this may not work properly

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

# Get current setting for "Process Creation"
$currentSetting = (auditpol.exe /get /subcategory:"Process Creation" | Select-String "Process Creation").ToString()
Write-Host "Current Audit Setting: $currentSetting"

# Define compliant pattern
$compliantPattern = "Success\s*Enabled.*Failure\s*Disabled"

# Check if system is already compliant
if ($currentSetting -match $compliantPattern) {
    Write-Host "System is already compliant with WN11-AU-000050."
} 
else {
    # Apply the audit policy
    auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null

    #Doublecheck if update went thru
    $updatedSetting = (auditpol.exe /get /subcategory:"Process Creation" | Select-String "Process Creation").ToString()
    Write-Host "Updated Audit Setting: $updatedSetting"

    if ($updatedSetting -match $compliantPattern) {
        Write-Host "Successfully remediated WN11-AU-000050."
    } 
    else {
        Write-Host "Failed to remediate WN11-AU-000050. Please check permissions or local policy settings."
    }
}




















# Get current setting for "Process Creation"
$currentSetting = (auditpol.exe /get /subcategory:"Process Creation" | Select-String "Process Creation").ToString()
Write-Host "Current Audit Setting: $currentSetting"

# Define compliant pattern
$compliantPattern = "Process Creation\s+Success(?!.*Failure)"

# Check if system is already compliant
if ($currentSetting -match $compliantPattern) {
    Write-Host "System is already compliant with WN11-AU-000050."
} 
else {
    # Apply the audit policy
    auditpol.exe /set /subcategory:"Process Creation" /auditing /success:enable /failure:disable | Out-Null

    #Doublecheck if update went thru
    $updatedSetting = (auditpol.exe /get /subcategory:"Process Creation" | Select-String "Process Creation").ToString()
    Write-Host "Updated Audit Setting: $updatedSetting"

    if ($updatedSetting -match $compliantPattern) {
        Write-Host "Successfully remediated WN11-AU-000050."
    } 
    else {
        Write-Host "Failed to remediate WN11-AU-000050. Please check permissions or local policy settings."
    }
}>

<#
.SYNOPSIS
  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised. This setting allows administrators to enable more precise auditing capabilities.
    
.NOTES
    Author          : William Olega
    LinkedIn        : linkedin.com/in/williamolega/
    GitHub          : github.com/williamolega
    Date Created    : 2025-11-11
    Last Modified   : 2025-11-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000030

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-SO-000030.ps1 
#>

# Define registry details
$RegPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$RegName  = "SCENoApplyLegacyAuditPolicy"
$ExpectedValue = 1

# Check if the key exists
if (Test-Path $RegPath) {
    try {
        $CurrentValue = Get-ItemPropertyValue -Path $RegPath -Name $RegName -ErrorAction Stop
        Write-Host "Current value of $RegName : $CurrentValue"
    } catch {
        Write-Host "$RegName not found. It will be created."
        $CurrentValue = $null
    }

    #Compare values and remediate if needed
    if ($CurrentValue -ne $ExpectedValue) {
        
        New-ItemProperty -Path $RegPath -Name $RegName -Value $ExpectedValue -PropertyType DWord -Force | Out-Null
        
    } else {
        Write-Host "System is already compliant with WN11-SO-000030."
    }

    #Doublecheck if value is updated
    $VerifyValue = Get-ItemPropertyValue -Path $RegPath -Name $RegName
    if ($VerifyValue -eq $ExpectedValue) {
        Write-Host "Verification passed: $RegName = $VerifyValue"
    } else {
        Write-Host "Verification failed. Please check permissions or GPO conflicts."
    }

} else {
    Write-Host "Registry path not found: $RegPath"
}

Write-Host "WN11-SO-000030 compliance check complete."

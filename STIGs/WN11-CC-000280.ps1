<#
.SYNOPSIS
Remote Desktop Services must always prompt a client for passwords upon connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.
  
.NOTES
    Author          : William Olega
    LinkedIn        : linkedin.com/in/williamolega/
    GitHub          : github.com/williamolega
    Date Created    : 2025-11-12
    Last Modified   : 2025-11-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000280
    
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000280.ps1 
#>

function Set-STIGRegistryValue {
    param(
        [string]$RegPath,
        [string]$RegName,
        [int]$ExpectedValue
    )

    # Check if the registry path exists (creates if missing)
    if (-not (Test-Path $RegPath)) { 
        New-Item -Path $RegPath -Force | Out-Null 
    }

    # Read the current registry value (if it exists)
    $CurrentValue = (Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue).$RegName

    # Compare current vs expected value
    if ($CurrentValue -ne $ExpectedValue) {
        New-ItemProperty -Path $RegPath -Name $RegName -Value $ExpectedValue -PropertyType DWord -Force | Out-Null
        Write-Host "$RegName updated to $ExpectedValue."
    } 
    else {
        Write-Host "$RegName is already compliant."
    }
}

Set-STIGRegistryValue -RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" `
                      -RegName "fPromptForPassword" `
                      -ExpectedValue 1

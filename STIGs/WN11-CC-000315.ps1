<#
.SYNOPSIS
    Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.

.NOTES
    Author          : William Olega
    LinkedIn        : linkedin.com/in/williamolega/
    GitHub          : github.com/williamolega
    Date Created    : 2025-11-11
    Last Modified   : 2025-11-11
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\WN11-CC-000315.ps1 
#>

# Define registry paths
$regPaths = @(
    "HKCU:\Software\Policies\Microsoft\Windows\Installer",
    "HKLM:\Software\Policies\Microsoft\Windows\Installer"
)

foreach ($path in $regPaths) {
    # Create the key if it doesn't exist
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }

    # Check current value of the -Name in the -Path and if there is an error, continue
    $currentValue = Get-ItemPropertyValue -Path $path -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue

    if ($currentValue -ne 0) {
        # Set AlwaysInstallElevated to 0 if missing or not 0
        Set-ItemProperty -Path $path -Name "AlwaysInstallElevated" -Value 0 -Type DWord
        Write-Output "Updated AlwaysInstallElevated to 0 at $path"
    } else {
        Write-Output "AlwaysInstallElevated already set to 0 at $path"
    }
}

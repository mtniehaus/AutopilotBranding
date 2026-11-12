<#
.SYNOPSIS
Autopilot Branding runner script.

.DESCRIPTION
Loads the AutopilotBranding module from the AutopilotBranding folder next to this script and runs the configuration
in AutopilotBranding.json (also next to this script): each enabled task is called with its configured parameters,
and file and folder parameters refer to the Assets folder next to this script.

This script is the same for every configuration; change the configuration (AutopilotBranding.json) with
Show-AutopilotBrandingBuilder or the web builder instead of editing it.

.PARAMETER Force
Run the tasks even if OOBE has already been completed.

.PARAMETER LogFolder
Folder for the log (AutopilotBranding.log).  Defaults to the usual location,
%ProgramData%\Microsoft\AutopilotBranding.  A relative path is resolved against the current location.  The tag file
used by the Intune detection rule is not affected (see -TagFile).

.PARAMETER TagFile
Full path of the tag file used by the Intune detection rule.  Defaults to the usual location,
%ProgramData%\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag.  A relative path is resolved against the current
location.  If you change it, change the app's uninstall command and detection rule to match.
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory = $false)] [Switch] $Force = $false,
	[Parameter(Mandatory = $false)] [string] $LogFolder = "$($env:ProgramData)\Microsoft\AutopilotBranding",
	[Parameter(Mandatory = $false)] [string] $TagFile = "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag"
)

$LogFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFolder)
$TagFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TagFile)

# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
	if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
		$relaunchArgs = @('-ExecutionPolicy', 'Bypass', '-NoProfile', '-File', $PSCommandPath)
		if ($Force) { $relaunchArgs += '-Force' }
		$relaunchArgs += @('-LogFolder', $LogFolder, '-TagFile', $TagFile)
		& "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" @relaunchArgs
		exit $LASTEXITCODE
	}
}

Import-Module (Join-Path $PSScriptRoot 'AutopilotBranding\AutopilotBranding.psd1') -Force

$startArgs = @{
	Force       = $Force
	LogFolder   = $LogFolder
	TagFolder   = Split-Path -Path $TagFile -Parent
	TagFileName = Split-Path -Path $TagFile -Leaf
}
if (-not (Start-AutopilotBranding @startArgs)) {
	exit 0
}

try {
	Invoke-AutopilotBranding -ConfigPath (Join-Path $PSScriptRoot 'AutopilotBranding.json')
} finally {
	Stop-AutopilotBranding
}

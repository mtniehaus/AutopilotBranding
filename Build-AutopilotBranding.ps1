<#
.SYNOPSIS
Generates the Autopilot Branding output folder from a JSON configuration (no UI) and packages it as an Intune
Win32 app (.intunewin).

.DESCRIPTION
Reads the configuration file, validates it, and creates an output folder containing:
  AutopilotBranding.ps1    - runner script that loads the module and calls each enabled task with its parameters
  AutopilotBranding\       - the AutopilotBranding module
  Assets\                  - files and folders referenced by the configuration
  AutopilotBranding.json   - the configuration used

The output folder is then packaged as AutopilotBranding.intunewin (using the SvRooij.ContentPrep.Cmdlet module,
which is installed from the PowerShell Gallery if needed).

Use Show-AutopilotBrandingBuilder.ps1 to edit the configuration interactively.

.PARAMETER ConfigPath
JSON configuration file.  Relative file and folder paths in it are relative to the file's folder.

.PARAMETER OutputPath
Output folder.  Its existing contents are replaced.

.PARAMETER PackagePath
Folder where the .intunewin file is created (default: the output folder's parent folder).  It must not be inside
the output folder.

.PARAMETER LegacyConfigXml
Convert a v3 Config.xml file into a JSON configuration (saved to ConfigPath) instead of building.

.EXAMPLE
.\Build-AutopilotBranding.ps1 -ConfigPath .\AutopilotBranding.json -OutputPath .\Output

Creates .\Output and .\AutopilotBranding.intunewin.

.EXAMPLE
.\Build-AutopilotBranding.ps1 -ConfigPath .\MyConfig.json -OutputPath C:\Build\Output -PackagePath C:\Build\Packages

.EXAMPLE
.\Build-AutopilotBranding.ps1 -LegacyConfigXml C:\Old\AutopilotBranding\Config.xml -ConfigPath .\MyConfig.json
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $false)] [string] $ConfigPath = (Join-Path $PSScriptRoot 'AutopilotBranding.json'),
	[Parameter(Mandatory = $false)] [string] $OutputPath = (Join-Path $PSScriptRoot 'Output'),
	[Parameter(Mandatory = $false)] [string] $PackagePath,
	[Parameter(Mandatory = $false)] [string] $LegacyConfigXml
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Builder\AutopilotBranding.Builder.psm1') -Force

if ($LegacyConfigXml) {
	$configuration = ConvertFrom-ABLegacyConfig -Path $LegacyConfigXml
	Save-ABConfiguration -Configuration $configuration -Path $ConfigPath
	Write-Host "Converted $LegacyConfigXml to $ConfigPath"
	return
}

$ConfigPath = (Resolve-Path $ConfigPath).Path
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
if (-not $PackagePath) {
	$PackagePath = Split-Path -Path $OutputPath -Parent
	if (-not $PackagePath) {
		throw 'The output folder must not be the root of a drive (the .intunewin file is created in its parent folder); specify -PackagePath.'
	}
}
$configuration = Read-ABConfiguration -Path $ConfigPath
$result = New-ABOutput -Configuration $configuration -BasePath (Split-Path $ConfigPath -Parent) -OutputPath $OutputPath -Force

Write-Host "Output created in $($result.OutputPath)"
Write-Host "Runner script:    $($result.RunnerScript)"
Write-Host "Enabled tasks:    $($result.EnabledTasks.Count)"

$intunewin = New-ABIntuneWinPackage -SourcePath $result.OutputPath -DestinationPath $PackagePath -SetupFile (Split-Path $result.RunnerScript -Leaf)
Write-Host "Intune package:   $intunewin"

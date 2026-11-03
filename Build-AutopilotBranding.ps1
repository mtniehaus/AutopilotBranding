<#
.SYNOPSIS
Generates the Autopilot Branding output folder from a JSON configuration (no UI).

.DESCRIPTION
Reads the configuration file, validates it, and creates an output folder containing:
  AutopilotBranding.ps1    - runner script that loads the module and calls each enabled task with its parameters
  AutopilotBranding\       - the AutopilotBranding module
  Assets\                  - files and folders referenced by the configuration
  AutopilotBranding.json   - the configuration used

Use Show-AutopilotBrandingBuilder.ps1 to edit the configuration interactively.

.PARAMETER ConfigPath
JSON configuration file.  Relative file and folder paths in it are relative to the file's folder.

.PARAMETER OutputPath
Output folder.  Its existing contents are replaced.

.PARAMETER LegacyConfigXml
Convert a v3 Config.xml file into a JSON configuration (saved to ConfigPath) instead of building.

.EXAMPLE
.\Build-AutopilotBranding.ps1 -ConfigPath .\AutopilotBranding.json -OutputPath .\Output

.EXAMPLE
.\Build-AutopilotBranding.ps1 -LegacyConfigXml C:\Old\AutopilotBranding\Config.xml -ConfigPath .\MyConfig.json
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $false)] [string] $ConfigPath = (Join-Path $PSScriptRoot 'AutopilotBranding.json'),
	[Parameter(Mandatory = $false)] [string] $OutputPath = (Join-Path $PSScriptRoot 'Output'),
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
$configuration = Read-ABConfiguration -Path $ConfigPath
$result = New-ABOutput -Configuration $configuration -BasePath (Split-Path $ConfigPath -Parent) -OutputPath $OutputPath -Force

Write-Host "Output created in $($result.OutputPath)"
Write-Host "Runner script:    $($result.RunnerScript)"
Write-Host "Enabled tasks:    $($result.EnabledTasks.Count)"

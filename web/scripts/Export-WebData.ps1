<#
.SYNOPSIS
Exports the data the web builder loads (web\dist\data) from the AutopilotBranding module.

.DESCRIPTION
Writes:
  tasks.json      the task definitions (Get-ABTaskDefinition), so the web builder matches the module it packages
  manifest.json   the module version and the lists of module and template files
  module\...      the module files that go into the package (the module without its Template folder)
  template\...    the default project template (AutopilotBranding.json and Assets)

Run it after building the site (npm run build) and before publishing web\dist.

.PARAMETER ModulePath
The AutopilotBranding module folder.

.PARAMETER OutputPath
The data folder to create (its contents are replaced).
#>
[CmdletBinding()]
param (
	[string] $ModulePath = (Join-Path (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'Module') 'AutopilotBranding'),
	[string] $OutputPath = (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'dist') 'data')
)

$ErrorActionPreference = 'Stop'
$ModulePath = (Resolve-Path $ModulePath).Path
Import-Module (Join-Path $ModulePath 'AutopilotBranding.psd1') -Force

if (Test-Path $OutputPath) {
	Remove-Item $OutputPath -Recurse -Force
}
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
$OutputPath = (Resolve-Path $OutputPath).Path
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Copy-Tree([string] $Source, [string] $Destination, [string[]] $Exclude = @()) {
	$files = New-Object System.Collections.Generic.List[string]
	foreach ($file in (Get-ChildItem -LiteralPath $Source -Recurse -File -Force | Sort-Object FullName)) {
		$relative = $file.FullName.Substring($Source.TrimEnd('\', '/').Length + 1).Replace('\', '/')
		if ($Exclude | Where-Object { $relative -like "$_/*" }) {
			continue
		}
		$target = Join-Path $Destination $relative
		New-Item -Path (Split-Path $target -Parent) -ItemType Directory -Force | Out-Null
		Copy-Item -LiteralPath $file.FullName -Destination $target -Force
		$files.Add($relative)
	}
	return , $files.ToArray()
}

$definitions = @(Get-ABTaskDefinition -ModulePath $ModulePath)
[System.IO.File]::WriteAllText((Join-Path $OutputPath 'tasks.json'), (ConvertTo-Json -InputObject $definitions -Depth 8), $utf8)

$moduleFiles = Copy-Tree -Source $ModulePath -Destination (Join-Path $OutputPath 'module') -Exclude @('Template')
$templateFiles = Copy-Tree -Source (Get-ABTemplatePath) -Destination (Join-Path $OutputPath 'template')
$manifest = Import-PowerShellDataFile (Join-Path $ModulePath 'AutopilotBranding.psd1')

$siteManifest = [ordered]@{
	ModuleVersion = [string]$manifest.ModuleVersion
	ModuleFiles   = $moduleFiles
	TemplateFiles = $templateFiles
	Runner        = 'Runner/AutopilotBranding.ps1'
}
[System.IO.File]::WriteAllText((Join-Path $OutputPath 'manifest.json'), (ConvertTo-Json -InputObject $siteManifest -Depth 4), $utf8)
Write-Host "Exported $($definitions.Count) tasks, $($moduleFiles.Count) module files and $($templateFiles.Count) template files to $OutputPath"

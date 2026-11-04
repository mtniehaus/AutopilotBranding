function New-AutopilotBrandingPackage {
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

	Use New-AutopilotBrandingProject to create a project folder (configuration plus sample assets) and
	Show-AutopilotBrandingBuilder to edit the configuration interactively.

	Build-AutopilotBranding is an alias for this cmdlet.  (Build isn't an approved verb in Windows PowerShell 5.1, so
	the cmdlet itself uses New to avoid a warning when the module is imported.)

	.PARAMETER ProjectPath
	Project folder (see New-AutopilotBrandingProject): uses its AutopilotBranding.json and, by default, creates the
	Output folder and the .intunewin file in it.

	.PARAMETER ConfigPath
	JSON configuration file, instead of ProjectPath.  Relative file and folder paths in it are relative to the file's
	folder.  If neither is specified, AutopilotBranding.json in the current folder is used.

	.PARAMETER OutputPath
	Output folder.  Its existing contents are replaced.  Defaults to an Output folder next to the configuration file.

	.PARAMETER PackagePath
	Folder where the .intunewin file is created (default: the output folder's parent folder).  It must not be inside
	the output folder.

	.PARAMETER LegacyConfigXml
	Convert a v3 Config.xml file into a JSON configuration (saved to ConfigPath) instead of building.

	.PARAMETER PassThru
	Return an object describing the output folder, runner script and package.

	.EXAMPLE
	New-AutopilotBrandingPackage -ProjectPath C:\AutopilotBranding\Contoso

	Creates C:\AutopilotBranding\Contoso\Output and C:\AutopilotBranding\Contoso\AutopilotBranding.intunewin.

	.EXAMPLE
	New-AutopilotBrandingPackage -ConfigPath .\AutopilotBranding.json -OutputPath .\Output

	Creates .\Output and .\AutopilotBranding.intunewin.

	.EXAMPLE
	Build-AutopilotBranding -ConfigPath .\MyConfig.json -OutputPath C:\Build\Output -PackagePath C:\Build\Packages

	Uses the Build-AutopilotBranding alias.

	.EXAMPLE
	New-AutopilotBrandingPackage -LegacyConfigXml C:\Old\AutopilotBranding\Config.xml -ConfigPath .\MyConfig.json
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $ProjectPath,
		[Parameter(Mandatory = $false)] [string] $ConfigPath,
		[Parameter(Mandatory = $false)] [string] $OutputPath,
		[Parameter(Mandatory = $false)] [string] $PackagePath,
		[Parameter(Mandatory = $false)] [string] $LegacyConfigXml,
		[Parameter(Mandatory = $false)] [switch] $PassThru
	)

	$ErrorActionPreference = 'Stop'

	if ($ProjectPath -and $ConfigPath) {
		throw 'Specify either -ProjectPath or -ConfigPath, not both.'
	}
	if ($ProjectPath) {
		$ConfigPath = Join-Path (ConvertTo-ABFullPath $ProjectPath) 'AutopilotBranding.json'
	} elseif (-not $ConfigPath) {
		$ConfigPath = Get-ABDefaultConfigurationPath
	}
	$ConfigPath = ConvertTo-ABFullPath $ConfigPath

	if ($LegacyConfigXml) {
		$configuration = ConvertFrom-ABLegacyConfig -Path $LegacyConfigXml
		Save-ABConfiguration -Configuration $configuration -Path $ConfigPath
		Write-Host "Converted $LegacyConfigXml to $ConfigPath"
		return
	}

	if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
		throw "Configuration file not found: $ConfigPath.  Create a project with New-AutopilotBrandingProject, or specify -ProjectPath or -ConfigPath."
	}
	if (-not $OutputPath) {
		$OutputPath = Join-Path (Split-Path -Path $ConfigPath -Parent) 'Output'
	}
	$OutputPath = ConvertTo-ABFullPath $OutputPath
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

	if ($PassThru) {
		[pscustomobject]@{
			OutputPath   = $result.OutputPath
			RunnerScript = $result.RunnerScript
			EnabledTasks = $result.EnabledTasks
			Package      = $intunewin
		}
	}
}

# Build isn't an approved verb in Windows PowerShell 5.1 (it is in PowerShell 7), so the cmdlet uses New and the
# Build-AutopilotBranding name is provided as an alias.
Set-Alias -Name Build-AutopilotBranding -Value New-AutopilotBrandingPackage

function New-AutopilotBrandingProject {
	<#
	.SYNOPSIS
	Creates an Autopilot Branding project folder from the default template included in the module.

	.DESCRIPTION
	A project folder holds your configuration and the files it uses, and is where the output folder and .intunewin
	package are generated:
	  AutopilotBranding.json   - the configuration (starts as the default configuration)
	  Assets\                  - sample files to customize: theme, wallpaper, lock screen image, Start menu and taskbar
	                             layouts, default app associations, OEM logo, Chrome preferences, language XML,
	                             language pack (LPs) and UE-V template folders
	  Output\                  - created by New-AutopilotBrandingPackage / Show-AutopilotBrandingBuilder
	  AutopilotBranding.intunewin

	Replace the sample files with your own, then open the project with Show-AutopilotBrandingBuilder -ProjectPath, or
	build it with New-AutopilotBrandingPackage -ProjectPath (alias Build-AutopilotBranding).

	.PARAMETER Path
	The project folder.  It is created if it doesn't exist.

	.PARAMETER Force
	Use a folder that already contains a project: the configuration and sample files are replaced with the template's.
	Without -Force, a folder that already contains AutopilotBranding.json is refused.

	.EXAMPLE
	New-AutopilotBrandingProject -Path C:\AutopilotBranding\Contoso
	Show-AutopilotBrandingBuilder -ProjectPath C:\AutopilotBranding\Contoso

	.OUTPUTS
	An object with the project folder (Path) and its configuration file (ConfigPath).
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true, Position = 0)] [string] $Path,
		[switch] $Force
	)

	$Path = ConvertTo-ABFullPath $Path
	$configPath = Join-Path $Path 'AutopilotBranding.json'
	if ((Test-Path -LiteralPath $configPath) -and -not $Force) {
		throw "$Path already contains a project (AutopilotBranding.json); specify -Force to replace it with the template."
	}
	if ((Test-Path -LiteralPath $Path) -and -not (Test-Path -LiteralPath $Path -PathType Container)) {
		throw "$Path is a file, not a folder."
	}

	$template = Get-ABTemplatePath
	if ($PSCmdlet.ShouldProcess($Path, 'Create Autopilot Branding project')) {
		if (-not (Test-Path -LiteralPath $Path)) {
			New-Item -Path $Path -ItemType Directory -Force | Out-Null
		}
		Copy-ABItemNoOverwrite -Source (Join-Path $template 'AutopilotBranding.json') -Destination $configPath -Force
		Copy-ABItemNoOverwrite -Source (Join-Path $template 'Assets') -Destination (Join-Path $Path 'Assets') -Force:$Force
		Write-Verbose "Created project $Path"
	}

	[pscustomobject]@{
		Path       = $Path
		ConfigPath = $configPath
	}
}

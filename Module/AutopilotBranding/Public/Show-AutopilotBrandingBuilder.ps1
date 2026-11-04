function Show-AutopilotBrandingBuilder {
	<#
	.SYNOPSIS
	Opens the UI for configuring Autopilot Branding and generating the output folder and .intunewin package.

	.DESCRIPTION
	Lists every configuration task (cmdlet) in the AutopilotBranding module along with the parameters it supports.
	For each task you can choose whether it runs and specify the parameter values.  The choices are saved to a JSON
	file that can be tweaked by hand and loaded again later.

	"Generate output and .intunewin" creates a folder containing the AutopilotBranding module, the files referenced by
	the configuration (Assets), the configuration itself, and AutopilotBranding.ps1, a script that loads the module and
	calls each enabled task with the configured parameters.  That folder is then packaged as an Intune Win32 app
	(AutopilotBranding.intunewin, created in the output folder's parent folder) using the SvRooij.ContentPrep.Cmdlet
	module, which is installed from the PowerShell Gallery if needed.

	Requires Windows (WPF); works with Windows PowerShell 5.1 and PowerShell 7.

	.PARAMETER ConfigPath
	JSON configuration file to open.  Defaults to AutopilotBranding.json in the repository root (when the module is
	loaded from the repository) or in the current folder.

	.PARAMETER OutputPath
	Default output folder.  Defaults to an Output folder next to the configuration file.

	.EXAMPLE
	Import-Module .\Module\AutopilotBranding\AutopilotBranding.psd1
	Show-AutopilotBrandingBuilder -ConfigPath .\AutopilotBranding.json
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $ConfigPath,
		[Parameter(Mandatory = $false)] [string] $OutputPath
	)

	if ($PSVersionTable.PSEdition -ne 'Desktop' -and -not $IsWindows) {
		throw 'The Autopilot Branding builder UI requires Windows.  Use New-AutopilotBrandingPackage (alias Build-AutopilotBranding) to build from a JSON file on other platforms.'
	}

	if (-not $ConfigPath) {
		$ConfigPath = Get-ABDefaultConfigurationPath
	}
	$ConfigPath = ConvertTo-ABFullPath $ConfigPath
	if (-not $OutputPath) {
		$OutputPath = Join-Path (Split-Path -Path $ConfigPath -Parent) 'Output'
	}
	$OutputPath = ConvertTo-ABFullPath $OutputPath

	# WPF requires a single-threaded apartment (the default for both Windows PowerShell and PowerShell 7 on Windows);
	# if this session is MTA, run the builder in a new STA process.
	if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
		$manifest = Join-Path $script:ABModuleRoot 'AutopilotBranding.psd1'
		$command = "Import-Module '{0}'; Show-AutopilotBrandingBuilder -ConfigPath '{1}' -OutputPath '{2}'" -f `
			$manifest.Replace("'", "''"), $ConfigPath.Replace("'", "''"), $OutputPath.Replace("'", "''")
		$encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
		$exe = (Get-Process -Id $PID).Path
		& $exe -NoProfile -STA -ExecutionPolicy Bypass -EncodedCommand $encoded
		return
	}

	Initialize-ABBuilderWindow -ConfigPath $ConfigPath -OutputPath $OutputPath
	try {
		$script:window.ShowDialog() | Out-Null
	}
	finally {
		$script:window = $null
		$script:ui = $null
		$script:State = $null
	}
}

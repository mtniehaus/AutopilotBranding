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

	Without a project or configuration (and no AutopilotBranding.json in the current folder), the builder opens the
	module's default template as an unsaved configuration.  Saving it turns the chosen folder into a project: the
	template files the configuration uses are copied there.  "New project..." creates a project with all of the
	template's sample files (like New-AutopilotBrandingProject).

	.PARAMETER ProjectPath
	Project folder to open (see New-AutopilotBrandingProject).  If it doesn't contain a project yet, one is created
	from the template.

	.PARAMETER ConfigPath
	JSON configuration file to open, instead of ProjectPath.  If neither is specified, AutopilotBranding.json in the
	current folder is opened if it exists.

	.PARAMETER OutputPath
	Default output folder.  Defaults to an Output folder next to the configuration file.

	.EXAMPLE
	New-AutopilotBrandingProject -Path C:\AutopilotBranding\Contoso
	Show-AutopilotBrandingBuilder -ProjectPath C:\AutopilotBranding\Contoso

	.EXAMPLE
	Show-AutopilotBrandingBuilder

	Opens AutopilotBranding.json in the current folder, or the default template if there is none.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $ProjectPath,
		[Parameter(Mandatory = $false)] [string] $ConfigPath,
		[Parameter(Mandatory = $false)] [string] $OutputPath
	)

	if ($PSVersionTable.PSEdition -ne 'Desktop' -and -not $IsWindows) {
		throw 'The Autopilot Branding builder UI requires Windows.  Use New-AutopilotBrandingPackage (alias Build-AutopilotBranding) to build from a JSON file on other platforms.'
	}
	if ($ProjectPath -and $ConfigPath) {
		throw 'Specify either -ProjectPath or -ConfigPath, not both.'
	}

	if ($ProjectPath) {
		$ProjectPath = ConvertTo-ABFullPath $ProjectPath
		$ConfigPath = Join-Path $ProjectPath 'AutopilotBranding.json'
		if (-not (Test-Path -LiteralPath $ConfigPath)) {
			New-AutopilotBrandingProject -Path $ProjectPath | Out-Null
		}
	} elseif ($ConfigPath) {
		$ConfigPath = ConvertTo-ABFullPath $ConfigPath
	} else {
		# AutopilotBranding.json in the current folder, or the default template (unsaved) if there is none
		$ConfigPath = Get-ABDefaultConfigurationPath
		if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
			$ConfigPath = ''
		}
	}
	if ($OutputPath) {
		$OutputPath = ConvertTo-ABFullPath $OutputPath
	} elseif ($ConfigPath) {
		$OutputPath = Join-Path (Split-Path -Path $ConfigPath -Parent) 'Output'
	}

	# WPF requires a single-threaded apartment (the default for both Windows PowerShell and PowerShell 7 on Windows);
	# if this session is MTA, run the builder in a new STA process.
	if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
		$manifest = Join-Path $script:ABModuleRoot 'AutopilotBranding.psd1'
		$command = "Import-Module '{0}'; Show-AutopilotBrandingBuilder" -f $manifest.Replace("'", "''")
		if ($ConfigPath) { $command += " -ConfigPath '{0}'" -f $ConfigPath.Replace("'", "''") }
		if ($OutputPath) { $command += " -OutputPath '{0}'" -f $OutputPath.Replace("'", "''") }
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

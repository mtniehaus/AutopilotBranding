function Set-ABChromeConfig {
	<#
	.SYNOPSIS
	Configures Chrome initial preferences and removes the Chrome desktop shortcut.
	.DESCRIPTION
	Needs to run after Chrome is installed (e.g. by Install-ABWinGetPackages) but before a user signs in.  See
	https://www.chromium.org/administrators/configuring-other-preferences/ for the available preferences.
	.PARAMETER InitialPreferencesPath
	Chrome initial_preferences file.
	.PARAMETER RemoveDesktopShortcut
	Remove the public Google Chrome desktop shortcut.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $InitialPreferencesPath,
		[Parameter(Mandatory = $false)] [bool] $RemoveDesktopShortcut = $true
	)

	Write-ABLog 'Copying Chrome initial_preferences file'
	Copy-ABFile -Path $InitialPreferencesPath -Destination "$($env:ProgramFiles)\Google\Chrome\Application\initial_preferences"
	if ($RemoveDesktopShortcut -and (Test-Path "$($env:PUBLIC)\Desktop\Google Chrome.lnk")) {
		Write-ABLog 'Removing Chrome desktop shortcut'
		Remove-Item "$($env:PUBLIC)\Desktop\Google Chrome.lnk" -Force
	}
}

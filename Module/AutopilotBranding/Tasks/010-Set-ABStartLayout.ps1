function Set-ABStartLayout {
	<#
	.SYNOPSIS
	Applies a custom Start menu layout for new users (and existing user profiles).
	.DESCRIPTION
	On Windows 10 the LayoutModification.xml file is copied into the default user profile.  On Windows 11 the
	start2.bin (pinned apps) and settings.dat files are copied into the Start menu package folder of the default
	user profile.  Supply the files for the OS versions you deploy; files that aren't specified are skipped.
	The files are also copied into user profiles that already exist (see Start-AutopilotBranding
	-IncludeExistingProfiles).
	.PARAMETER LayoutXmlPath
	Windows 10 only: Start layout XML file (copied to LayoutModification.xml in the default user profile).
	.PARAMETER Start2BinPath
	Windows 11 only: start2.bin file containing the pinned Start menu apps.
	.PARAMETER SettingsDatPath
	Windows 11 only: settings.dat file for the Start menu package.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $LayoutXmlPath,
		[Parameter(Mandatory = $false)] [string] $Start2BinPath,
		[Parameter(Mandatory = $false)] [string] $SettingsDatPath
	)

	# The default user profile (new users) and, if included, existing user profiles (see Start-AutopilotBranding)
	$profilePaths = @(Get-ABUserProfilePaths)
	if (Test-ABLegacyStartMenu) {
		if (-not $LayoutXmlPath) {
			Write-ABLog 'No Windows 10 layout XML specified, skipping Start layout'
			return
		}
		foreach ($profilePath in $profilePaths) {
			Write-ABLog "Importing layout into $($profilePath): $LayoutXmlPath"
			Copy-ABFile -Path $LayoutXmlPath -Destination "$profilePath\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
		}
	} else {
		if (-not $Start2BinPath) {
			Write-ABLog 'No start2.bin specified, skipping Start layout'
			return
		}
		foreach ($profilePath in $profilePaths) {
			$packageFolder = "$profilePath\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy"
			Write-ABLog "Copying Start menu layout into $($profilePath): $Start2BinPath"
			Copy-ABFile -Path $Start2BinPath -Destination "$packageFolder\LocalState\start2.bin"
			if ($SettingsDatPath) {
				Copy-ABFile -Path $SettingsDatPath -Destination "$packageFolder\Settings\settings.dat"
			}
		}
	}
}

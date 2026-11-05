function Set-ABSearchBoxMode {
	<#
	.SYNOPSIS
	Sets how the taskbar search box is shown for new users (and existing user profiles).
	.DESCRIPTION
	Windows sets the search box mode when a user's profile is created, so a value in the default user profile is
	overwritten; a RunOnce entry in the default user profile sets SearchboxTaskbarMode again at first sign-in.  For
	user profiles that already exist (see Start-AutopilotBranding -IncludeExistingProfiles) the value is also set
	directly.  With UsePolicy, the "Configures search on the taskbar" policy is set instead, for the whole device:
	that doesn't depend on user profiles, but users can't change the setting.
	.PARAMETER Mode
	Hidden, IconOnly, SearchBox, or IconAndLabel.
	.PARAMETER UsePolicy
	Set the machine policy (SearchOnTaskbarMode) instead of the per-user setting.  Users can't change it.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [ValidateSet('Hidden', 'IconOnly', 'SearchBox', 'IconAndLabel')] [string] $Mode = 'IconOnly',
		[Parameter(Mandatory = $false)] [bool] $UsePolicy = $false
	)

	$value = @{ Hidden = 0; IconOnly = 1; SearchBox = 2; IconAndLabel = 3 }[$Mode]
	if ($UsePolicy) {
		Write-ABLog "Setting the search on the taskbar policy to $Mode ($value)"
		Set-ABRegistryValue -Path 'SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name SearchOnTaskbarMode -Type REG_DWORD -Value $value
		return
	}
	Write-ABLog "Setting search box mode to $Mode ($value) via RunOnce"
	$runOnceCommand = "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /t REG_DWORD /v SearchboxTaskbarMode /d $value /f"
	Set-ABRegistryValue -Hive DefaultUser -Path 'Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'SetSearchIconOnly' -Type REG_SZ -Value $runOnceCommand
	Set-ABRegistryValue -Hive ExistingUsers -Path 'Software\Microsoft\Windows\CurrentVersion\Search' -Name SearchboxTaskbarMode -Type REG_DWORD -Value $value
}

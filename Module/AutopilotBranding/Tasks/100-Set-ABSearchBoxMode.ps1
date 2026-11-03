function Set-ABSearchBoxMode {
	<#
	.SYNOPSIS
	Sets how the taskbar search box is shown for new users.
	.DESCRIPTION
	Adds a RunOnce entry to the default user profile that sets SearchboxTaskbarMode at first sign-in.
	.PARAMETER Mode
	Hidden, IconOnly, SearchBox, or IconAndLabel.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [ValidateSet('Hidden', 'IconOnly', 'SearchBox', 'IconAndLabel')] [string] $Mode = 'IconOnly'
	)

	$value = @{ Hidden = 0; IconOnly = 1; SearchBox = 2; IconAndLabel = 3 }[$Mode]
	Write-ABLog "Setting search box mode to $Mode ($value) via RunOnce"
	$runOnceCommand = "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /t REG_DWORD /v SearchboxTaskbarMode /d $value /f"
	Set-ABRegistryValue -Hive DefaultUser -Path 'Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'SetSearchIconOnly' -Type REG_SZ -Value $runOnceCommand
}

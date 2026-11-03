function Set-ABTaskbarLayout {
	<#
	.SYNOPSIS
	Applies a custom Windows 11 taskbar layout.
	.DESCRIPTION
	Copies the taskbar layout XML to C:\Windows\OEM and configures the "Start Layout" policy to use it.  Optionally
	prevents the Microsoft Store from being pinned to the taskbar for new users.  This is skipped on Windows 10.
	.PARAMETER TaskbarLayoutPath
	Taskbar layout modification XML file.
	.PARAMETER UnpinStore
	Unpin the Microsoft Store app from the taskbar for new users.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $TaskbarLayoutPath,
		[Parameter(Mandatory = $false)] [bool] $UnpinStore = $true
	)

	if (Test-ABLegacyStartMenu) {
		Write-ABLog 'Skipping taskbar layout (Windows 10)'
		return
	}

	Write-ABLog "Importing Taskbar layout: $TaskbarLayoutPath"
	Copy-ABFile -Path $TaskbarLayoutPath -Destination "$($env:SystemRoot)\OEM\TaskbarLayoutModification.xml"

	Write-ABLog "Set 'Start Layout' policy settings to apply the custom taskbar layout"
	Set-ABRegistryValue -Path 'SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name StartLayoutFile -Type REG_EXPAND_SZ -Value '%SystemRoot%\OEM\TaskbarLayoutModification.xml'
	Set-ABRegistryValue -Path 'SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name LockedStartLayout -Type REG_DWORD -Value 1

	if ($UnpinStore) {
		Write-ABLog 'Unpin the Microsoft Store app from the taskbar'
		Set-ABRegistryValue -Hive DefaultUser -Path 'Software\Policies\Microsoft\Windows\Explorer' -Name NoPinningStoreToTaskbar -Type REG_DWORD -Value 1
	}
}

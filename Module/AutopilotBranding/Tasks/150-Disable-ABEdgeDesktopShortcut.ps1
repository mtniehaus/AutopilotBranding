function Disable-ABEdgeDesktopShortcut {
	<#
	.SYNOPSIS
	Prevents Edge from creating a desktop shortcut and removes the existing one.
	.DESCRIPTION
	The shortcut roams to OneDrive (with Known Folder Move) and creates duplicate shortcuts.
	#>
	[CmdletBinding()]
	param ()

	Write-ABLog 'Turning off (old) Edge desktop shortcut'
	Set-ABRegistryValue -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name DisableEdgeDesktopShortcutCreation -Type REG_DWORD -Value 1
	Write-ABLog 'Turning off Edge desktop icon'
	Set-ABRegistryValue -Path 'SOFTWARE\Policies\Microsoft\EdgeUpdate' -Name CreateDesktopShortcutDefault -Type REG_DWORD -Value 0
	Set-ABRegistryValue -Path 'SOFTWARE\Policies\Microsoft\EdgeUpdate' -Name RemoveDesktopShortcutDefault -Type REG_DWORD -Value 2
	if (Test-Path "$($env:PUBLIC)\Desktop\Microsoft Edge.lnk") {
		Write-ABLog 'Removing Edge desktop shortcut'
		Remove-Item "$($env:PUBLIC)\Desktop\Microsoft Edge.lnk" -Force
	}
}

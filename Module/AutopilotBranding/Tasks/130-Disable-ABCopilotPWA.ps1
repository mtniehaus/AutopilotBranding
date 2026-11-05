function Disable-ABCopilotPWA {
	<#
	.SYNOPSIS
	Prevents the Copilot PWA from being automatically installed for new users.
	#>
	[CmdletBinding()]
	param ()

	Write-ABLog 'Preventing the Copilot PWA from being installed'
	Set-ABRegistryValue -Hive DefaultUser -Path 'Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs' -Name CopilotPWAPreinstallCompleted -Type REG_DWORD -Value 1
}

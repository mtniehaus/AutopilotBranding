function Disable-ABStartOnFirstLogon {
	<#
	.SYNOPSIS
	Stops the Start menu from opening automatically the first time each new user signs in.
	#>
	[CmdletBinding()]
	param ()

	Write-ABLog 'Stopping the Start menu from opening on first logon'
	Set-ABRegistryValue -Hive DefaultUser -Path 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name StartShownOnUpgrade -Type REG_DWORD -Value 1
}

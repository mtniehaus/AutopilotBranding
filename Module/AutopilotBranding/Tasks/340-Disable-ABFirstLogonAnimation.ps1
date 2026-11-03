function Disable-ABFirstLogonAnimation {
	<#
	.SYNOPSIS
	Shows the desktop faster: skips the first sign-in animation (FSIA) and turns off the delayed desktop switch.
	#>
	[CmdletBinding()]
	param ()

	Write-ABLog 'Skipping FSIA and turning off delayed desktop switch'
	$registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
	New-ItemProperty -Path $registryPath -Name 'EnableFirstLogonAnimation' -Value 0 -PropertyType DWord -Force | Out-Null
	New-ItemProperty -Path $registryPath -Name 'DelayedDesktopSwitchTimeout' -Value 0 -PropertyType DWord -Force | Out-Null
}

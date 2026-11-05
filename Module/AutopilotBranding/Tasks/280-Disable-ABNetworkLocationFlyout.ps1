function Disable-ABNetworkLocationFlyout {
	<#
	.SYNOPSIS
	Turns off the "allow your PC to be discoverable" network location fly-out.
	#>
	[CmdletBinding()]
	param ()

	Write-ABLog 'Turning off network location fly-out'
	Set-ABRegistryValue -Path 'SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff'
}

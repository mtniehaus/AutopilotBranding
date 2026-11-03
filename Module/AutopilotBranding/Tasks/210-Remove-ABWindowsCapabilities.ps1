function Remove-ABWindowsCapabilities {
	<#
	.SYNOPSIS
	Removes preinstalled Windows capabilities (features on demand).
	.PARAMETER CapabilityNames
	Capability names as returned by Get-WindowsCapability -Online, excluding the tildes and version
	(e.g. App.StepsRecorder), one per line.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string[]] $CapabilityNames
	)

	$installed = Get-WindowsCapability -Online | Where-Object { $_.State -eq 'Installed' }
	foreach ($capability in $installed) {
		if ($CapabilityNames -contains $capability.Name.Split('~')[0]) {
			Write-ABLog "Removing Windows capability: $($capability.Name)"
			try {
				Remove-WindowsCapability -Online -Name $capability.Name | Out-Null
			}
			catch {
				Write-ABLog "  Unable to remove Windows capability: $_"
			}
		}
	}
}

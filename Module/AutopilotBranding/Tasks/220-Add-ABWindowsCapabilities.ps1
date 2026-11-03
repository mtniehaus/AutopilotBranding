function Add-ABWindowsCapabilities {
	<#
	.SYNOPSIS
	Adds Windows capabilities (features on demand), downloading them from Windows Update.
	.DESCRIPTION
	See https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod for
	the available features.  If you added a language pack, add its language features here too
	(e.g. Language.Basic~~~es-ES~0.0.1.0).
	.PARAMETER CapabilityNames
	Capability names (e.g. Microsoft.Windows.Sense.Client~~~~, NetFX3~~~~), one per line.
	.PARAMETER BypassWsus
	If the device is configured to use WSUS, temporarily turn that off so the features come from Windows Update.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string[]] $CapabilityNames,
		[Parameter(Mandatory = $false)] [bool] $BypassWsus = $true
	)

	$auPath = 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU'
	$currentWU = (Get-ItemProperty -Path $auPath -ErrorAction Ignore).UseWuServer
	$wsusDisabled = $false
	if ($BypassWsus -and $currentWU -eq 1) {
		Write-ABLog 'Turning off WSUS'
		Set-ItemProperty -Path $auPath -Name 'UseWuServer' -Value 0
		Restart-Service wuauserv
		$wsusDisabled = $true
	}

	try {
		foreach ($name in $CapabilityNames) {
			Write-ABLog "Adding Windows capability: $name"
			try {
				$result = Add-WindowsCapability -Online -Name $name
				if ($result.RestartNeeded) {
					Write-ABLog "  Capability $name was installed but requires a restart"
				}
			}
			catch {
				Write-ABLog "  Unable to add Windows capability: $_"
			}
		}
	}
	finally {
		if ($wsusDisabled) {
			Write-ABLog 'Turning on WSUS'
			Set-ItemProperty -Path $auPath -Name 'UseWuServer' -Value 1
			Restart-Service wuauserv
		}
	}
}

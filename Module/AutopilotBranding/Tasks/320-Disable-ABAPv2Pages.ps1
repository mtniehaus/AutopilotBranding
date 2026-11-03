function Disable-ABAPv2Pages {
	<#
	.SYNOPSIS
	Hides the extra OOBE pages (privacy, voice, etc.) shown with Autopilot device preparation (APv2).
	.DESCRIPTION
	It's too late to do anything about the EULA.  See https://call4cloud.nl/autopilot-device-preparation-hide-privacy-settings/
	#>
	[CmdletBinding()]
	param ()

	$registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE'
	New-ItemProperty -Path $registryPath -Name 'DisablePrivacyExperience' -Value 1 -PropertyType DWord -Force | Out-Null
	New-ItemProperty -Path $registryPath -Name 'DisableVoice' -Value 1 -PropertyType DWord -Force | Out-Null
	New-ItemProperty -Path $registryPath -Name 'PrivacyConsentStatus' -Value 1 -PropertyType DWord -Force | Out-Null
	New-ItemProperty -Path $registryPath -Name 'ProtectYourPC' -Value 3 -PropertyType DWord -Force | Out-Null
	Write-ABLog 'APv2 extra pages disabled'
}

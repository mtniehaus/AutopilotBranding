function Set-ABTimeZone {
	<#
	.SYNOPSIS
	Sets the time zone, or enables location services so that it is set automatically.
	.DESCRIPTION
	If a time zone is specified it is set immediately.  Otherwise location services are enabled so that the time zone
	will be set automatically (even when the privacy page is skipped in OOBE).
	.PARAMETER TimeZone
	Time zone ID (e.g. "Pacific Standard Time", see Get-TimeZone -ListAvailable).  Leave empty to detect automatically.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $TimeZone = ''
	)

	if ($TimeZone) {
		Write-ABLog "Setting time zone: $TimeZone"
		Set-TimeZone -Id $TimeZone
	} else {
		Write-ABLog 'Enabling location services for automatic time zone'
		# Use the same mechanism as the Settings app; directly setting the sensor override registry value gets reverted on newer builds (issue #106)
		Start-Process -FilePath "$env:windir\System32\SystemSettingsAdminFlows.exe" -ArgumentList 'SetCamSystemGlobal location 1' -Wait -NoNewWindow
		Start-Service -Name 'lfsvc' -ErrorAction SilentlyContinue
		Set-Service -Name 'tzautoupdate' -StartupType Automatic -ErrorAction SilentlyContinue
	}
}

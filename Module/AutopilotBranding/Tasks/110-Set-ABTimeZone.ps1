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
		$enabled = $false
		$adminFlows = "$env:windir\System32\SystemSettingsAdminFlows.exe"
		if (Test-Path $adminFlows) {
			try {
				$proc = Start-Process -FilePath $adminFlows -ArgumentList 'SetCamSystemGlobal location 1' -Wait -NoNewWindow -PassThru -ErrorAction Stop
				Write-ABLog "SystemSettingsAdminFlows.exe exit code: $($proc.ExitCode)"
				$enabled = ($proc.ExitCode -eq 0)
			} catch {
				Write-ABLog "SystemSettingsAdminFlows.exe failed: $_"
			}
		} else {
			Write-ABLog "$adminFlows not found"
		}

		if (-not $enabled) {
			# Fall back to setting the registry values directly (works on older builds)
			Write-ABLog 'Falling back to registry settings for location services'
			$consentPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
			$sensorPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
			foreach ($path in $consentPath, $sensorPath) {
				if (-not (Test-Path $path)) {
					New-Item -Path $path -Force | Out-Null
				}
			}
			Set-ItemProperty -Path $consentPath -Name 'Value' -Type 'String' -Value 'Allow' -Force
			Set-ItemProperty -Path $sensorPath -Name 'SensorPermissionState' -Type 'DWord' -Value 1 -Force
		}

		Start-Service -Name 'lfsvc' -ErrorAction SilentlyContinue
		Set-Service -Name 'tzautoupdate' -StartupType Automatic -ErrorAction SilentlyContinue
	}
}

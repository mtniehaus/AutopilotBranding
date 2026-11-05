function Set-ABOEMInfo {
	<#
	.SYNOPSIS
	Configures OEM branding and support information (shown in Settings > System > About).
	.DESCRIPTION
	By default the manufacturer and model are read from the hardware (for Lenovo devices the friendly model name is
	used); the Manufacturer and Model parameters are used if the hardware doesn't report them or if
	UseDetectedHardware is turned off.  The logo is only supported on Windows 10.
	.PARAMETER Manufacturer
	Manufacturer name (fallback when the hardware value isn't used).
	.PARAMETER Model
	Model name (fallback when the hardware value isn't used).
	.PARAMETER UseDetectedHardware
	Use the manufacturer and model reported by the hardware when available.
	.PARAMETER SupportPhone
	Support phone number.
	.PARAMETER SupportHours
	Support hours.
	.PARAMETER SupportURL
	Support web site URL.
	.PARAMETER LogoPath
	Windows 10 only: 120x120 BMP logo file (copied to C:\Windows).
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $Manufacturer = '',
		[Parameter(Mandatory = $false)] [string] $Model = '',
		[Parameter(Mandatory = $false)] [bool] $UseDetectedHardware = $true,
		[Parameter(Mandatory = $false)] [string] $SupportPhone = '',
		[Parameter(Mandatory = $false)] [string] $SupportHours = '',
		[Parameter(Mandatory = $false)] [string] $SupportURL = '',
		[Parameter(Mandatory = $false)] [string] $LogoPath
	)

	Write-ABLog 'Configuring OEM branding info'
	$oemPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
	if (-not (Test-Path $oemPath)) {
		New-Item -Path $oemPath -Force | Out-Null
	}

	$oemVendor = $Manufacturer
	$oemModel = $Model
	if ($UseDetectedHardware) {
		$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
		if ($cs -and -not [string]::IsNullOrWhiteSpace($cs.Manufacturer)) {
			$oemVendor = $cs.Manufacturer
		}

		$detectedModel = $null
		# For Lenovo the friendly model is in the 'Version' property; 'Name' returns a SKU.
		if ($oemVendor -match 'Lenovo') {
			$csp = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
			if ($csp -and -not [string]::IsNullOrWhiteSpace($csp.Version)) {
				$detectedModel = $csp.Version
			}
		}
		if (-not $detectedModel -and $cs -and -not [string]::IsNullOrWhiteSpace($cs.Model)) {
			$detectedModel = $cs.Model
		}
		if ($detectedModel) {
			$oemModel = $detectedModel
		}
	}
	Write-ABLog "Manufacturer: $oemVendor"
	Write-ABLog "Model: $oemModel"

	$values = [ordered]@{
		Manufacturer = $oemVendor
		Model        = $oemModel
		SupportPhone = $SupportPhone
		SupportHours = $SupportHours
		SupportURL   = $SupportURL
	}
	foreach ($name in $values.Keys) {
		if (-not [string]::IsNullOrWhiteSpace($values[$name])) {
			New-ItemProperty -Path $oemPath -Name $name -PropertyType String -Value $values[$name] -Force | Out-Null
		}
	}

	if ($LogoPath) {
		if (Test-ABLegacyStartMenu) {
			if (Test-Path $LogoPath) {
				$logoDest = "$($env:SystemRoot)\$(Split-Path -Path $LogoPath -Leaf)"
				Write-ABLog "Copying OEM logo to $logoDest"
				Copy-ABFile -Path $LogoPath -Destination $logoDest
				New-ItemProperty -Path $oemPath -Name 'Logo' -PropertyType String -Value $logoDest -Force | Out-Null
			} else {
				Write-ABLog "OEM logo not found: $LogoPath"
			}
		} else {
			Write-ABLog "Windows 11 doesn't support the OEM logo, skipping"
		}
	}
	Write-ABLog 'OEM branding info set'
}

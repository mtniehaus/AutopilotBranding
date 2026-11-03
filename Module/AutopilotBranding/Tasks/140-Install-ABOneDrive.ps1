function Install-ABOneDrive {
	<#
	.SYNOPSIS
	Installs the latest OneDrive client per-machine.
	.DESCRIPTION
	Downloads and installs OneDriveSetup.exe with /allusers, removes the per-user OneDriveSetup Run entry from the
	default user profile (which would otherwise start multiple OneDrive instances at sign-in), and configures OneDrive
	to start from the machine-wide location.
	.PARAMETER Url
	Download URL for the x64 OneDriveSetup.exe.
	.PARAMETER ArmUrl
	Download URL for the ARM64 OneDriveSetup.exe.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $Url = 'https://go.microsoft.com/fwlink/?linkid=844652',
		[Parameter(Mandatory = $false)] [string] $ArmUrl = 'https://go.microsoft.com/fwlink/?linkid=2282608'
	)

	if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -and $ArmUrl) {
		$downloadUrl = $ArmUrl
	} else {
		$downloadUrl = $Url
	}
	$dest = "$($env:TEMP)\OneDriveSetup.exe"
	Invoke-ABDownload -Url $downloadUrl -Destination $dest
	Write-ABLog "Installing: $dest"
	$proc = Start-Process $dest -ArgumentList '/allusers /silent' -WindowStyle Hidden -PassThru
	$proc.WaitForExit()
	Write-ABLog "OneDriveSetup exit code: $($proc.ExitCode)"

	Mount-ABDefaultUserHive
	try {
		$runKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
		$regRunPath = "Registry::HKEY_LOCAL_MACHINE\$($script:ABDefaultUserHiveName)\$runKey"
		if (-not (Test-Path -Path $regRunPath)) {
			Write-ABLog 'Default user Run key not found, creating it'
			Set-ABRegistryValue -Hive DefaultUser -Path $runKey
		}

		# The per-user OneDriveSetup entry (C:\Windows\System32\OneDriveSetup.exe /thfirstsetup) causes multiple
		# OneDrive instances to launch at sign-in.  It is no longer needed once the machine-wide installer has run.
		if (Get-ItemProperty -Path $regRunPath -Name 'OneDriveSetup' -ErrorAction SilentlyContinue) {
			Write-ABLog "Per-user 'OneDriveSetup' Run entry still exists, removing it"
			& reg.exe delete "$(Get-ABDefaultUserRegistryRoot)\$runKey" /v 'OneDriveSetup' /f /reg:64 2>&1 | Out-Null
		} else {
			Write-ABLog "Per-user 'OneDriveSetup' Run entry not found"
		}

		# OneDriveSetup should set this but it can take an additional reboot; this starts OneDrive at first sign-in.
		Write-ABLog 'Setting OneDrive to autostart from the machine-wide location'
		New-ItemProperty -Path $regRunPath -Name 'OneDrive' -Value '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background' -PropertyType String -Force | Out-Null
	}
	finally {
		Dismount-ABDefaultUserHive
	}
}

function Install-ABOneDrive {
	<#
	.SYNOPSIS
	Installs the latest OneDrive client per-machine.
	.DESCRIPTION
	Downloads and installs OneDriveSetup.exe with /allusers, removes the per-user OneDriveSetup Run entry from the
	default user profile (and existing user profiles, see Start-AutopilotBranding -IncludeExistingProfiles) (which would otherwise start multiple OneDrive instances at sign-in), and configures OneDrive
	to start from the machine-wide location (only if the machine-wide OneDrive.exe exists after setup).
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

	if ((Test-ABArm64) -and $ArmUrl) {
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

	# Only repoint the default user Run key when the per-machine OneDrive actually exists, otherwise OneDrive would never start
	$oneDriveExe = "$($env:ProgramFiles)\Microsoft OneDrive\OneDrive.exe"
	if (-not (Test-Path $oneDriveExe)) {
		throw "Per-machine OneDrive not found after running OneDriveSetup ($oneDriveExe); the default user Run key was not changed"
	}

	Mount-ABDefaultUserHive
	try {
		# The default user profile (new users) and, if included, existing user profiles (see Start-AutopilotBranding)
		$runKey = 'Software\Microsoft\Windows\CurrentVersion\Run'
		foreach ($root in @(Get-ABUserRegistryRoots)) {
			$regRunPath = "$(ConvertTo-ABProviderPath $root.Root)\$runKey"
			if (-not (Test-Path -Path $regRunPath)) {
				New-Item -Path $regRunPath -Force | Out-Null
			}

			# The per-user OneDriveSetup entry (C:\Windows\System32\OneDriveSetup.exe /thfirstsetup) causes multiple
			# OneDrive instances to launch at sign-in.  It is no longer needed once the machine-wide installer has run.
			if (Get-ItemProperty -Path $regRunPath -Name 'OneDriveSetup' -ErrorAction SilentlyContinue) {
				Write-ABLog "Removing the per-user 'OneDriveSetup' Run entry ($($root.Name))"
				Remove-ItemProperty -Path $regRunPath -Name 'OneDriveSetup' -Force
			}

			# OneDriveSetup should set this but it can take an additional reboot; this starts OneDrive at first sign-in.
			Write-ABLog "Setting OneDrive to autostart from the machine-wide location ($($root.Name))"
			New-ItemProperty -Path $regRunPath -Name 'OneDrive' -Value "`"$oneDriveExe`" /background" -PropertyType String -Force | Out-Null
		}
	}
	finally {
		Dismount-ABDefaultUserHive
	}
}

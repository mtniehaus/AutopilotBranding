function Set-ABLockScreen {
	<#
	.SYNOPSIS
	Configures the lock screen image.
	.DESCRIPTION
	Copies the image to C:\Windows\Web\Wallpaper\Autopilot and configures it through the PersonalizationCSP registry
	keys.  See https://www.systemcenterdudes.com/apply-custom-lock-screen-wallpaper-using-intune/
	.PARAMETER ImagePath
	Lock screen image file.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $ImagePath
	)

	Write-ABLog 'Configuring lock screen image'
	$lockScreenImage = "$($env:SystemRoot)\Web\Wallpaper\Autopilot\$(Split-Path -Path $ImagePath -Leaf)"
	Copy-ABFile -Path $ImagePath -Destination $lockScreenImage

	$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'
	if (-not (Test-Path -Path $regPath)) {
		New-Item -Path $regPath -Force | Out-Null
	}
	New-ItemProperty -Path $regPath -Name LockScreenImagePath -Value $lockScreenImage -PropertyType String -Force | Out-Null
	New-ItemProperty -Path $regPath -Name LockScreenImageUrl -Value $lockScreenImage -PropertyType String -Force | Out-Null
	New-ItemProperty -Path $regPath -Name LockScreenImageStatus -Value 1 -PropertyType DWORD -Force | Out-Null
}

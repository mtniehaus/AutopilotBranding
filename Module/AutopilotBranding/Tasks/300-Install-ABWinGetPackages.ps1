function Install-ABWinGetPackages {
	<#
	.SYNOPSIS
	Installs apps using WinGet (machine scope).
	.DESCRIPTION
	Installs the Microsoft.WinGet.Client module, repairs/updates WinGet, installs the Visual C++ runtime that WinGet
	needs when running as SYSTEM (matching the OS architecture), and then installs each package.  A failure in one of
	the preparation steps is logged and the remaining steps still run; WinGet is in-box on current Windows 11 builds.
	.PARAMETER PackageIds
	WinGet package IDs (e.g. Google.Chrome) or Microsoft Store IDs (e.g. 9WZDNCRD29V9), one per line.
	.PARAMETER VCRedistUrl
	Download URL for the x64 Visual C++ redistributable.  Leave empty to skip installing it on x64 devices.
	.PARAMETER VCRedistArmUrl
	Download URL for the ARM64 Visual C++ redistributable.  Leave empty to skip installing it on ARM64 devices.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string[]] $PackageIds,
		[Parameter(Mandatory = $false)] [string] $VCRedistUrl = 'https://aka.ms/vs/17/release/vc_redist.x64.exe',
		[Parameter(Mandatory = $false)] [string] $VCRedistArmUrl = 'https://aka.ms/vs/17/release/vc_redist.arm64.exe'
	)

	try {
		Assert-ABNuGetProvider
		Write-ABLog 'Installing Microsoft.WinGet.Client module'
		Install-Module -Name Microsoft.WinGet.Client -Force -Scope AllUsers -Repository PSGallery -ErrorAction Stop | Out-Null
		Import-Module Microsoft.WinGet.Client -ErrorAction Stop
	}
	catch {
		Write-ABLog "Unable to install the WinGet.Client module: $_"
	}

	# Repair-WinGetPackageManager updates WinGet, but it periodically breaks (unsupported in Windows PowerShell, CDN
	# timeouts, etc.).  WinGet is in-box on current Windows 11 builds, so a failure here isn't fatal.
	Write-ABLog 'Installing latest WinGet package and dependencies'
	try {
		Repair-WinGetPackageManager -Force -Latest -ErrorAction Stop | Out-Null
	}
	catch {
		Write-ABLog "  WinGet repair failed, will use the existing WinGet if present: $_"
	}

	# Use the Visual C++ runtime that matches the OS architecture
	$vcUrl = if (Test-ABArm64) { $VCRedistArmUrl } else { $VCRedistUrl }
	if ($vcUrl) {
		try {
			$vcPath = Join-Path $env:TEMP 'vc_redist.exe'
			Invoke-ABDownload -Url $vcUrl -Destination $vcPath
			Write-ABLog 'Installing Visual C++ redistributable'
			Start-Process -FilePath $vcPath -ArgumentList '/install', '/quiet', '/norestart' -Wait
			Remove-Item $vcPath -Force -ErrorAction SilentlyContinue
		}
		catch {
			Write-ABLog "  Unable to install the Visual C++ redistributable: $_"
		}
	}

	# Use the newest winget.exe (the version is part of the package folder name)
	$wingetExe = Resolve-Path "$($env:ProgramFiles)\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
		Sort-Object { try { [version](($_.Path -split '_')[1]) } catch { [version]'0.0' } } |
		Select-Object -Last 1 -ExpandProperty Path
	if (-not $wingetExe) {
		throw 'winget.exe not found, unable to install the WinGet packages'
	}
	$wingetVer = & "$wingetExe" --version
	Write-ABLog "WinGet version is: $wingetVer"

	foreach ($id in $PackageIds) {
		Write-ABLog "WinGet installing: $id"
		try {
			& "$wingetExe" install $id --silent --scope machine --accept-package-agreements --accept-source-agreements
			Write-ABLog "  WinGet exit code: $LASTEXITCODE"
		}
		catch {
			Write-ABLog "WinGet installing error: $_"
		}
	}
}

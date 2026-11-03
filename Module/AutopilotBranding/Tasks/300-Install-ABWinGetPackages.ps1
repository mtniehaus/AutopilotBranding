function Install-ABWinGetPackages {
	<#
	.SYNOPSIS
	Installs apps using WinGet (machine scope).
	.DESCRIPTION
	Installs the Microsoft.WinGet.Client module, repairs/updates WinGet, installs the Visual C++ runtime that WinGet
	needs when running as SYSTEM, and then installs each package.
	.PARAMETER PackageIds
	WinGet package IDs (e.g. Google.Chrome) or Microsoft Store IDs (e.g. 9WZDNCRD29V9), one per line.
	.PARAMETER VCRedistUrl
	Download URL for the Visual C++ redistributable.  Leave empty to skip installing it.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string[]] $PackageIds,
		[Parameter(Mandatory = $false)] [string] $VCRedistUrl = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
	)

	Assert-ABNuGetProvider

	Write-ABLog 'Installing Microsoft.WinGet.Client module'
	Install-Module -Name Microsoft.WinGet.Client -Force -Scope AllUsers -Repository PSGallery | Out-Null
	Import-Module Microsoft.WinGet.Client -ErrorAction SilentlyContinue

	Write-ABLog 'Installing latest WinGet package and dependencies'
	try {
		Repair-WinGetPackageManager -Force -Latest | Out-Null
	}
	catch {
		Write-ABLog "WinGet repair failed in system context: $_"
	}

	if ($VCRedistUrl) {
		$vcPath = Join-Path $env:TEMP 'vc_redist.exe'
		Invoke-ABDownload -Url $VCRedistUrl -Destination $vcPath
		Write-ABLog 'Installing Visual C++ redistributable'
		Start-Process -FilePath $vcPath -ArgumentList '/install', '/quiet', '/norestart' -Wait
		Remove-Item $vcPath -Force -ErrorAction SilentlyContinue
	}

	$wingetResolve = Resolve-Path "$($env:ProgramFiles)\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue
	if (-not $wingetResolve) {
		throw 'winget.exe not found'
	}
	$wingetExe = @($wingetResolve)[-1].Path
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

function Remove-ABInstalledPrograms {
	<#
	.SYNOPSIS
	Removes installed (e.g. OEM preinstalled) MSI products and programs using the PackageManagement module.
	.DESCRIPTION
	Finds installed packages with Get-Package (MSI and Programs providers by default) and removes each one that matches
	an entry in PackageIds with Uninstall-Package.  An entry matches a package's name (wildcards such as "HP Wolf*" are
	allowed) or its ID: the MSI product code (with or without braces) or the Programs uninstall registry key name.
	On PowerShell 7 the MSI and Programs providers are only available in Windows PowerShell, so the PackageManagement
	module is imported with -UseWindowsPowerShell.
	Programs entries are uninstalled with their registered uninstall command, so only programs whose uninstaller runs
	silently can be removed this way.
	.PARAMETER PackageIds
	Names or IDs of the packages to remove, one per line.  Use Get-Package -ProviderName msi, Programs to list the
	installed packages: the Name column, or the MSI product code / uninstall key name (in FastPackageReference).
	.PARAMETER ProviderNames
	PackageManagement providers to search, one per line.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string[]] $PackageIds,
		[Parameter(Mandatory = $false)] [string[]] $ProviderNames = @('msi', 'Programs')
	)

	Write-ABLog 'Removing specified installed programs'

	# The MSI and Programs providers only exist in Windows PowerShell.  On PowerShell 7, use the Windows PowerShell
	# compatibility session; a prefix keeps its commands separate from PowerShell 7's own PackageManagement module.
	$compatModule = $null
	if ($PSVersionTable.PSEdition -eq 'Core') {
		$compatModule = Import-Module PackageManagement -UseWindowsPowerShell -Prefix ABWinPS -Force -PassThru -WarningAction SilentlyContinue -ErrorAction Stop
		$getPackage = 'Get-ABWinPSPackage'
		$uninstallPackage = 'Uninstall-ABWinPSPackage'
	} else {
		Import-Module PackageManagement -ErrorAction Stop
		$getPackage = 'Get-Package'
		$uninstallPackage = 'Uninstall-Package'
	}

	try {
		$packages = @(& $getPackage -ProviderName $ProviderNames -ErrorAction SilentlyContinue)
		Write-ABLog "Found $($packages.Count) installed packages ($($ProviderNames -join ', '))"

		$removed = @{}
		foreach ($id in ($PackageIds | Where-Object { $_ } | ForEach-Object { $_.Trim() } | Select-Object -Unique)) {
			$idValue = $id.Trim('{}')
			$found = @($packages | Where-Object {
					$refs = @($_.TagId, (([string]$_.FastPackageReference) -split '\\')[-1]) |
						Where-Object { $_ } | ForEach-Object { ([string]$_).Trim('{}') }
					($_.Name -like $id) -or ($refs -contains $idValue)
				})
			if ($found.Count -eq 0) {
				Write-ABLog "No installed package matches $id"
				continue
			}
			foreach ($package in $found) {
				$key = "$($package.ProviderName)|$($package.Name)|$($package.Version)"
				if ($removed.ContainsKey($key)) {
					continue
				}
				$removed[$key] = $true
				try {
					Write-ABLog "Uninstalling $($package.Name) $($package.Version) ($($package.ProviderName))"
					$uninstall = @{
						Name         = $package.Name
						ProviderName = $package.ProviderName
						Force        = $true
						ErrorAction  = 'Stop'
					}
					if ($package.Version) {
						$uninstall.RequiredVersion = $package.Version
					}
					& $uninstallPackage @uninstall | Out-Null
				}
				catch {
					Write-ABLog "  Unable to uninstall $($package.Name): $_"
				}
			}
		}
	}
	finally {
		if ($compatModule) {
			$compatModule | Remove-Module -Force -ErrorAction SilentlyContinue
		}
	}
}

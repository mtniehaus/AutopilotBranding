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
	The Programs provider's Uninstall-Package doesn't run every program's uninstaller, so when a Programs entry is still
	registered afterwards, its silent uninstall command is run directly: the QuietUninstallString, or an msiexec
	UninstallString changed to a quiet uninstall.  Programs without a silent uninstall command are skipped (logged).
	.PARAMETER PackageIds
	Names or IDs of the packages to remove, one per line (nothing is removed when empty).  Use
	Get-Package -ProviderName msi, Programs to list the installed packages: the Name column, or the MSI product code /
	uninstall key name (in FastPackageReference).
	.PARAMETER ProviderNames
	PackageManagement providers to search, one per line.
	.PARAMETER TimeoutSeconds
	How long to wait for a program's uninstall command before stopping it.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string[]] $PackageIds = @(),
		[Parameter(Mandatory = $false)] [string[]] $ProviderNames = @('msi', 'Programs'),
		[Parameter(Mandatory = $false)] [int] $TimeoutSeconds = 600
	)

	$PackageIds = @($PackageIds | Where-Object { $_ } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
	if ($PackageIds.Count -eq 0) {
		Write-ABLog 'No package IDs specified, nothing to remove'
		return
	}
	Write-ABLog 'Removing specified installed programs'

	# The MSI and Programs providers only exist in Windows PowerShell.  On PowerShell 7, import PackageManagement into
	# the Windows PowerShell compatibility session and run Get-Package / Uninstall-Package there, returning only plain
	# values (returning the SoftwareIdentity objects through the proxy commands fails).  The prefix keeps the proxy
	# commands separate from PowerShell 7's own PackageManagement module.
	$compatModule = $null
	$session = $null
	if ($PSVersionTable.PSEdition -eq 'Core') {
		$compatModule = Import-Module PackageManagement -UseWindowsPowerShell -Prefix ABWinPS -Force -PassThru -WarningAction SilentlyContinue -ErrorAction Stop
		$session = Get-PSSession -Name 'WinPSCompatSession' -ErrorAction Stop | Where-Object { $_.State -eq 'Opened' } | Select-Object -First 1
		if (-not $session) {
			throw 'The Windows PowerShell compatibility session (WinPSCompatSession) is not available'
		}
		Write-ABLog 'Using PackageManagement through the Windows PowerShell compatibility session'
	} else {
		Import-Module PackageManagement -ErrorAction Stop
	}
	$invoke = {
		param ([scriptblock] $ScriptBlock, [object[]] $ArgumentList)
		if ($session) {
			Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
		} else {
			& $ScriptBlock @ArgumentList
		}
	}
	$getBlock = {
		param ([string[]] $Providers)
		Get-Package -ProviderName $Providers -ErrorAction SilentlyContinue | ForEach-Object {
			[pscustomobject]@{
				Name                 = [string]$_.Name
				Version              = [string]$_.Version
				ProviderName         = [string]$_.ProviderName
				FastPackageReference = [string]$_.FastPackageReference
				TagId                = [string]$_.TagId
			}
		}
	}
	$uninstallBlock = {
		param ([hashtable] $Parameters)
		Uninstall-Package @Parameters | ForEach-Object {
			[pscustomobject]@{ Name = [string]$_.Name; Version = [string]$_.Version; Status = [string]$_.Status }
		}
	}

	try {
		$packages = @(& $invoke $getBlock @(, [string[]]$ProviderNames))
		Write-ABLog "Found $($packages.Count) installed packages ($($ProviderNames -join ', '))"

		$removed = @{}
		foreach ($id in $PackageIds) {
			$idValue = $id.Trim('{}')
			$found = @($packages | Where-Object {
					$refs = @($_.TagId, ($_.FastPackageReference -split '\\')[-1]) |
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
					$result = @(& $invoke $uninstallBlock @(, $uninstall))
					foreach ($r in $result) {
						Write-ABLog "  $($r.Name) $($r.Version): $($r.Status)"
					}
					if ($package.ProviderName -eq 'Programs') {
						$entry = Get-ABUninstallEntry -FastPackageReference $package.FastPackageReference
						if ($entry) {
							Write-ABLog '  Still registered after Uninstall-Package, running its uninstall command'
							$exitCode = Invoke-ABUninstallCommand -Entry $entry -TimeoutSeconds $TimeoutSeconds
							Write-ABLog "  Exit code: $exitCode"
							if (Get-ABUninstallEntry -FastPackageReference $package.FastPackageReference) {
								throw "still registered after running its uninstall command (exit code $exitCode)"
							}
						}
						Write-ABLog '  Uninstalled'
					}
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

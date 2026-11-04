function Remove-ABProvisionedApps {
	<#
	.SYNOPSIS
	Removes in-box provisioned apps (and, optionally, the same apps installed for all users).
	.PARAMETER AppNames
	Display names of the provisioned apps to remove (as returned by Get-AppxProvisionedPackage -Online), one per line.
	.PARAMETER RemoveInstalledPackages
	Also remove installed (not just provisioned) packages with these names, as OEMs sometimes install apps for all
	users without provisioning them.  Packages marked as non-removable are skipped.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string[]] $AppNames,
		[Parameter(Mandatory = $false)] [bool] $RemoveInstalledPackages = $true
	)

	Write-ABLog 'Removing specified in-box provisioned apps'
	$apps = Get-AppxProvisionedPackage -Online
	$installedApps = @()
	if ($RemoveInstalledPackages) {
		$installedApps = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
	}
	foreach ($name in ($AppNames | Select-Object -Unique)) {
		$apps | Where-Object { $_.DisplayName -eq $name } | ForEach-Object {
			try {
				Write-ABLog "Removing provisioned app: $name"
				$_ | Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction Stop | Out-Null
			}
			catch {
				Write-ABLog "  Unable to remove provisioned app $($name): $_"
			}
		}
		$installedApps | Where-Object { $_.Name -eq $name -and -not $_.NonRemovable } | ForEach-Object {
			try {
				Write-ABLog "Removing installed app: $($_.PackageFullName)"
				$_ | Remove-AppxPackage -AllUsers -ErrorAction Stop | Out-Null
			}
			catch {
				Write-ABLog "  Unable to remove installed app $($name): $_"
			}
		}
	}
}

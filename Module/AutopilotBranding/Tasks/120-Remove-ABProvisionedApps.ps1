function Remove-ABProvisionedApps {
	<#
	.SYNOPSIS
	Removes in-box provisioned apps.
	.PARAMETER AppNames
	Display names of the provisioned apps to remove (as returned by Get-AppxProvisionedPackage -Online), one per line.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string[]] $AppNames
	)

	Write-ABLog 'Removing specified in-box provisioned apps'
	$apps = Get-AppxProvisionedPackage -Online
	foreach ($name in ($AppNames | Select-Object -Unique)) {
		$apps | Where-Object { $_.DisplayName -eq $name } | ForEach-Object {
			try {
				Write-ABLog "Removing provisioned app: $name"
				$_ | Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction SilentlyContinue | Out-Null
			}
			catch {
				Write-ABLog "  Unable to remove $($name): $_"
			}
		}
	}
}

function Disable-ABOptionalFeatures {
	<#
	.SYNOPSIS
	Disables Windows optional features.
	.PARAMETER FeatureNames
	Feature names as returned by Get-WindowsOptionalFeature -Online, one per line.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string[]] $FeatureNames
	)

	$enabledFeatures = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' }
	foreach ($feature in $enabledFeatures) {
		if ($FeatureNames -contains $feature.FeatureName) {
			Write-ABLog "Disabling optional feature: $($feature.FeatureName)"
			try {
				Disable-WindowsOptionalFeature -Online -FeatureName $feature.FeatureName -NoRestart -ErrorAction Stop | Out-Null
			}
			catch {
				Write-ABLog "  Unable to disable optional feature: $_"
			}
		}
	}
}

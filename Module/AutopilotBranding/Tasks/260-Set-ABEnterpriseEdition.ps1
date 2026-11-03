function Set-ABEnterpriseEdition {
	<#
	.SYNOPSIS
	Switches the OS edition to Enterprise using a generic volume license key.
	.PARAMETER ProductKey
	Product key passed to changepk.exe (default: the Windows Enterprise KMS client setup key).
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $ProductKey = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
	)

	Write-ABLog 'Forcing Enterprise SKU'
	& changepk.exe /ProductKey $ProductKey
}

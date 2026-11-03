function Set-ABRegisteredOwner {
	<#
	.SYNOPSIS
	Sets the registered owner and organization (shown by winver).
	.PARAMETER Owner
	Registered owner name.
	.PARAMETER Organization
	Registered organization name.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $Owner,
		[Parameter(Mandatory = $false)] [string] $Organization = ''
	)

	Write-ABLog 'Configuring registered user information'
	Set-ABRegistryValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name RegisteredOwner -Type REG_SZ -Value $Owner
	Set-ABRegistryValue -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name RegisteredOrganization -Type REG_SZ -Value $Organization
}

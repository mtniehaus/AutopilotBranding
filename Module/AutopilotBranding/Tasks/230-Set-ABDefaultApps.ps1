function Set-ABDefaultApps {
	<#
	.SYNOPSIS
	Imports default app (file type and protocol) associations.
	.DESCRIPTION
	Configure the associations you want on a reference machine, then export them with
	"DISM /Online /Export-DefaultAppAssociations:C:\Associations.xml".  Don't edit the exported file.
	.PARAMETER AssociationsXmlPath
	Default app associations XML file exported by DISM.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $AssociationsXmlPath
	)

	if (-not (Test-Path $AssociationsXmlPath)) {
		throw "Associations file not found: $AssociationsXmlPath"
	}
	Write-ABLog "Setting default apps: $AssociationsXmlPath"
	& Dism.exe /Online "/Import-DefaultAppAssociations:$AssociationsXmlPath"
}

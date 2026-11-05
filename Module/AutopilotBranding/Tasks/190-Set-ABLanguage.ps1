function Set-ABLanguage {
	<#
	.SYNOPSIS
	Configures language settings for all users using an INTL.CPL XML file.
	.DESCRIPTION
	Adding a language pack isn't enough - Windows also needs to be told to use it for all users.  This feeds the
	specified globalization XML file to INTL.CPL.
	.PARAMETER LanguageXmlPath
	Globalization services XML file (see the sample Language.xml).
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $LanguageXmlPath
	)

	if (-not (Test-Path $LanguageXmlPath)) {
		throw "Language XML file not found: $LanguageXmlPath"
	}
	Write-ABLog "Configuring language using: $LanguageXmlPath"
	& "$($env:SystemRoot)\System32\control.exe" "intl.cpl,,/f:`"$LanguageXmlPath`""
}

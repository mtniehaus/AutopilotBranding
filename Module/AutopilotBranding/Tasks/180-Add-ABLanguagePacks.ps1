function Add-ABLanguagePacks {
	<#
	.SYNOPSIS
	Installs language pack CAB files.
	.DESCRIPTION
	Every .cab file in the specified folder is added to the running OS.  Language pack CABs can be downloaded from the
	language pack ISO (MSDN / VLSC).  Remember to also add the language features (Language.Basic etc.) with
	Add-ABWindowsCapabilities and to configure the language with Set-ABLanguage.
	.PARAMETER LanguagePackFolder
	Folder containing the language pack .cab files.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $LanguagePackFolder
	)

	if (-not (Test-Path $LanguagePackFolder)) {
		Write-ABLog "Language pack folder not found: $LanguagePackFolder"
		return
	}
	$cabs = @(Get-ChildItem $LanguagePackFolder -Filter *.cab)
	if ($cabs.Count -eq 0) {
		Write-ABLog 'No language packs found'
	}
	foreach ($cab in $cabs) {
		Write-ABLog "Adding language pack: $($cab.FullName)"
		Add-WindowsPackage -Online -NoRestart -PackagePath $cab.FullName | Out-Null
	}
}

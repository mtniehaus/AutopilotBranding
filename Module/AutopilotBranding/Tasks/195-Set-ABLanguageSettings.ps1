function Set-ABLanguageSettings {
	<#
	.SYNOPSIS
	Installs a language from Windows Update and configures the display language and regional settings (Windows 11).
	.DESCRIPTION
	An alternative to Set-ABLanguage (INTL.CPL XML) that uses the LanguagePackManagement and international cmdlets:
	installs the language, sets it as the preferred UI language, sets the system locale, culture, user language list and
	(optionally) the home location, and copies the settings to the welcome screen and new users.  Installing the language
	downloads it from Windows Update, which can take a while.
	.PARAMETER Language
	Language tag to install and use as the display language, e.g. en-GB.
	.PARAMETER Locale
	System locale and culture, e.g. en-GB.  Defaults to Language if empty.
	.PARAMETER GeoId
	Home location GeoID (e.g. 242 for the United Kingdom), see
	https://learn.microsoft.com/windows/win32/intl/table-of-geographical-locations.  0 leaves it unchanged.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $Language,
		[Parameter(Mandatory = $false)] [string] $Locale = '',
		[Parameter(Mandatory = $false)] [int] $GeoId = 0
	)

	try {
		Write-ABLog "Installing language: $Language (downloaded from Windows Update, this can take a while)"
		Install-Language -Language $Language -ErrorAction Stop | Out-Null
		Set-SystemPreferredUILanguage -Language $Language -ErrorAction Stop
	}
	catch {
		# This sometimes fails the first time a language is installed; the remaining settings still apply
		Write-ABLog "  Unable to install or set display language $($Language): $_"
	}

	if (-not $Locale) {
		$Locale = $Language
	}
	Write-ABLog "Setting system locale, culture, and user language list: $Locale"
	Set-WinSystemLocale -SystemLocale $Locale -ErrorAction Stop
	Set-Culture -CultureInfo $Locale -ErrorAction Stop
	Set-WinUserLanguageList -LanguageList $Locale -Force -ErrorAction Stop
	if ($GeoId) {
		Write-ABLog "Setting home location: $GeoId"
		Set-WinHomeLocation -GeoId $GeoId -ErrorAction Stop
	}
	if (Get-Command Copy-UserInternationalSettingsToSystem -ErrorAction SilentlyContinue) {
		Write-ABLog 'Copying international settings to the welcome screen and new users'
		Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true -ErrorAction Stop
	} else {
		Write-ABLog '  Copy-UserInternationalSettingsToSystem is not available on this OS version, settings will not be copied to new users'
	}
}

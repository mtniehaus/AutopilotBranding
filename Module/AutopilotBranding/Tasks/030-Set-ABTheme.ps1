function Set-ABTheme {
	<#
	.SYNOPSIS
	Installs a custom theme and wallpaper and makes it the default for new users.
	.DESCRIPTION
	Copies the theme to C:\Windows\Resources\OEM Themes and the wallpaper to C:\Windows\Web\Wallpaper\Autopilot, then
	configures the default user profile to use the theme.  (This won't work if the user has Enterprise State Roaming
	enabled and has previously configured a background image.)
	.PARAMETER ThemePath
	Windows .theme file.
	.PARAMETER WallpaperPath
	Wallpaper image referenced by the theme.
	.PARAMETER UpdateThemeWallpaper
	Update the Wallpaper= line in the copied theme so that it points to the copied wallpaper image.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $ThemePath,
		[Parameter(Mandatory = $true)] [string] $WallpaperPath,
		[Parameter(Mandatory = $false)] [bool] $UpdateThemeWallpaper = $true
	)

	Write-ABLog 'Setting up Autopilot theme'
	$themeName = Split-Path -Path $ThemePath -Leaf
	$themeDest = "$($env:SystemRoot)\Resources\OEM Themes\$themeName"
	$wallpaperName = Split-Path -Path $WallpaperPath -Leaf
	$wallpaperDest = "$($env:SystemRoot)\Web\Wallpaper\Autopilot\$wallpaperName"

	Copy-ABFile -Path $ThemePath -Destination $themeDest
	Copy-ABFile -Path $WallpaperPath -Destination $wallpaperDest

	if ($UpdateThemeWallpaper) {
		$wallpaperValue = "%SystemRoot%\Web\Wallpaper\Autopilot\$wallpaperName"
		$content = [System.IO.File]::ReadAllText($themeDest, [System.Text.Encoding]::Default)
		$updated = [regex]::Replace($content, '(?m)^Wallpaper=.*$', { param($m) "Wallpaper=$wallpaperValue" })
		if ($updated -ne $content) {
			Write-ABLog "Updating theme wallpaper to $wallpaperValue"
			[System.IO.File]::WriteAllText($themeDest, $updated, [System.Text.Encoding]::Default)
		}
	}

	Write-ABLog 'Setting Autopilot theme as the new user default'
	$themeValue = "%SystemRoot%\Resources\OEM Themes\$themeName"
	Set-ABRegistryValue -Hive DefaultUser -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Name InstallTheme -Type REG_EXPAND_SZ -Value $themeValue
	Set-ABRegistryValue -Hive DefaultUser -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Name CurrentTheme -Type REG_EXPAND_SZ -Value $themeValue
}

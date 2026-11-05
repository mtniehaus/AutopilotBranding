function Set-ABTheme {
	<#
	.SYNOPSIS
	Installs a custom theme and wallpaper and makes it the default for new users.
	.DESCRIPTION
	Copies the theme to C:\Windows\Resources\OEM Themes and the wallpaper to C:\Windows\Web\Wallpaper\Autopilot, then
	configures the default user profile to use the theme.  For user profiles that already exist (see
	Start-AutopilotBranding -IncludeExistingProfiles), Windows has already applied its own theme, so the desktop
	wallpaper is also set directly.  (This won't work if the user has Enterprise State Roaming
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

	$content = [System.IO.File]::ReadAllText($themeDest, [System.Text.Encoding]::Default)
	if ($UpdateThemeWallpaper) {
		$wallpaperValue = "%SystemRoot%\Web\Wallpaper\Autopilot\$wallpaperName"
		$current = [regex]::Match($content, '(?m)^Wallpaper=([^\r\n]*)')
		# Only rewrite the line if it points somewhere else (paths aren't case-sensitive); keep the file's line endings
		if (-not $current.Success -or -not $current.Groups[1].Value.Trim().Equals($wallpaperValue, [System.StringComparison]::OrdinalIgnoreCase)) {
			Write-ABLog "Updating theme wallpaper to $wallpaperValue"
			$content = [regex]::Replace($content, '(?m)^Wallpaper=[^\r\n]*', { param($m) "Wallpaper=$wallpaperValue" })
			[System.IO.File]::WriteAllText($themeDest, $content, [System.Text.Encoding]::Default)
		}
	}

	Write-ABLog 'Setting Autopilot theme as the new user default'
	$themeValue = "%SystemRoot%\Resources\OEM Themes\$themeName"
	Set-ABRegistryValue -Hive DefaultUser -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Name InstallTheme -Type REG_EXPAND_SZ -Value $themeValue
	Set-ABRegistryValue -Hive DefaultUser -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes' -Name CurrentTheme -Type REG_EXPAND_SZ -Value $themeValue

	# Existing profiles have already applied a theme at creation, so set their wallpaper directly (with the theme's style)
	$style = [regex]::Match($content, '(?m)^WallpaperStyle=(\d+)')
	$tile = [regex]::Match($content, '(?m)^TileWallpaper=(\d+)')
	$wallpaperStyle = if ($style.Success) { $style.Groups[1].Value } else { '10' }
	$tileWallpaper = if ($tile.Success) { $tile.Groups[1].Value } else { '0' }
	Set-ABRegistryValue -Hive ExistingUsers -Path 'Control Panel\Desktop' -Name Wallpaper -Type REG_SZ -Value $wallpaperDest
	Set-ABRegistryValue -Hive ExistingUsers -Path 'Control Panel\Desktop' -Name WallpaperStyle -Type REG_SZ -Value $wallpaperStyle
	Set-ABRegistryValue -Hive ExistingUsers -Path 'Control Panel\Desktop' -Name TileWallpaper -Type REG_SZ -Value $tileWallpaper
}

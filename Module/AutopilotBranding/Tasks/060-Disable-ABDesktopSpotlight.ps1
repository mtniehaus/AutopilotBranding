function Disable-ABDesktopSpotlight {
	<#
	.SYNOPSIS
	Turns off Windows Spotlight on the desktop so that the custom wallpaper is used.
	.DESCRIPTION
	Hides the "Learn about this picture" desktop icon and disables Windows Spotlight for the desktop, see
	https://github.com/mtniehaus/AutopilotBranding/issues/13#issuecomment-2449224828
	.PARAMETER HideLearnAboutThisPicture
	Hide the "Learn about this picture" icon from the desktop.
	.PARAMETER DisableSpotlightCollection
	Disable the Windows Spotlight collection on the desktop.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [bool] $HideLearnAboutThisPicture = $true,
		[Parameter(Mandatory = $false)] [bool] $DisableSpotlightCollection = $true
	)

	if ($HideLearnAboutThisPicture) {
		Write-ABLog 'Hiding "Learn about this picture" from the desktop'
		Set-ABRegistryValue -Hive DefaultUser -Path 'Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{2cc5ca98-6485-489a-920e-b3e88a6ccce3}' -Type REG_DWORD -Value 1
	}
	if ($DisableSpotlightCollection) {
		Write-ABLog 'Disabling Windows Spotlight for Desktop'
		Set-ABRegistryValue -Hive DefaultUser -Path 'Software\Policies\Microsoft\Windows\CloudContent' -Name DisableSpotlightCollectionOnDesktop -Type REG_DWORD -Value 1
	}
}

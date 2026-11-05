function Disable-ABWidgets {
	<#
	.SYNOPSIS
	Completely disables Widgets via policy (the Settings toggle is greyed out).
	.DESCRIPTION
	See https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-newsandinterests#allownewsandinterests
	.PARAMETER DisableOnLockScreen
	Also disable widgets on the lock screen.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [bool] $DisableOnLockScreen = $true
	)

	Write-ABLog 'Disabling Widgets'
	$path = 'HKLM:\Software\Policies\Microsoft\Dsh'
	if (-not (Test-Path $path)) {
		New-Item -Path $path -Force | Out-Null
	}
	if ($DisableOnLockScreen) {
		Set-ItemProperty -Path $path -Name 'DisableWidgetsOnLockScreen' -Value 1 -Type DWord
	}
	Set-ItemProperty -Path $path -Name 'DisableWidgetsBoard' -Value 1 -Type DWord
	Set-ItemProperty -Path $path -Name 'AllowNewsAndInterests' -Value 0 -Type DWord
}

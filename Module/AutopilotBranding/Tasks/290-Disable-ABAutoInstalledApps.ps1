function Disable-ABAutoInstalledApps {
	<#
	.SYNOPSIS
	Stops Windows 11 from automatically installing Dev Home and the new Outlook during OOBE.
	.PARAMETER DevHome
	Prevent Dev Home from being installed.
	.PARAMETER OutlookNew
	Prevent the new Outlook for Windows from being installed.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [bool] $DevHome = $true,
		[Parameter(Mandatory = $false)] [bool] $OutlookNew = $true
	)

	Write-ABLog 'Disabling automatically installed apps'
	$base = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe'
	if ($DevHome -and (Test-Path -Path "$base\DevHomeUpdate")) {
		Write-ABLog '  Removing DevHome key'
		Remove-Item -Path "$base\DevHomeUpdate" -Force
	}
	if ($OutlookNew -and (Test-Path -Path "$base\OutlookUpdate")) {
		Write-ABLog '  Removing Outlook for Windows key'
		Remove-Item -Path "$base\OutlookUpdate" -Force
	}
}

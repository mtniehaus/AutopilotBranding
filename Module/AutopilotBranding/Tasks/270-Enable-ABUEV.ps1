function Enable-ABUEV {
	<#
	.SYNOPSIS
	Enables User Experience Virtualization (UE-V) and registers settings templates.
	.PARAMETER TemplateFolder
	Folder containing the UE-V template XML files to register.
	.PARAMETER SettingsStorageLocation
	UE-V settings storage path (may contain environment variables, evaluated per user).
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $TemplateFolder,
		[Parameter(Mandatory = $false)] [string] $SettingsStorageLocation = '%OneDriveCommercial%\UEV'
	)

	Write-ABLog 'Enabling UE-V'
	Enable-UEV
	Set-UevConfiguration -Computer -SettingsStoragePath $SettingsStorageLocation -SyncMethod External -DisableWaitForSyncOnLogon
	if ($TemplateFolder -and (Test-Path $TemplateFolder)) {
		Get-ChildItem $TemplateFolder -Filter *.xml | ForEach-Object {
			Write-ABLog "Registering template: $($_.FullName)"
			Register-UevTemplate -Path $_.FullName
		}
	}
}

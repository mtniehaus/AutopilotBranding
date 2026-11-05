function Update-ABApps {
	<#
	.SYNOPSIS
	Updates in-box Store apps and triggers a Microsoft Store update scan.
	.PARAMETER UpdateInboxApps
	Install and run the Update-InboxApp script from the PowerShell Gallery to update all in-box apps.
	.PARAMETER TriggerStoreScan
	Trigger a Microsoft Store app update scan through the MDM bridge.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [bool] $UpdateInboxApps = $true,
		[Parameter(Mandatory = $false)] [bool] $TriggerStoreScan = $true
	)

	if ($UpdateInboxApps) {
		try {
			# NuGet 2.8.5.201 is required to install the Update-InboxApp script from the PowerShell Gallery
			Assert-ABNuGetProvider -MinimumVersion ([version]'2.8.5.201')
		}
		catch {
			Write-ABLog "Error updating NuGet: $_"
		}
		try {
			Write-ABLog 'Installing Update-InboxApp script'
			Install-Script Update-InboxApp -Force | Out-Null

			Write-ABLog 'Updating inbox apps'
			# The path might not be set right to find this, so we'll hard-code the location
			# Only Store-signed packages can be updated from the Store (system packages just produce errors)
			Get-AppxPackage -AllUsers | Where-Object { $_.SignatureKind -eq 'Store' } | Select-Object -Unique PackageFamilyName |
				. "$($env:ProgramFiles)\WindowsPowerShell\Scripts\Update-InboxApp.ps1" -Verbose
		}
		catch {
			Write-ABLog "Error updating in-box apps: $_"
		}
	}

	if ($TriggerStoreScan) {
		try {
			Write-ABLog 'Triggering Microsoft Store update scan'
			Get-CimInstance -Namespace 'Root\cimv2\mdm\dmmap' -ClassName 'MDM_EnterpriseModernAppManagement_AppManagement01' |
				Invoke-CimMethod -MethodName UpdateScanMethod | Out-Null
		}
		catch {
			Write-ABLog "Error triggering Store update scan: $_"
		}
	}
}

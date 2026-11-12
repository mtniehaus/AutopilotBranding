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
			# v1.4 or later is needed on PowerShell 7: it runs the update in a Windows PowerShell 5.1 session itself, as
			# the Windows Runtime (Store) APIs it uses aren't available in PowerShell 7
			Install-Script Update-InboxApp -MinimumVersion 1.4 -Scope AllUsers -Force -ErrorAction Stop | Out-Null

			# The Scripts folder might not be on the path, and its location depends on the PowerShell edition
			# (Windows PowerShell vs. PowerShell 7), so ask PowerShellGet where it put the script.  (Indexing instead of
			# Select-Object -First 1 avoids a "pipeline has been stopped" error record in the transcript.)
			$installed = @(Get-InstalledScript -Name Update-InboxApp -ErrorAction Stop)[0]
			$updateInboxApp = Join-Path $installed.InstalledLocation 'Update-InboxApp.ps1'

			Write-ABLog "Updating inbox apps (Update-InboxApp v$($installed.Version))"
			# Only Store-signed packages can be updated from the Store (system packages just produce errors).  Run the
			# script with & rather than dot-sourcing it: it needs its own script scope (on PowerShell 7 it re-runs
			# itself from $PSCommandPath in the Windows PowerShell session), and its variables and helper function
			# shouldn't land in this function's scope.
			# On PowerShell 7 the script's messages come back from its Windows PowerShell session through Invoke-Command,
			# and they show at the console but don't end up in the transcript.  So merge all of its streams into the
			# output and log each message, as the task's own messages are.
			Get-AppxPackage -AllUsers | Where-Object { $_.SignatureKind -eq 'Store' } | Select-Object -Unique PackageFamilyName |
				& $updateInboxApp -Verbose *>&1 | ForEach-Object {
					$prefix = switch ($_) {
						{ $_ -is [System.Management.Automation.VerboseRecord] } { 'VERBOSE: '; break }
						{ $_ -is [System.Management.Automation.WarningRecord] } { 'WARNING: '; break }
						{ $_ -is [System.Management.Automation.DebugRecord] } { 'DEBUG: '; break }
						{ $_ -is [System.Management.Automation.ErrorRecord] } { 'ERROR: '; break }
						default { '' }
					}
					Write-ABLog "$prefix$_"
				}
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

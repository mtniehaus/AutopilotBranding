function Remove-ABOffice {
	<#
	.SYNOPSIS
	Removes all preinstalled (OEM) Microsoft Office Click-to-Run and MSI products.
	.DESCRIPTION
	If any Office product is installed (Click-to-Run or MSI), downloads the latest Office Deployment Tool and runs it
	with a configuration that removes all products, regardless of product ID and language.  If none is installed,
	nothing is done.  The Office Deployment Tool logs to %TEMP%\AutopilotBrandingODT (C:\Windows\Temp when running as
	SYSTEM); if it fails, the end of its log is written to the Autopilot Branding log and the task fails.
	.PARAMETER OdtUrl
	Download URL for the Office Deployment Tool setup.exe.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $OdtUrl = 'https://officecdn.microsoft.com/pr/wsus/setup.exe'
	)

	# Is any Office product installed?
	$installed = @()
	if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration') {
		$installed += 'Office Click-to-Run'
	}
	$uninstallKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
	$installed += @(Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
			Where-Object { $_.DisplayName -match '^Microsoft (Office|365 Apps|Project|Visio|OneNote|Access|Excel|Outlook|PowerPoint|Publisher|Word)\b' } |
			ForEach-Object { $_.DisplayName } | Select-Object -Unique)
	if ($installed.Count -eq 0) {
		Write-ABLog 'No Office products are installed, nothing to remove'
		return
	}
	Write-ABLog "Removing all Office products (found: $($installed -join ', '))"

	$logFolder = Join-Path $env:TEMP 'AutopilotBrandingODT'
	New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
	$xml = @"
<Configuration>
  <Display Level="None" AcceptEULA="True" />
  <Logging Level="Standard" Path="$logFolder" />
  <Property Name="FORCEAPPSHUTDOWN" Value="True" />
  <Remove All="TRUE">
  </Remove>
  <RemoveMSI />
</Configuration>
"@
	$xmlPath = Join-Path $env:TEMP 'o365.xml'
	$odtPath = Join-Path $env:TEMP 'setup.exe'
	$xml | Out-File -FilePath $xmlPath -Encoding UTF8

	Write-ABLog 'Downloading latest ODT'
	Invoke-WebRequest -Uri $OdtUrl -OutFile $odtPath -UseBasicParsing -ErrorAction Stop

	Write-ABLog "Running ODT (log folder: $logFolder)"
	$started = Get-Date
	$proc = Start-Process -FilePath $odtPath -ArgumentList "/configure `"$xmlPath`"" -WindowStyle Hidden -Wait -PassThru
	Write-ABLog "ODT exit code: $($proc.ExitCode)"
	if ($proc.ExitCode -ne 0) {
		$log = Get-ChildItem -Path $logFolder -Filter '*.log' -ErrorAction SilentlyContinue |
			Where-Object { $_.LastWriteTime -ge $started.AddMinutes(-1) } |
			Sort-Object LastWriteTime -Descending | Select-Object -First 1
		if ($log) {
			Write-ABLog "Last lines of the ODT log $($log.FullName):"
			Get-Content -Path $log.FullName -Tail 25 -ErrorAction SilentlyContinue | ForEach-Object { Write-ABLog "  $_" }
		} else {
			Write-ABLog "No ODT log found in $logFolder"
		}
		throw "The Office Deployment Tool failed with exit code $($proc.ExitCode)"
	}
}

function Remove-ABOffice {
	<#
	.SYNOPSIS
	Removes all preinstalled (OEM) Microsoft Office Click-to-Run and MSI products.
	.DESCRIPTION
	Downloads the latest Office Deployment Tool and runs it with a configuration that removes all products,
	regardless of product ID and language.
	.PARAMETER OdtUrl
	Download URL for the Office Deployment Tool setup.exe.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $OdtUrl = 'https://officecdn.microsoft.com/pr/wsus/setup.exe'
	)

	Write-ABLog 'Removing all Office products'
	$xml = @"
<Configuration>
  <Display Level="None" AcceptEULA="True" />
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

	Write-ABLog 'Running ODT'
	$proc = Start-Process -FilePath $odtPath -ArgumentList "/configure `"$xmlPath`"" -WindowStyle Hidden -Wait -PassThru
	Write-ABLog "ODT exit code: $($proc.ExitCode)"
}

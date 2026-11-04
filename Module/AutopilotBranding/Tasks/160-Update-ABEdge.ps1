function Update-ABEdge {
	<#
	.SYNOPSIS
	Downloads and installs the latest Microsoft Edge for Business MSI.
	.DESCRIPTION
	If the MSI install fails, MicrosoftEdgeUpdate.exe is triggered to update Edge instead.  On ARM64 devices only the
	ARM64 MSI is used, because installing the x64 MSI replaces the native Edge and breaks Edge and WebView2; if ArmUrl
	is empty, the update is skipped on ARM64.
	.PARAMETER Url
	Download URL for the x64 Edge for Business MSI.
	.PARAMETER ArmUrl
	Download URL for the ARM64 Edge for Business MSI.  If empty, the Edge update is skipped on ARM64 devices.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [string] $Url = 'https://go.microsoft.com/fwlink/?LinkID=2093437',
		[Parameter(Mandatory = $false)] [string] $ArmUrl = ''
	)

	if (Test-ABArm64) {
		if (-not $ArmUrl) {
			Write-ABLog 'ARM64 device and no ARM64 Edge for Business MSI specified (ArmUrl), skipping Edge update'
			return
		}
		$downloadUrl = $ArmUrl
		$dest = "$($env:TEMP)\MicrosoftEdgeEnterpriseARM64.msi"
	} else {
		$downloadUrl = $Url
		$dest = "$($env:TEMP)\MicrosoftEdgeEnterpriseX64.msi"
	}
	Invoke-ABDownload -Url $downloadUrl -Destination $dest

	# The Edge version is in the MSI comments; the first 13 characters contain the version number.
	$versionOnly = ''
	try {
		$shell = New-Object -ComObject Shell.Application
		$folder = $shell.NameSpace((Split-Path $dest))
		$file = $folder.ParseName((Split-Path $dest -Leaf))
		$comment = $folder.GetDetailsOf($file, 24) # 24 is the index for comments
		$versionOnly = $comment.Substring(0, [Math]::Min(13, $comment.Length))
	}
	catch { }

	Write-ABLog "Installing Edge for Business v:$versionOnly"
	$arguments = "/i `"$dest`" /qn /L*v `"$($env:TEMP)\EdgeBusiness.log`""
	$proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -PassThru -WindowStyle Hidden
	$proc.WaitForExit()
	if ($proc.ExitCode -ne 0) {
		Write-ABLog "MSI error $($proc.ExitCode), trying to run MicrosoftEdgeUpdate.exe instead"
		$proc = Start-Process -FilePath "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" -ArgumentList '/silent /install appguid={56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}&appname=Microsoft%20Edge&needsadmin=True' -PassThru -WindowStyle Hidden
		$proc.WaitForExit()
		Write-ABLog 'Edge updater triggered'
	} else {
		Write-ABLog 'Edge for Business updated'
	}
}

function Update-ABEdge {
	<#
	.SYNOPSIS
	Downloads and installs the latest Microsoft Edge for Business MSI.
	.DESCRIPTION
	By default the latest Stable Edge Enterprise MSI for the device's architecture (x64 or ARM64) is looked up from the
	edgeupdates.microsoft.com API and its hash is verified before installing.  If the lookup fails (or LookUpLatest is
	turned off), the Url (x64) or ArmUrl (ARM64) MSI is used instead.  ARM64 devices never use the x64 MSI, because it
	replaces the native Edge and breaks Edge and WebView2.  If the MSI install fails, MicrosoftEdgeUpdate.exe is
	triggered to update Edge instead.
	.PARAMETER LookUpLatest
	Look up the latest Stable MSI (and its hash) from the edgeupdates.microsoft.com API.
	.PARAMETER Url
	x64 Edge for Business MSI download URL, used if the lookup fails or is turned off.
	.PARAMETER ArmUrl
	ARM64 Edge for Business MSI download URL, used if the lookup fails or is turned off.  No fixed evergreen URL is
	known for the ARM64 MSI, so it is empty by default; the update is then skipped on ARM64 if the lookup fails.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [bool] $LookUpLatest = $true,
		[Parameter(Mandatory = $false)] [string] $Url = 'https://go.microsoft.com/fwlink/?LinkID=2093437',
		[Parameter(Mandatory = $false)] [string] $ArmUrl = ''
	)

	if (Test-ABArm64) {
		$edgeArch = 'arm64'
		$fallbackUrl = $ArmUrl
		$dest = "$($env:TEMP)\MicrosoftEdgeEnterpriseARM64.msi"
	} else {
		$edgeArch = 'x64'
		$fallbackUrl = $Url
		$dest = "$($env:TEMP)\MicrosoftEdgeEnterpriseX64.msi"
	}

	# Look up the latest Stable MSI (with its hash); fall back to the configured URL if the lookup fails
	$downloadUrl = $null
	$edgeMsi = $null
	if ($LookUpLatest) {
		try {
			Write-ABLog "Looking up latest Edge Stable $edgeArch MSI from edgeupdates.microsoft.com"
			$edgeMsi = Get-ABLatestEdgeMsi -Architecture $edgeArch
			if ($edgeMsi) {
				$downloadUrl = $edgeMsi.Url
				Write-ABLog "Found Edge Stable $edgeArch $($edgeMsi.Version)"
			} else {
				Write-ABLog "No Edge Stable $edgeArch MSI found in the edgeupdates response"
			}
		}
		catch {
			Write-ABLog "Unable to query edgeupdates.microsoft.com: $_"
		}
	}
	if (-not $downloadUrl -and $fallbackUrl) {
		$downloadUrl = $fallbackUrl
		Write-ABLog "Using the configured Edge for Business MSI URL"
	}
	if (-not $downloadUrl) {
		Write-ABLog "No Edge for Business MSI available for $edgeArch, skipping Edge update"
		return
	}

	Invoke-ABDownload -Url $downloadUrl -Destination $dest

	if ($edgeMsi -and $edgeMsi.Hash) {
		$actualHash = (Get-FileHash -Path $dest -Algorithm $edgeMsi.HashAlgorithm).Hash
		if ($actualHash -ne $edgeMsi.Hash) {
			Remove-Item $dest -Force -ErrorAction SilentlyContinue
			throw "Downloaded MSI hash mismatch (expected $($edgeMsi.Hash), got $actualHash)"
		}
		Write-ABLog "Edge MSI $($edgeMsi.HashAlgorithm) hash verified"
	}

	$versionOnly = ''
	if ($edgeMsi) {
		$versionOnly = $edgeMsi.Version
	} else {
		# The Edge version is in the MSI comments; the first 13 characters contain the version number.
		try {
			$shell = New-Object -ComObject Shell.Application
			$folder = $shell.NameSpace((Split-Path $dest))
			$file = $folder.ParseName((Split-Path $dest -Leaf))
			$comment = $folder.GetDetailsOf($file, 24) # 24 is the index for comments
			$versionOnly = $comment.Substring(0, [Math]::Min(13, $comment.Length))
		}
		catch { }
	}

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

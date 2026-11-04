# Shared helper functions used by the AutopilotBranding task cmdlets.  These are not exported.

# Name of the key under HKLM where the default user profile's NTUSER.DAT is loaded.
$script:ABDefaultUserHiveName = 'TempUser'
$script:ABHiveRefCount = 0
$script:ABHiveLoadedByModule = $false


function Get-ABDefaultUserProfilePath {
	<#
	.SYNOPSIS
	Returns the path to the default user profile folder (normally C:\Users\Default).
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param ()

	$default = $null
	try {
		$default = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name Default -ErrorAction Stop).Default
	}
	catch { }
	if ([string]::IsNullOrWhiteSpace($default)) {
		$default = "$($env:SystemDrive)\Users\Default"
	}
	[Environment]::ExpandEnvironmentVariables($default)
}


function Get-ABDefaultUserRegistryRoot {
	<#
	.SYNOPSIS
	Returns the reg.exe-style root of the loaded default user hive (e.g. HKLM\TempUser).
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param ()

	"HKLM\$($script:ABDefaultUserHiveName)"
}


function Get-ABOSBuild {
	<#
	.SYNOPSIS
	Returns the OS build number of the running OS.
	#>
	[CmdletBinding()]
	[OutputType([int])]
	param ()

	try {
		[int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber
	}
	catch {
		[Environment]::OSVersion.Version.Build
	}
}


function Test-ABLegacyStartMenu {
	<#
	.SYNOPSIS
	Returns $true if the OS uses the Windows 10 style (Layout.xml) Start menu.
	.DESCRIPTION
	Matches the logic of the original script: builds up to and including 22000 use LayoutModification.xml,
	later builds use start2.bin and the Windows 11 taskbar layout.
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param ()

	(Get-ABOSBuild) -le 22000
}


function Test-ABArm64 {
	<#
	.SYNOPSIS
	Returns $true if the OS is ARM64.
	.DESCRIPTION
	Checks the OS architecture rather than the process architecture, which could be x86 or x64 under emulation on ARM64.
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param ()

	($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') -or ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64')
}


function Set-ABRegistryValue {
	<#
	.SYNOPSIS
	Sets a registry value using reg.exe (64-bit view), either in HKLM or in the default user hive.
	.PARAMETER Hive
	Machine = HKLM; DefaultUser = the default user profile's NTUSER.DAT (loaded on demand).
	.PARAMETER Path
	Key path relative to the hive root, e.g. "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced".
	.PARAMETER Name
	Value name.  If omitted, only the key is created.
	#>
	[CmdletBinding()]
	param (
		[ValidateSet('Machine', 'DefaultUser')] [string] $Hive = 'Machine',
		[Parameter(Mandatory = $true)] [string] $Path,
		[string] $Name,
		[ValidateSet('REG_SZ', 'REG_EXPAND_SZ', 'REG_DWORD', 'REG_QWORD', 'REG_MULTI_SZ', 'REG_BINARY')] [string] $Type = 'REG_DWORD',
		$Value,
		[string] $RegExe = 'reg.exe'
	)

	if ($Hive -eq 'DefaultUser') {
		Mount-ABDefaultUserHive
		$root = Get-ABDefaultUserRegistryRoot
	} else {
		$root = 'HKLM'
	}

	try {
		$key = "$root\$($Path.TrimStart('\'))"
		if ($PSBoundParameters.ContainsKey('Name')) {
			$output = & $RegExe add "$key" /v "$Name" /t $Type /d "$Value" /f /reg:64 2>&1
		} else {
			$output = & $RegExe add "$key" /f /reg:64 2>&1
		}
		if ($LASTEXITCODE -ne 0) {
			throw "reg.exe add `"$key`" $Name failed (exit code $LASTEXITCODE): $output"
		}
	}
	finally {
		if ($Hive -eq 'DefaultUser') {
			Dismount-ABDefaultUserHive
		}
	}
}


function Assert-ABNuGetProvider {
	<#
	.SYNOPSIS
	Makes sure the NuGet package provider (needed by Install-Module / Install-Script) is installed.
	#>
	[CmdletBinding()]
	param (
		[version] $MinimumVersion = [version]'2.8.5.201'
	)

	$provider = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
		Sort-Object Version -Descending |
		Select-Object -First 1

	if (-not $provider) {
		Write-ABLog 'NuGet Provider Package not detected, installing...'
		Install-PackageProvider -Name NuGet -MinimumVersion $MinimumVersion -Force | Out-Null
	} elseif ($provider.Version -lt $MinimumVersion) {
		Write-ABLog "NuGet provider v$($provider.Version) is less than required v$MinimumVersion; updating."
		Install-PackageProvider -Name NuGet -MinimumVersion $MinimumVersion -Force | Out-Null
	} else {
		Write-ABLog "NuGet provider meets min requirements (v:$($provider.Version))."
	}
}


function Invoke-ABDownload {
	<#
	.SYNOPSIS
	Downloads a file to the specified destination.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $Url,
		[Parameter(Mandatory = $true)] [string] $Destination
	)

	Write-ABLog "Downloading $Url to $Destination"
	$client = New-Object System.Net.WebClient
	try {
		$client.DownloadFile($Url, $Destination)
	}
	finally {
		$client.Dispose()
	}
}


function Test-ABOOBEComplete {
	<#
	.SYNOPSIS
	Returns $true if OOBE has already been completed on this device.
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param ()

	if (-not ('AutopilotBranding.Kernel32' -as [type])) {
		Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace AutopilotBranding
{
	public class Kernel32
	{
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		public static extern int OOBEComplete(ref int bIsOOBEComplete);
	}
}
"@
	}
	$isOOBEComplete = 0
	$null = [AutopilotBranding.Kernel32]::OOBEComplete([ref] $isOOBEComplete)
	[bool]$isOOBEComplete
}


function Copy-ABFile {
	<#
	.SYNOPSIS
	Copies a file, creating the destination folder if needed.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $Path,
		[Parameter(Mandatory = $true)] [string] $Destination
	)

	if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
		throw "Source file not found: $Path"
	}
	$folder = Split-Path -Path $Destination -Parent
	if ($folder -and -not (Test-Path -LiteralPath $folder)) {
		New-Item -Path $folder -ItemType Directory -Force | Out-Null
	}
	Copy-Item -LiteralPath $Path -Destination $Destination -Force
}


function Invoke-ABHiveUnload {
	# Unloads HKLM\TempUser, retrying a few times.  Leaving the default user hive loaded corrupts new profiles
	# ("The User Profile Service failed the sign-in").  Returns $true if the hive was unloaded.
	for ($i = 1; $i -le 5; $i++) {
		[GC]::Collect()
		[GC]::WaitForPendingFinalizers()
		$output = & reg.exe unload "$(Get-ABDefaultUserRegistryRoot)" 2>&1
		if ($LASTEXITCODE -eq 0) {
			Write-ABLog 'Default user registry hive unloaded'
			return $true
		}
		Write-ABLog "Unable to unload default user registry hive (attempt $i): $output"
		Start-Sleep -Seconds 2
	}
	Write-ABLog 'ERROR: Unable to unload default user registry hive'
	return $false
}



function Get-ABLatestEdgeMsi {
	<#
	.SYNOPSIS
	Returns the latest Edge Stable Enterprise MSI (Version, Url, Hash, HashAlgorithm) for an architecture, or $null.
	.DESCRIPTION
	Queries the edgeupdates.microsoft.com API.  Throws if the API can't be reached.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [ValidateSet('x64', 'arm64')] [string] $Architecture
	)

	# Parentheses are required: Windows PowerShell 5.1 otherwise passes the JSON array down the pipeline as one object
	$release = (Invoke-RestMethod -Uri 'https://edgeupdates.microsoft.com/api/products' -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop) |
		Where-Object Product -EQ 'Stable' |
		Select-Object -ExpandProperty Releases |
		Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq $Architecture } |
		Sort-Object { [version]$_.ProductVersion } -Descending |
		Select-Object -First 1
	if (-not $release) {
		return $null
	}
	$msi = $release.Artifacts | Where-Object ArtifactName -EQ 'msi' | Select-Object -First 1
	if (-not $msi -or -not $msi.Location) {
		return $null
	}

	[pscustomobject]@{
		Version       = $release.ProductVersion
		Url           = $msi.Location
		Hash          = $msi.Hash
		HashAlgorithm = $msi.HashAlgorithm
	}
}

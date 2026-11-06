# Shared helper functions used by the AutopilotBranding task cmdlets.  These are not exported.

# Name of the key under HKLM where the default user profile's NTUSER.DAT is loaded.
$script:ABDefaultUserHiveName = 'TempUser'
$script:ABHiveRefCount = 0
$script:ABHiveLoadedByModule = $false
# Per-user changes also go to user profiles that already exist (see Start-AutopilotBranding -IncludeExistingProfiles)
$script:ABIncludeExistingProfiles = $true
$script:ABUserHives = @()


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
	Sets a registry value using reg.exe (64-bit view): in HKLM, or in user profiles.
	.PARAMETER Hive
	Machine = HKLM.
	DefaultUser = the default user profile (so new users get the value) and, unless turned off with
	Start-AutopilotBranding -IncludeExistingProfiles $false, every user profile that already exists (for example the
	profile of the user who is signing in while the app installs during Autopilot account setup).
	ExistingUsers = only the user profiles that already exist.
	.PARAMETER Path
	Key path relative to the hive root, e.g. "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced".
	.PARAMETER Name
	Value name.  If omitted, only the key is created.
	#>
	[CmdletBinding()]
	param (
		[ValidateSet('Machine', 'DefaultUser', 'ExistingUsers')] [string] $Hive = 'Machine',
		[Parameter(Mandatory = $true)] [string] $Path,
		[string] $Name,
		[ValidateSet('REG_SZ', 'REG_EXPAND_SZ', 'REG_DWORD', 'REG_QWORD', 'REG_MULTI_SZ', 'REG_BINARY')] [string] $Type = 'REG_DWORD',
		$Value,
		[string] $RegExe = 'reg.exe'
	)

	$userHive = $Hive -ne 'Machine'
	if ($userHive) {
		Mount-ABDefaultUserHive
	}
	try {
		if ($userHive) {
			$roots = @(Get-ABUserRegistryRoots -Scope $Hive)
		} else {
			$roots = @([pscustomobject]@{ Root = 'HKLM'; Name = 'HKLM' })
		}
		foreach ($root in $roots) {
			$key = "$($root.Root)\$($Path.TrimStart('\'))"
			if ($PSBoundParameters.ContainsKey('Name')) {
				$output = & $RegExe add "$key" /v "$Name" /t $Type /d "$Value" /f /reg:64 2>&1
			} else {
				$output = & $RegExe add "$key" /f /reg:64 2>&1
			}
			if ($LASTEXITCODE -ne 0) {
				throw "reg.exe add `"$key`" $Name ($($root.Name)) failed (exit code $LASTEXITCODE): $output"
			}
		}
	}
	finally {
		if ($userHive) {
			Dismount-ABDefaultUserHive
		}
	}
}


function Get-ABExistingUserProfile {
	<#
	.SYNOPSIS
	Returns the user profiles that already exist on the device (SID, ProfilePath, Loaded).
	.DESCRIPTION
	Local and domain users (S-1-5-21-...) and Microsoft Entra ID users (S-1-12-1-...) with a profile folder and an
	NTUSER.DAT.  System accounts and the temporary OOBE accounts (defaultuser0, ...) are left out.  Loaded is $true
	when the profile's registry hive is already loaded (under HKEY_USERS), e.g. for a signed-in user.
	#>
	[CmdletBinding()]
	param ()

	$profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
	foreach ($key in (Get-ChildItem -Path $profileList -ErrorAction SilentlyContinue)) {
		$sid = $key.PSChildName
		if ($sid -notmatch '^S-1-5-21-|^S-1-12-1-') {
			continue
		}
		$path = (Get-ItemProperty -Path $key.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
		if ([string]::IsNullOrWhiteSpace($path)) {
			continue
		}
		$path = [Environment]::ExpandEnvironmentVariables($path)
		if ((Split-Path -Path $path -Leaf) -like 'defaultuser*' -or -not (Test-Path -LiteralPath (Join-Path $path 'NTUSER.DAT'))) {
			continue
		}
		[pscustomobject]@{
			Sid         = $sid
			ProfilePath = $path
			Loaded      = Test-Path -LiteralPath "Registry::HKEY_USERS\$sid"
		}
	}
}


function Mount-ABUserHives {
	# Makes the registry of every existing user profile available: loaded hives are used through HKEY_USERS, others
	# are loaded under HKLM\ABUser<n> (and unloaded again by Dismount-ABUserHives).
	$script:ABUserHives = @()
	$index = 0
	foreach ($userProfile in @(Get-ABExistingUserProfile)) {
		if ($userProfile.Loaded) {
			$script:ABUserHives += [pscustomobject]@{ Root = "HKU\$($userProfile.Sid)"; Name = $userProfile.ProfilePath; ProfilePath = $userProfile.ProfilePath; LoadedByModule = $false }
			Write-ABLog "Existing user profile (signed in): $($userProfile.ProfilePath)"
			continue
		}
		$index++
		$root = "HKLM\ABUser$index"
		if (Test-Path -LiteralPath "Registry::HKEY_LOCAL_MACHINE\ABUser$index") {
			Invoke-ABHiveUnload -Root $root -Description "registry hive $root (left over from a previous run)" | Out-Null
		}
		$output = & reg.exe load $root (Join-Path $userProfile.ProfilePath 'NTUSER.DAT') 2>&1
		if ($LASTEXITCODE -ne 0) {
			Write-ABLog "Unable to load the registry hive of $($userProfile.ProfilePath), skipping it: $output"
			continue
		}
		$script:ABUserHives += [pscustomobject]@{ Root = $root; Name = $userProfile.ProfilePath; ProfilePath = $userProfile.ProfilePath; LoadedByModule = $true }
		Write-ABLog "Existing user profile (registry loaded as $root): $($userProfile.ProfilePath)"
	}
}


function Dismount-ABUserHives {
	foreach ($hive in $script:ABUserHives) {
		if ($hive.LoadedByModule) {
			Invoke-ABHiveUnload -Root $hive.Root -Description "registry hive of $($hive.Name)" | Out-Null
		}
	}
	$script:ABUserHives = @()
}


function Get-ABUserRegistryRoots {
	<#
	.SYNOPSIS
	Returns the reg.exe roots (Root, Name) of the user registry hives to change; the hives must be mounted.
	.PARAMETER Scope
	DefaultUser = the default user hive plus the existing profiles (if included); ExistingUsers = only those.
	#>
	param (
		[ValidateSet('DefaultUser', 'ExistingUsers')] [string] $Scope = 'DefaultUser'
	)

	if ($Scope -eq 'DefaultUser') {
		[pscustomobject]@{ Root = Get-ABDefaultUserRegistryRoot; Name = 'default user' }
	}
	if ($script:ABIncludeExistingProfiles) {
		foreach ($hive in $script:ABUserHives) {
			$hive
		}
	}
}


function Get-ABUserProfilePaths {
	<#
	.SYNOPSIS
	Returns the profile folders to change: the default user profile and, if included, the existing user profiles.
	#>
	param (
		[ValidateSet('DefaultUser', 'ExistingUsers')] [string] $Scope = 'DefaultUser'
	)

	if ($Scope -eq 'DefaultUser') {
		Get-ABDefaultUserProfilePath
	}
	if ($script:ABIncludeExistingProfiles) {
		foreach ($userProfile in @(Get-ABExistingUserProfile)) {
			$userProfile.ProfilePath
		}
	}
}


function ConvertTo-ABProviderPath([string] $Root) {
	# Converts a reg.exe root (HKLM\X, HKU\SID) to a PowerShell registry provider path
	$Root -replace '^HKLM\\', 'Registry::HKEY_LOCAL_MACHINE\' -replace '^HKU\\', 'Registry::HKEY_USERS\'
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
	# Unloads a registry hive (by default HKLM\TempUser), retrying a few times.  Leaving the default user hive loaded
	# corrupts new profiles ("The User Profile Service failed the sign-in").  Returns $true if the hive was unloaded.
	param (
		[string] $Root = (Get-ABDefaultUserRegistryRoot),
		[string] $Description = 'default user registry hive'
	)

	for ($i = 1; $i -le 5; $i++) {
		[GC]::Collect()
		[GC]::WaitForPendingFinalizers()
		$output = & reg.exe unload $Root 2>&1
		if ($LASTEXITCODE -eq 0) {
			Write-ABLog "Unloaded $Description"
			return $true
		}
		Write-ABLog "Unable to unload $Description (attempt $i): $output"
		Start-Sleep -Seconds 2
	}
	Write-ABLog "ERROR: Unable to unload $Description"
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


function Get-ABUninstallEntry {
	<#
	.SYNOPSIS
	Returns the uninstall registry values of a Programs provider package (from its FastPackageReference, e.g.
	hklm64\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<key>), or $null if it no longer
	exists.  Only per-machine (hklm32/hklm64) entries are supported.
	#>
	param (
		[Parameter(Mandatory = $true)] [string] $FastPackageReference
	)

	$parts = $FastPackageReference -split '\\', 3
	if ($parts.Count -ne 3 -or $parts[1] -ne 'HKEY_LOCAL_MACHINE') {
		return $null
	}
	switch ($parts[0].ToLowerInvariant()) {
		'hklm64' { $view = [Microsoft.Win32.RegistryView]::Registry64 }
		'hklm32' { $view = [Microsoft.Win32.RegistryView]::Registry32 }
		default { return $null }
	}
	$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
	try {
		$key = $base.OpenSubKey($parts[2])
		if (-not $key) {
			return $null
		}
		try {
			$values = @{}
			foreach ($name in $key.GetValueNames()) {
				$values[$name] = $key.GetValue($name)
			}
			return $values
		}
		finally {
			$key.Close()
		}
	}
	finally {
		$base.Close()
	}
}


function Invoke-ABUninstallCommand {
	<#
	.SYNOPSIS
	Runs a program's registered uninstall command silently: QuietUninstallString, or an msiexec UninstallString changed
	to a quiet uninstall (/X ... /qn /norestart).  Returns the exit code; throws if there is no silent command or the
	command doesn't finish within the timeout (it is then stopped).
	#>
	param (
		[Parameter(Mandatory = $true)] [hashtable] $Entry,
		[int] $TimeoutSeconds = 600
	)

	$command = [string]$Entry['QuietUninstallString']
	if (-not $command.Trim()) {
		$command = [string]$Entry['UninstallString']
		if ($command -match '(?i)msiexec(\.exe)?"?\s+/[IX]\s*"?(\{[0-9A-F-]+\})') {
			$command = "`"$env:SystemRoot\System32\msiexec.exe`" /X $($Matches[2]) /qn /norestart"
		} else {
			throw 'No silent uninstall command (QuietUninstallString or msiexec UninstallString) is registered'
		}
	}
	$command = [Environment]::ExpandEnvironmentVariables($command.Trim())

	# Split the command into the program and its arguments
	if ($command.StartsWith('"')) {
		$end = $command.IndexOf('"', 1)
		if ($end -lt 0) {
			throw "Unable to parse the uninstall command: $command"
		}
		$file = $command.Substring(1, $end - 1)
		$arguments = $command.Substring($end + 1).Trim()
	} elseif (Test-Path -LiteralPath $command -PathType Leaf) {
		$file = $command
		$arguments = ''
	} elseif ($command -match '^(?<file>.+?\.(exe|cmd|bat))(\s+(?<args>.*))?$') {
		$file = $Matches['file']
		$arguments = [string]$Matches['args']
	} else {
		$file, $arguments = $command -split '\s+', 2
	}

	Write-ABLog "  Running: $command"
	$start = @{ FilePath = $file; PassThru = $true; WindowStyle = 'Hidden' }
	if ($arguments) {
		$start.ArgumentList = $arguments
	}
	$proc = Start-Process @start
	if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
		$proc | Stop-Process -Force -ErrorAction SilentlyContinue
		throw "The uninstall command didn't finish within $TimeoutSeconds seconds and was stopped"
	}
	return $proc.ExitCode
}

<#PSScriptInfo
.VERSION 3.3.2
.GUID 39efc9c5-7b51-4d1f-b650-0f3818e5327a
.AUTHOR Michael Niehaus
.COMPANYNAME
.COPYRIGHT Copyright (c) 2025 Michael Niehaus
.TAGS intune endpoint autopilot branding windows
.LICENSEURI https://github.com/mtniehaus/AutopilotBranding/blob/main/LICENSE
.PROJECTURI https://github.com/mtniehaus/AutopilotBranding
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v1.0.0 - 2019-04-16 - Created initial version as an MSI
v1.0.1 - 2019-04-18 - Added additional features for languages and features on demand
v2.0.0 - 2020-05-18 - Converted from an MSI to a Win32 app
v2.0.1 - 2020-05-26 - Added logic to remove the Edge desktop icon
v2.0.2 - 2020-08-11 - Added time zone logic
v2.0.3 - 2023-09-24 - Improved start layout support for Windows 11
v2.0.4 - 2024-01-31 - Improved logging
v2.0.5 - 2024-06-01 - Added logic to hide "Learn about this picture" and related Spotlight stuff
v2.0.6 - 2024-08-15 - Added logic to update OneDrive with the machine-wide installer
v2.0.7 - 2024-09-14 - Added logic to install the Microsoft.Windows.Sense.Client (for MDE) if it was missing
v2.0.8 - 2024-12-27 - Updated for Windows 11 taskbar, added support for removing/disabling Windows features
v3.0.0 - 2025-04-17 - Lots of improvements and additions based on feedback
v3.0.1 - 2025-04-18 - Fixed OneDriveSetup bugs
v3.0.2 - 2025-04-19 - Added a -Force option when installing the Update-InboxApp script; added -AllUsers when removing provisioned in-box apps
v3.0.3 - 2025-05-02 - Additional fixes based on user feedback; tweaked script formatting; added FSIA, desktop switch logic
v3.0.4 - 2025-05-02 - Fixed FSIA default (should be 0)
v3.0.5 - 2025-05-14 - Remove logic that removed widgets, cross-device app.
v3.1.0 - 2025-06-01 - Modified WinGet logic, switched to PowerShell for creating package
v3.2.0 - 2025-07-15 - Various fixes (start menu layout, apps, etc.)
v3.2.1 - 2025-07-15 - Updated makeapps.cmd to use PowerShell 7
v3.3.0 - 2025-09-20 - Added bookmark cleanup for Edge, Chrome. Fixed start menu config. Added Try/catch/finally. Added OOBE check.
v3.3.1 - 2025-10-10 - Minor bug fixes
v3.3.2 - 2026-11-03 - Fixed WinGet step aborting the script; failures in one step no longer skip the rest; default user hive is always unloaded;
                      ARM64 fixes for Edge and VC++ runtime; optional computer rename; optional PowerShell-based language config;
                      in-box app removal also removes installed packages; removed obsolete IE http/https associations
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory = $false)] [Switch] $Force = $false
)


function Log() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [String] $message
	)

	$ts = get-date -f "yyyy/MM/dd hh:mm:ss tt"
	Write-Output "$ts $message"
}


function Check-NuGetProvider {
	[CmdletBinding()]
	param (
		[version]$MinimumVersion = [version]'2.8.5.201'
	)
	$provider = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
	Sort-Object Version -Descending |
	Select-Object -First 1

	if (-not $provider) {
		Log 'NuGet Provider Package not detected, installing...'
		Install-PackageProvider -Name NuGet -Force | Out-Null
	} elseif ($provider.Version -lt $MinimumVersion) {
		Log "NuGet provider v$($provider.Version) is less than required v$MinimumVersion; updating."
		Install-PackageProvider -Name NuGet -Force | Out-Null
        
	} else {
		Log "NuGet provider meets min requirements (v:$($provider.Version))."
	}

}


function Dismount-DefaultUserHive {
	# Leaving the default user hive loaded corrupts new profiles ("The User Profile Service failed the sign-in"), so retry a few times
	for ($i = 1; $i -le 5; $i++) {
		[GC]::Collect()
		[GC]::WaitForPendingFinalizers()
		& reg.exe unload HKLM\TempUser 2>&1 | Out-Null
		if ($LASTEXITCODE -eq 0) {
			Log "Default user registry unloaded"
			$script:hiveLoaded = $false
			return
		}
		Log "Unable to unload default user registry (attempt $i), retrying..."
		Start-Sleep -Seconds 2
	}
	Log "ERROR: Unable to unload default user registry"
}

# Get the Current start time in UTC format, so that Time Zone Changes don't affect total runtime calculation
$startUtc = [datetime]::UtcNow

# Don't show progress bar for Add-AppxPackage - there's a weird issue where the progress stays on the screen after the apps are installed
$OriginalProgressPreference = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'

# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
	if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
		& "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
		Exit $lastexitcode
	}
}

# Check the OS architecture (not the process architecture, which could be x86 or x64 under emulation on ARM64)
$isArm64 = ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") -or ($env:PROCESSOR_ARCHITEW6432 -eq "ARM64")

# Create output folder
if (-not (Test-Path "$($env:ProgramData)\Microsoft\AutopilotBranding")) {
	Mkdir "$($env:ProgramData)\Microsoft\AutopilotBranding" -Force
}

# Start logging
Start-Transcript "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.log"

# Creating tag file
Set-Content -Path "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"

# STEP 0: Bail out if we aren't in OOBE
$TypeDef = @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
 
namespace Api
{
 public class Kernel32
 {
   [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
   public static extern int OOBEComplete(ref int bIsOOBEComplete);
 }
}
"@
Add-Type -TypeDefinition $TypeDef -Language CSharp
$IsOOBEComplete = $false
$null = [Api.Kernel32]::OOBEComplete([ref] $IsOOBEComplete)
if ($IsOOBEComplete) {
	if (-not $Force)
	{
		Log "OOBE is completed, bailing out without doing any configuration."
  		Stop-Transcript
		exit 0
	} else {
		Log "OOBE is completed but -Force specified, will run anyway."
	}
}

$hiveLoaded = $false
try
{
	# PREP: Load the Config.xml
	$installFolder = "$PSScriptRoot\"
	Log "Install folder: $installFolder"
	Log "Loading configuration: $($installFolder)Config.xml"
	[Xml]$config = Get-Content "$($installFolder)Config.xml"

	# PREP: Load the default user registry
	if (Test-Path "HKLM:\TempUser") {
		# Left over from a previous run that didn't finish, unload it first so the load below succeeds
		$hiveLoaded = $true
		Dismount-DefaultUserHive
	}
	Log "Loading Default User Registry Hive NTUSER.DAT"
	reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Null
	$hiveLoaded = ($LASTEXITCODE -eq 0)

	# STEP 0A: Rename the computer (if specified). %SERIAL% is replaced with the BIOS serial number.
	# Don't use this with hybrid Entra join; set the name in the Autopilot profile or domain join profile instead.
	if ($config.Config.ComputerName) {
		try {
			$serial = (Get-CimInstance Win32_BIOS).SerialNumber -replace '[^A-Za-z0-9-]', ''
			$newName = $config.Config.ComputerName -ireplace '%SERIAL%', $serial
			$newName = ($newName -replace '[^A-Za-z0-9-]', '')
			$newName = $newName.Substring(0, [Math]::Min(15, $newName.Length)).Trim('-')
			if ([string]::IsNullOrWhiteSpace($newName)) {
				Log "Computer name is empty after substitution, skipping rename"
			} elseif ($env:COMPUTERNAME -ieq $newName) {
				Log "Computer is already named $newName"
			} else {
				Log "Renaming computer to $newName (takes effect after reboot)"
				Rename-Computer -NewName $newName -Force -ErrorAction Stop
			}
		} catch {
			Log "Unable to rename computer: $_"
		}
	}

	# STEP 1: Apply a custom start menu and taskbar layout
	$ci = Get-ComputerInfo
	if ($ci.OsBuildNumber -le 22000) {
		if ($config.Config.SkipStartLayout -ine "true") {
			Log "Importing layout: $($installFolder)Layout.xml"
			Copy-Item "$($installFolder)Layout.xml" "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Force
		} else {
			Log "Skipping Start layout (Windows 10)"
		}
	} else {
		if ($config.Config.SkipStartLayout -ine "true") {
			Log "Copying Start menu layout: $($installFolder)Start2.bin"
			MkDir -Path "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Force -ErrorAction SilentlyContinue | Out-Null
			Copy-Item "$($installFolder)Start2.bin" "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start2.bin" -Force
			Log "Copying Start menu settings: $($installFolder)settings.dat"
			MkDir -Path "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\Settings" -Force -ErrorAction SilentlyContinue | Out-Null
			Copy-Item "$($installFolder)settings.dat" "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\Settings\settings.dat" -Force
		} else {
			Log "Skipping Start layout (Windows 11)"
		}

		if ($config.Config.SkipTaskbarLayout -ine "true") {
			Log "Importing Taskbar layout: $($installFolder)TaskbarLayoutModification.xml"
			MkDir -Path "C:\Windows\OEM\" -Force -ErrorAction SilentlyContinue | Out-Null
			Copy-Item "$($installFolder)TaskbarLayoutModification.xml" "C:\Windows\OEM\TaskbarLayoutModification.xml" -Force
			Log "Set 'Start Layout' policy settings to apply the custom taskbar layout"
			& reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v StartLayoutFile /t REG_EXPAND_SZ /d "%SystemRoot%\OEM\TaskbarLayoutModification.xml" /f /reg:64 2>&1 | Out-Null
			& reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v LockedStartLayout /t REG_DWORD /d 1 /f /reg:64 2>&1 | Out-Null
			Log "Unpin the Microsoft Store app from the taskbar"
			& reg.exe add "HKLM\TempUser\Software\Policies\Microsoft\Windows\Explorer" /v NoPinningStoreToTaskbar /t REG_DWORD /d 1 /f /reg:64 2>&1 | Out-Null
		} else {
			Log "Skipping Taskbar layout (Windows 11)"
		}
	}

	# STEP 2: Configure background
	if ($config.Config.SkipTheme -ine "true") {
		Log "Setting up Autopilot theme"
		Mkdir "C:\Windows\Resources\OEM Themes" -Force | Out-Null
		Copy-Item "$installFolder\Autopilot.theme" "C:\Windows\Resources\OEM Themes\Autopilot.theme" -Force
		Mkdir "C:\Windows\web\wallpaper\Autopilot" -Force | Out-Null
		Copy-Item "$installFolder\Autopilot.jpg" "C:\Windows\web\wallpaper\Autopilot\Autopilot.jpg" -Force
		Log "Setting Autopilot theme as the new user default"
		& reg.exe add "HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v InstallTheme /t REG_EXPAND_SZ /d "%SystemRoot%\resources\OEM Themes\Autopilot.theme" /f /reg:64 2>&1 | Out-Null
		& reg.exe add "HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v CurrentTheme /t REG_EXPAND_SZ /d "%SystemRoot%\resources\OEM Themes\Autopilot.theme" /f /reg:64 2>&1 | Out-Null
	} else {
		Log "Skipping Autopilot theme"
	}

	# STEP 2A: Set lock screen image, see https://www.systemcenterdudes.com/apply-custom-lock-screen-wallpaper-using-intune/
	if ($config.Config.SkipLockScreen -ine "true") {
		Log "Configuring lock screen image"
		$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
		Mkdir "C:\Windows\web\wallpaper\Autopilot" -Force | Out-Null
		$LockScreenImage = "C:\Windows\web\wallpaper\Autopilot\AutopilotLock.jpg"
		Copy-Item "$installFolder\AutopilotLock.jpg" $LockScreenImage -Force
		if (!(Test-Path -Path $RegPath)) {
			New-Item -Path $RegPath -Force | Out-Null
		}
		New-ItemProperty -Path $RegPath -Name LockScreenImagePath -Value $LockScreenImage -PropertyType String -Force | Out-Null
		New-ItemProperty -Path $RegPath -Name LockScreenImageUrl -Value $LockScreenImage -PropertyType String -Force | Out-Null
		New-ItemProperty -Path $RegPath -Name LockScreenImageStatus -Value 1 -PropertyType DWORD -Force | Out-Null
	} else {
		Log "Skipping lock screen image"
	}

	# STEP 2B: Stop Start menu from opening on first logon
	& reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StartShownOnUpgrade /t REG_DWORD /d 1 /f /reg:64 2>&1 | Out-Null

	# STEP 2C: Hide "Learn more about this picture" from the desktop (so wallpaper will work)
	& reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /t REG_DWORD /d 1 /f /reg:64 2>&1 | Out-Null

	# STEP 2D: Disable Windows Spotlight as per https://github.com/mtniehaus/AutopilotBranding/issues/13#issuecomment-2449224828 (so wallpaper will work)
	Log "Disabling Windows Spotlight for Desktop"
	& reg.exe add "HKLM\TempUser\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSpotlightCollectionOnDesktop /t REG_DWORD /d 1 /f /reg:64 2>&1 | Out-Null

	# STEP 3: Left Align Start Button in the default user profile, users can change it if they want
	if ($config.Config.SkipLeftAlignStart -ine "true") {
		Log "Configuring left aligned Start menu"
		& reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f /reg:64 2>&1 | Out-Null
	} else {
		Log "Skipping Left align start"
	}

	# STEP 4: Hide the widgets
	if ($config.Config.SkipHideWidgets -ine "true") {
		# This will fail on Windows 11 24H2 due to UCPD, see https://kolbi.cz/blog/2024/04/03/userchoice-protection-driver-ucpd-sys/
		# New Work Around tested with 24H2 to disable widgets as a preference
		try {
			Log "Attempting to Hide widgets via Reg Key"	
			$output = & reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f /reg:64 2>&1
			#write-host $output
			if($LASTEXITCODE -ne 0) {
			throw $output
			}
			Log "Widgets Hidden Completed"
		}
		catch {
			$errorMessage = $_.Exception.Message
			#Write-Host "This is the error: $errorMessage"
			if ($errorMessage -like '*Access is denied*') {
			Log "UCPD driver may active"
			Log "Attempting Widget Hiding workaround (TaskbarDa)"
			$regExePath = (Get-Command reg.exe).Source
			$tempRegExe = "$($env:TEMP)\reg1.exe"
			Copy-Item -Path $regExePath -Destination $tempRegExe -Force -ErrorAction Stop
			& $tempRegExe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f /reg:64 2>&1 | Out-Null
			Remove-Item $tempRegExe -Force -ErrorAction SilentlyContinue
			Log "Widget Workaround Completed"
			}
		}
	} else {
		Log "Skipping Hide widgets"
	}

	# STEP 4A: Disable Widgets (Grey out Settings Toggle)
	if ($config.Config.SkipDisableWidgets -ine "true") {

		# GPO settings below will completely disable Widgets, see:https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-newsandinterests#allownewsandinterests
		Log "Disabling Widgets"
		if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Dsh")) {
			New-Item -Path "HKLM:\Software\Policies\Microsoft\Dsh" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Dsh"  -Name "DisableWidgetsOnLockScreen" -Value 1
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Dsh"  -Name "DisableWidgetsBoard" -Value 1
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Dsh"  -Name "AllowNewsAndInterests" -Value 0

	}
	# STEP 4C: Set Search Bar to Icon Only via RunOnce
	if ($config.Config.SkipSetSearchIcon -ine "true") {

 	Log "Setting Searchbar Icon via RunOnce"
	& reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f | Out-Null # Ensure path exists
	$RunOnceCommand = 'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /t REG_DWORD /v SearchboxTaskbarMode /d 1 /f'
	& reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v 'SetSearchIconOnly' /t REG_SZ /d $RunOnceCommand /f | Out-Null
	}

	# STEP 5: Set time zone (if specified)
	if ($config.Config.TimeZone) {
		Log "Setting time zone: $($config.Config.TimeZone)"
		Set-Timezone -Id $config.Config.TimeZone
	} else {
		# Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Allow" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
		Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
	}

	# STEP 6: Remove specified provisioned apps if they exist
	Log "Removing specified in-box provisioned apps"
	$apps = Get-AppxProvisionedPackage -online
	# Also look at installed packages, as OEMs sometimes install apps for all users without provisioning them
	$installedApps = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
	$config.Config.RemoveApps.App | ForEach-Object {
		$current = $_
		$apps | Where-Object { $_.DisplayName -eq $current } | ForEach-Object {
			try {
				Log "Removing provisioned app: $current"
				$_ | Remove-AppxProvisionedPackage -Online -AllUsers -ErrorAction Stop | Out-Null
			}
			catch {
				Log "  Unable to remove provisioned app $($current): $_"
			}
		}
		$installedApps | Where-Object { $_.Name -eq $current -and -not $_.NonRemovable } | ForEach-Object {
			try {
				Log "Removing installed app: $($_.PackageFullName)"
				$_ | Remove-AppxPackage -AllUsers -ErrorAction Stop | Out-Null
			}
			catch {
				Log "  Unable to remove installed app $($current): $_"
			}
		}
	}

	# STEP 6A: Prevent Copilot PWA from being installed
	if ($config.Config.SkipRemoveCopilotPWA -ine "true") {
		Log "Removing specified in-box provisioned apps"
		reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoInstalledPWAs" /v CopilotPWAPreinstallCompleted /t REG_DWORD /d 1 /f /reg:64
	}

	# STEP 7: Install OneDrive per machine
	$oneDriveInstalled = $false
	if ($config.Config.OneDriveSetup) {
		try {
			$dest = "$($env:TEMP)\OneDriveSetup.exe"
			$client = new-object System.Net.WebClient
			if ($isArm64) {
				$url = $config.Config.OneDriveARMSetup
			} else {
				$url = $config.Config.OneDriveSetup
			}
			Log "Downloading OneDriveSetup: $url"
			$client.DownloadFile($url, $dest)
			Log "Installing: $dest"
			$proc = Start-Process $dest -ArgumentList "/allusers /silent" -WindowStyle Hidden -PassThru
			$proc.WaitForExit()
			Log "OneDriveSetup exit code: $($proc.ExitCode)"
			$oneDriveInstalled = Test-Path "C:\Program Files\Microsoft OneDrive\OneDrive.exe"
		} catch {
			Log "Unable to install OneDrive per-machine: $_"
		}
	}

	# Only repoint the default user Run key when the per-machine OneDrive actually exists, otherwise OneDrive would never start
	if ($oneDriveInstalled) {


		Log "Making sure the Defaultuser Run key exists"
		$RegRunPath = "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Run"
		if (!(Test-Path -Path $RegRunPath)) {
			Log "Run Key not found!.. Will create it now."
			& reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" /f /reg:64 2>&1 | Out-Null	
			Log "Run Key created"	
		}
        else{ 
            Log "Run Key Already Exists"
        }

		$RunValueName = "OneDriveSetup"
		Log "Looking for per-user OneDriveSetup REG_SZ"
		# Check for the existence of string OneDriveSetup which should have the value ( C:\Windows\System32\OneDriveSetup.exe /thfirstsetup )
		# This is creating multiple Onedrives launching at sign. Remove as no longer needed once Machine-Wide installer is run.
		if (Get-ItemProperty -Path $RegRunPath -Name $RunValueName -ErrorAction SilentlyContinue) {
    		Log "Per-User '$RunValueName'  still exists. Cleaning up."
			& reg.exe delete "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f /reg:64 2>&1 | Out-Null
			Log "Per-User '$RunValueName' removed."
		}
		else {
    		 Log "'$RunValueName' per-user not found. This is Good."
		}

		#OneDriveSetup should set these keys but can take an additional reboot after copying binaries. This should jump start OneDrive at first User Login.
		Log "Setting OneDrive to Autostart from Machine-Wide location"
		$OnedrivePath = '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background'
		#& reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" /v 'OneDrive' /t REG_SZ /d $OnedrivePath /f /reg:64 2>&1 #| Out-Null
        New-Itemproperty -Path $RegRunPath -Name 'OneDrive' -Value $OnedrivePath -PropertyType String -Force | Out-Null
	}

	# STEP 8: Don't let Edge create a desktop shortcut (roams to OneDrive, creates mess)
	Log "Turning off (old) Edge desktop shortcut"
	& reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v DisableEdgeDesktopShortcutCreation /t REG_DWORD /d 1 /f /reg:64 2>&1 | Out-Null
	Log "Turning off Edge desktop icon"
	& reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d 0 /f /reg:64 2>&1 | Out-Null
	& reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "RemoveDesktopShortcutDefault" /t REG_DWORD /d 2 /f /reg:64 2>&1 | Out-Null
	if (Test-Path "C:\Users\Public\Desktop\Microsoft Edge.lnk") {
		Log "Removing Edge desktop shortcut"
		Remove-Item "C:\Users\Public\Desktop\Microsoft Edge.lnk" -Force
	}

	# STEP 8A: Attempt to Donwload and install Latest Edge for Business MSI from Evergreen URL
	if ($config.Config.SkipEdgeUpdate -ine "true") {
		# Installing the x64 MSI on ARM64 replaces the native Edge and breaks WebView2, so only use the ARM64 MSI there
		if ($isArm64) {
			$url = $config.Config.EdgeBusinessARM
			$dest = "$($env:TEMP)\MicrosoftEdgeEnterpriseARM64.msi"
		} else {
			$url = $config.Config.EdgeBusinessMSI
			$dest = "$($env:TEMP)\MicrosoftEdgeEnterpriseX64.msi"
		}

		if (-not $url) {
			Log "No Edge for Business MSI specified for this architecture (EdgeBusinessARM for ARM64), skipping Edge update"
		} else {
			try {
				$client = new-object System.Net.WebClient
				Log "Downloading Latest Edge for Business: $url"
				$client.DownloadFile($url, $dest)

				# Edge Version is buried in Comments of MSI. Parse the first 13 charaters to pull out Version number.
				$shell = New-Object -ComObject Shell.Application
				$folder = $shell.NameSpace((Split-Path $dest))
				$file = $folder.ParseName((Split-Path $dest -Leaf))
				$comment = $folder.GetDetailsOf($file, 24) # 24 is the index for comments
				$versionOnly = $comment.Substring(0, [Math]::Min(13, $comment.Length))

				Log "Installing Edge for Business V:$versionOnly"
				$arguments = "/i `"$($dest)`" /qn /L*v $($env:TEMP)\EdgeBusiness.log"
				$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -PassThru -WindowStyle Hidden
				$proc.WaitForExit()
				if ($proc.ExitCode -ne 0) {
					Log "MSI Error (exit code $($proc.ExitCode)), trying to Run MicrosoftEdgeUpdate.exe instead"
					$proc = Start-Process -FilePath "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" -argumentlist "/silent /install appguid={56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}&appname=Microsoft%20Edge&needsadmin=True" -PassThru -WindowStyle Hidden
					$proc.WaitForExit()
					Log "Edge Updater Triggered"
				} else {
					Log "Edge for Business Updated"
				}
			} catch {
				Log "Unable to update Edge for Business: $_"
			}
		}
	}

	# STEP 8B: Clean up any OEM-added bookmarks from the default user profile
	$bookmarks = "C:\Users\Default\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
	if (Test-Path $bookmarks) {
		Log "Removing Edge bookmarks folder from default profile"
		Remove-Item $bookmarks -Force
	}
	$Bookmarksregpath = "HKLM:\SOFTWARE\Microsoft\MicrosoftEdge\Main\FavoriteBarItems"
	if (test-path $Bookmarksregpath){
	Remove-Item -path $Bookmarksregpath -Recurse -Force
	Log "OEM Edge Bookmarks were detected and removed successfully"
	}else{
	Log "No OEM Edge Booksmarks were detected"
	}



	

	# STEP 9: Add language packs
	if (Test-Path "$($installFolder)LPs") {
		Get-ChildItem "$($installFolder)LPs" -Filter *.cab | ForEach-Object {
			Log "Adding language pack: $($_.FullName)"
			Add-WindowsPackage -Online -NoRestart -PackagePath $_.FullName
		}
	}

	# STEP 10: Change language
	if ($config.Config.Language) {
		Log "Configuring language using: $($config.Config.Language)"
		& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$($installFolder)$($config.Config.Language)`""
	}

	# STEP 10A: Install and configure a language using the LanguagePackManagement cmdlets (Windows 11), as an alternative to intl.cpl
	if ($config.Config.LanguageSettings.Language) {
		$ls = $config.Config.LanguageSettings
		try {
			Log "Installing language: $($ls.Language) (downloaded from Windows Update, this can take a while)"
			Install-Language -Language $ls.Language -ErrorAction Stop | Out-Null
			Set-SystemPreferredUILanguage -Language $ls.Language -ErrorAction Stop
		} catch {
			# This sometimes fails the first time a language is installed; the remaining settings still apply
			Log "  Unable to install or set display language $($ls.Language): $_"
		}
		try {
			$locale = if ($ls.Locale) { $ls.Locale } else { $ls.Language }
			Log "Setting system locale, culture, and user language list: $locale"
			Set-WinSystemLocale -SystemLocale $locale -ErrorAction Stop
			Set-Culture -CultureInfo $locale -ErrorAction Stop
			Set-WinUserLanguageList -LanguageList $locale -Force -ErrorAction Stop
			if ($ls.GeoId) {
				Log "Setting home location: $($ls.GeoId)"
				Set-WinHomeLocation -GeoId ([int]$ls.GeoId) -ErrorAction Stop
			}
			if (Get-Command Copy-UserInternationalSettingsToSystem -ErrorAction SilentlyContinue) {
				Log "Copying international settings to the welcome screen and new users"
				Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true -ErrorAction Stop
			} else {
				Log "  Copy-UserInternationalSettingsToSystem is not available on this OS version, settings will not be copied to new users"
			}
		} catch {
			Log "  Unable to configure regional settings: $_"
		}
	}

	# STEP 11: Add features on demand, Disable Optional Features, Remove Windows Capabilities
	$currentWU = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Ignore).UseWuServer
	if ($currentWU -eq 1) {
		Log "Turning off WSUS"
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 0
		Restart-Service wuauserv
	}

	# Step 11A: Disable Optional features
	if ($config.Config.DisableOptionalFeatures.Feature.Count -gt 0) {
		try {
			$EnabledOptionalFeatures = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" }
			foreach ($EnabledFeature in $EnabledOptionalFeatures) {
				if ($config.Config.DisableOptionalFeatures.Feature -contains $EnabledFeature.FeatureName) {
					Log "Disabling Optional Feature:  $($EnabledFeature.FeatureName)"
					try {
						Disable-WindowsOptionalFeature -Online -FeatureName $EnabledFeature.FeatureName -NoRestart -ErrorAction Stop | Out-Null
					}
					catch {
						Log "  Unable to disable optional feature: $_"
					}
				}
			}
			}
		catch {
			Log "Unexpected error querying Windows optional features: $_"
		}
	}

	# Step 11B: Remove Windows Capabilities
	if ($config.Config.RemoveCapability.Capability.Count -gt 0) {
		try {
			# This can fail (e.g. 0x800f0800 on some OEM images); log it and keep going
			$InstalledCapabilities = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.State -eq "Installed" }
			foreach ($InstalledCapability in $InstalledCapabilities) {
				if ($config.Config.RemoveCapability.Capability -contains $InstalledCapability.Name.Split("~")[0]) {
					Log "Removing Windows Capability:  $($InstalledCapability.Name)"
					try {
						Remove-WindowsCapability -Online -Name $InstalledCapability.Name -ErrorAction Stop | Out-Null
					}
					catch {
						Log "  Unable to remove Windows capability: $_"
					}
				}
			}
		} catch {
			Log "Unexpected error querying Windows capabilities: $_"
		}
	}

	# Step 11C: Add features on demand
	if ($config.Config.AddFeatures.Feature.Count -gt 0) {
		$config.Config.AddFeatures.Feature | ForEach-Object {
			Log "Adding Windows feature: $_"
			try {
				$result = Add-WindowsCapability -Online -Name $_ -ErrorAction Stop
				if ($result.RestartNeeded) {
					Log "  Feature $_ was installed but requires a restart"
				}
			}
			catch {
				Log "  Unable to add Windows capability: $_"
			}
		}
	}

	if ($currentWU -eq 1) {
		Log "Turning on WSUS"
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 1
		Restart-Service wuauserv
	}

	# STEP 12: Customize default apps
	if ($config.Config.DefaultApps) {
		Log "Setting default apps: $($config.Config.DefaultApps)"
		& Dism.exe /Online /Import-DefaultAppAssociations:`"$($installFolder)$($config.Config.DefaultApps)`"
	}

	# STEP 13: Set registered user and organization
	if ($config.Config.RegisteredOwner) {
		Log "Configuring registered user information"
		& reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d "$($config.Config.RegisteredOwner)" /f /reg:64 2>&1 | Out-Null
		& reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d "$($config.Config.RegisteredOrganization)" /f /reg:64 2>&1 | Out-Null
	}

# STEP 14: Configure OEM branding info
	
	if ($config.Config.OEMInfo) {
		Log "Configuring OEM branding info"
		
		$OEMpath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'

		$cs  = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
		$csp = $null

    # Manufacturer (CIM → config fallback)
    if ($cs -and -not [string]::IsNullOrWhiteSpace($cs.Manufacturer)) {
        $OEMVender = $cs.Manufacturer
    } else {
        $OEMVender = $config.Config.OEMInfo.Manufacturer
    }
	Log "Manufacturer found is: $($OEMVender)"
	
    # Model for Lenovo is found under the 'Version' property. 'Name' returns a SKU and is not friendly name.
    if ($OEMVender -match 'Lenovo' -and $cs) {
        $csp = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue

        if ($csp -and -not [string]::IsNullOrWhiteSpace($csp.Version)) {
            $OEMModel = $csp.Version
        }
    }
	
    # Get model for Non-Lenovo PCs or Lenovo fallback
    if (-not $OEMModel) {
        if ($cs -and -not [string]::IsNullOrWhiteSpace($cs.Model)) {
            $OEMModel = $cs.Model
        } else {
            $OEMModel = $config.Config.OEMInfo.Model
        }
    }
		Log "Model found is: $($OEMModel)"
		
		New-ItemProperty -Path $OEMpath -Name 'Manufacturer' -PropertyType String -Value $OEMVender -Force | Out-Null
		New-ItemProperty -Path $OEMpath -Name 'Model'        -PropertyType String -Value $OEMModel  -Force | Out-Null	
		New-ItemProperty -Path $OEMpath -Name 'SupportPhone' -PropertyType String -Value $config.Config.OEMInfo.SupportPhone -Force | Out-Null
		New-ItemProperty -Path $OEMpath -Name 'SupportHours' -PropertyType String -Value $config.Config.OEMInfo.SupportHours -Force | Out-Null
		New-ItemProperty -Path $OEMpath -Name 'SupportURL' -PropertyType String -Value $config.Config.OEMInfo.SupportURL -Force | Out-Null
				
	if ($ci.OsBuildNumber -le 22000) {
		
		if (Test-Path "$installFolder\$($config.Config.OEMInfo.Logo)") { 
			Log "BMP Logo Found copying.."
			Copy-Item "$installFolder\$($config.Config.OEMInfo.Logo)" "C:\Windows\$($config.Config.OEMInfo.Logo)" -Force 
			New-ItemProperty -Path $OEMpath -Name 'Logo' -PropertyType String -Value $config.Config.OEMInfo.Logo -Force | Out-Null
		}
	}
	else {
		Log "Windows 11 doesnt support Logo Bmp, skipping..."
		}
	Log "OEM Branding Info set"
	
	}
	

	# STEP 15A: Force Enterprise SKU
	if ($config.Config.SkipEnterpriseGVLK -ine "true") {
		Log "Forcing Enterprise SKU"
		& changepk.exe /ProductKey NPPR9-FWDCX-D2C8J-H872K-2YT43
	}

	# STEP 15B: Enable UE-V
	if ($config.Config.SkipUEV -ine "true") {
		Log "Enabling UE-V"
		Enable-UEV
		Set-UevConfiguration -Computer -SettingsStoragePath "%OneDriveCommercial%\UEV" -SyncMethod External -DisableWaitForSyncOnLogon
		Get-ChildItem "$($installFolder)UEV" -Filter *.xml | ForEach-Object {
			Log "Registering template: $($_.FullName)"
			Register-UevTemplate -Path $_.FullName
		}
	} else {
		Log "Skipping UE-V"
	}

	# STEP 16: Disable network location fly-out
	Log "Turning off network location fly-out"
	& reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f /reg:64 | Out-Null

	# STEP 17: Remove the registry keys for Dev Home and Outlook New
	# This is a workaround for the issue where the Dev Home and Outlook New apps are installed by default
	if ($config.Config.SkipAutoinstallingApps -ine "true") {
		Log "Disabling Windows 11 Dev Home and Outlook New"
		$DevHome = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate"
		$OutlookNew = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate"
		if (Test-Path -Path $DevHome) {
			Log "  Removing DevHome key"
			Remove-Item -Path $DevHome -Force
		}
		if (Test-Path -Path $OutlookNew) {
			Log "  Removing Outlook for Windows key"
			Remove-Item -Path $OutlookNew -Force
		}
	} else {
		Log "Skipping autoinstalling app logic"
	}

	# STEP 18: WinGet installs
	if ($config.Config.SkipWinGet -ne 'true') {
		try {
			# Ensure NuGet provider before installing modules
			Check-NuGetProvider

			Log 'Installing WinGet.Client module'
			Install-Module -Name Microsoft.WinGet.Client -Force -Scope AllUsers -Repository PSGallery -ErrorAction Stop | Out-Null
		} catch {
			Log "Unable to install the WinGet.Client module: $_"
		}

		# Repair-WinGetPackageManager updates WinGet, but it periodically breaks (unsupported in Windows PowerShell, CDN timeouts, etc.).
		# WinGet is in-box on current Windows 11 builds, so a failure here isn't fatal.
		Log "Installing Latest Winget package and dependencies"
		try {
			Repair-WinGetPackageManager -Force -Latest -ErrorAction Stop | Out-Null
		} catch {
			Log "  Winget repair failed, will use the existing WinGet if present: $_"
		}

		try {
			# Use the VC++ runtime that matches the OS architecture
			$vcArch = if ($isArm64) { 'arm64' } else { 'x64' }
			$VCppRedistributable_Url = "https://aka.ms/vs/17/release/vc_redist.$vcArch.exe"
			$VCppRedistributable_Path = Join-Path $env:TEMP "vc_redist.$vcArch.exe"
			Log "Installing VC++ runtime: $VCppRedistributable_Url"
			Invoke-WebRequest -uri $VCppRedistributable_Url -outfile $VCppRedistributable_Path -UseBasicParsing -ErrorAction Stop
			Start-Process -FilePath $VCppRedistributable_Path -ArgumentList "/install", "/quiet", "/norestart" -Wait
			Remove-Item $VCppRedistributable_Path -Force -ErrorAction SilentlyContinue
		} catch {
			Log "  Unable to install VC++ runtime: $_"
		}

		#Look for Winget.exe in the C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_* Folder (newest version last)
		$wingetExe = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
			Sort-Object { [version](($_.Path -split '_')[1]) } |
			Select-Object -Last 1 -ExpandProperty Path
		if (-not $wingetExe) {
			Log "WinGet not found, skipping WinGet installs"
		} else {
			$wingetVer = & "$wingetExe" --version
			Log "Winget version is: $wingetVer"

			foreach ($id in $config.Config.WinGetInstall.Id) {
				Log "WinGet installing: $id"
				try {
					& "$wingetExe" install $id --silent --scope machine --accept-package-agreements --accept-source-agreements
					Log "  WinGet exit code: $LASTEXITCODE"
				}
				catch {
					Log "WinGet installing error: $_"
				}
			}
		}

	} else {
		Log 'Skipping WinGet installs'
	}

	# STEP 18A: Configure Chrome initial preferences (needs to happen after Chrome is installed but before a user logs in)
	# See https://www.chromium.org/administrators/configuring-other-preferences/ for available preferences that can be set.
	if ($config.Config.SkipChromeConfig -ine "true") {
		Log "Copying Chrome initial_preferences file"
		$dest = "C:\Program Files\Google\Chrome\Application"
		if (-not (Test-Path $dest))
		{
			MkDir $dest -Force | Out-Null
		}
		Copy-Item "$PSScriptRoot\initial_preferences" "$dest\" -Force
		if (Test-Path "C:\Users\Public\Desktop\Google Chrome.lnk") {
			Log "Removing Chrome desktop shortcut"
			Remove-Item "C:\Users\Public\Desktop\Google Chrome.lnk" -Force
		}
	}

	# STEP 19: Disable extra APv2 pages (too late to do anything about the EULA), see https://call4cloud.nl/autopilot-device-preparation-hide-privacy-settings/
	if ($config.Config.SkipAPv2 -ine "true") {
		$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
		New-ItemProperty -Path $registryPath -Name "DisablePrivacyExperience" -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path $registryPath -Name "DisableVoice" -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path $registryPath -Name "PrivacyConsentStatus" -Value 1 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path $registryPath -Name "ProtectYourPC" -Value 3 -PropertyType DWord -Force | Out-Null
		Log 'APv2 extra pages disabled'
	} else {
		Log 'Skipping APv2 tweaks'
	}

	# CLEANUP: Unload default user registry (the remaining steps don't need it)
	Log "Unloading Default user Registry"
	if ($hiveLoaded) {
		Dismount-DefaultUserHive
	}

	# STEP 20: Updates & Inbox-App script
	if ($config.Config.SkipUpdates -ne 'true') {
		try {

			#Nuget v 2.8.5.201 is required to import mtniehaus's PS Gallery Script Update-InboxApp
			$minrequired = [version]'2.8.5.201'
			Check-NuGetProvider -MinimumVersion $minrequired
		} catch {
			Log "Error updating NuGet"
		}
		try {
			Log 'Installing Update-InboxApp script'
			Install-Script Update-InboxApp -Force | Out-Null

			Log 'Updating inbox apps'
			# The path might not be set right to find this, so we'll hard-code the location
			Get-AppxPackage -AllUsers | Select-Object -Unique PackageFamilyName | . "C:\Program Files\WindowsPowerShell\Scripts\Update-InboxApp.ps1" -Verbose
		} catch {
			Log "Error updating in-box apps: $_"
		}
		try {
			Log 'Triggering Windows Update scan'
			$ns = 'Root\cimv2\mdm\dmmap'
			$class = 'MDM_EnterpriseModernAppManagement_AppManagement01'
			Get-CimInstance -Namespace $ns -ClassName $class | Invoke-CimMethod -MethodName UpdateScanMethod
		} catch {
			Log "Error triggering Windows Update scan: $_"
		}
	} else {
		Log 'Skipping updates'
	}

	# STEP 21: Skip FSIA and turn off delayed desktop switch
	if ($config.Config.SkipShowDesktopFaster -ine "true") {
		Log "Skipping FSIA and turning off delayed desktop switch"
		$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
		New-ItemProperty -Path $registryPath -Name "EnableFirstLogonAnimation" -Value 0 -PropertyType DWord -Force | Out-Null
		New-ItemProperty -Path $registryPath -Name "DelayedDesktopSwitchTimeout" -Value 0 -PropertyType DWord -Force | Out-Null
	}
	# STEP 22: Remove All Office Products
	## Remove All Office Products
	if ($config.Config.SkipRemoveOffice -ine "true") {
	Log  "Remove All Office Products Selected"
	
## The XML below will Remove All Microsoft C2Rs ( Click-to-Runs), regardless of Product ID and Languages. To remove All Comment out or remove the XML block between Start and End above. Then Uncomment the XML below.
$xml = @"
<Configuration>
  <Display Level="None" AcceptEULA="True" />
  <Property Name="FORCEAPPSHUTDOWN" Value="True" />
  <Remove All="TRUE">
  </Remove>
  <RemoveMSI />
</Configuration>
"@
## Remove All Office Products XML End ##

	# Define temp folder and file paths
	$tempFolder     = $env:TEMP
	$xmlPath        = Join-Path $tempFolder 'o365.xml'
	$odtPath        = Join-Path $tempFolder 'setup.exe'

	try {
		# Write XML to temp folder
		$xml | Out-File -FilePath $xmlPath -Encoding UTF8
		Log "Downloading latest ODT"
		# Download the Latest ODT into temp folder. URI obtained from Stealthpuppy's Evergreen Project
		$odtUrl = 'https://officecdn.microsoft.com/pr/wsus/setup.exe'
		Invoke-WebRequest -Uri $odtUrl `
	                  -OutFile $odtPath `
	                  -UseBasicParsing `
	                  -ErrorAction Stop

		Log "Running ODT"
		# Run the ODT from temp, pointing at the XML also in temp
		$proc = Start-Process -FilePath $odtPath `
	              -ArgumentList "/configure `"$xmlPath`"" `
	              -WindowStyle Hidden `
	              -Wait `
	              -PassThru
		Log "ODT exit code: $($proc.ExitCode)"
	} catch {
		Log "Unable to remove Office products: $_"
	}
	}

} catch {
	Log "Unhandled exception: $_"
} finally {
	# Never leave the default user hive loaded, even if a step failed
	if ($hiveLoaded) {
		Log "Unloading Default user Registry"
		Dismount-DefaultUserHive
	}
	Log "All Steps Completed"
}

$stopUtc = [datetime]::UtcNow

# Calculate the total run time
$runTime = $stopUTC - $startUTC

# Format the runtime with hours, minutes, and seconds
if ($runTime.TotalHours -ge 1) {
	$runTimeFormatted = 'Duration: {0:hh} hr {0:mm} min {0:ss} sec' -f $runTime
}
else {
	$runTimeFormatted = 'Duration: {0:mm} min {0:ss} sec' -f $runTime
}

Log 'Autopilot Branding Complete'
Log "Total Script $($runTimeFormatted)"

$ProgressPreference = $OriginalProgressPreference 
Stop-Transcript

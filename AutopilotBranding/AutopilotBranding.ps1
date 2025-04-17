
function Log() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$false)] [String] $message
	)

	$ts = get-date -f "yyyy/MM/dd hh:mm:ss tt"
	Write-Output "$ts $message"
}

# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64")
{
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

# Create output folder
if (-not (Test-Path "$($env:ProgramData)\Microsoft\AutopilotBranding"))
{
    Mkdir "$($env:ProgramData)\Microsoft\AutopilotBranding" -Force
}

# Start logging
Start-Transcript "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.log"

# Creating tag file
Set-Content -Path "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"

# PREP: Load the Config.xml
$installFolder = "$PSScriptRoot\"
Log "Install folder: $installFolder"
Log "Loading configuration: $($installFolder)Config.xml"
[Xml]$config = Get-Content "$($installFolder)Config.xml"

# PREP: Load the default user registry
reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Host

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
		Log "Importing Start menu layout: $($installFolder)Start2.bin"
		MkDir -Path "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Force -ErrorAction SilentlyContinue | Out-Null
		Copy-Item "$($installFolder)Start2.bin" "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start2.bin" -Force
	} else {
		Log "Skipping Start layout (Windows 11)"
	}
	if ($config.Config.SkipTaskbarLayout -ine "true") {
		Log "Importing Taskbar layout: $($installFolder)TaskbarLayoutModification.xml"
		MkDir -Path "C:\Windows\OEM\" -Force -ErrorAction SilentlyContinue | Out-Null
		Copy-Item "$($installFolder)TaskbarLayoutModification.xml" "C:\Windows\OEM\TaskbarLayoutModification.xml" -Force
		reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v LayoutXMLPath /t REG_EXPAND_SZ /d "%SystemRoot%\OEM\TaskbarLayoutModification.xml" /f | Out-Host
		Log "Unpin the Microsoft Store app from the taskbar"
		reg.exe add "HKLM\TempUser\Software\Policies\Microsoft\Windows\Explorer" /v NoPinningStoreToTaskbar /t REG_DWORD /d 1 /f | Out-Host
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
	reg.exe add "HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v InstallTheme /t REG_EXPAND_SZ /d "%SystemRoot%\resources\OEM Themes\Autopilot.theme" /f | Out-Host
	reg.exe add "HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v CurrentTheme /t REG_EXPAND_SZ /d "%SystemRoot%\resources\OEM Themes\Autopilot.theme" /f | Out-Host
} else {
	Log "Skipping Autopilot theme"
}

# STEP 2A: Set lock screen image, see https://www.systemcenterdudes.com/apply-custom-lock-screen-wallpaper-using-intune/
if ($config.Config.SkipLockScreen -ine "true") {
	Log "Configuring lock screen image"
	$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
	$LockScreenImage = "C:\Windows\web\wallpaper\Autopilot\AutopilotLock.jpg"
	Copy-Item "$installFolder\AutopilotLock.jpg" $LockScreenImage -Force
	if (!(Test-Path -Path $RegPath)) {
		New-Item -Path $RegPath -Force | Out-Null
	}
	New-ItemProperty -Path $RegPath -Name LockScreenImagePath -Value $LockScreenImage -PropertyType String -Force | Out-Null
	New-ItemProperty -Path $RegPath -Name LockScreenImageUrl -Value $LockScreenImage -PropertyType String -Force | Out-Null
	New-ItemProperty -Path $RegPath -Name LockScreenImageStatus -Value 1 -PropertyType DWORD -Force | Out-Null

	# STEP 2B: Stop Start menu from opening on first logon
	reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StartShownOnUpgrade /t REG_DWORD /d 1 /f | Out-Host

	# STEP 2C: Hide "Learn more about this picture" from the desktop (so wallpaper will work)
	reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /t REG_DWORD /d 1 /f | Out-Host

	# STEP 2D: Disable Windows Spotlight as per https://github.com/mtniehaus/AutopilotBranding/issues/13#issuecomment-2449224828 (so wallpaper will work)
	Log "Disabling Windows Spotlight for Desktop"
	reg.exe add "HKLM\TempUser\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSpotlightCollectionOnDesktop /t REG_DWORD /d 1 /f | Out-Host

} else {
	Log "Skipping lock screen image"
}

# STEP 2E: Left Align Start Button in the default user profile, users can change it if they want
if ($config.Config.SkipLeftAlignStart -ine "true") {
	Log "Configuring left aligned Start menu"
	reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f | Out-Host
} else {
	Log "Skipping Left align start"
}

# STEP 2F: Hide the widgets button
if ($config.Config.SkipHideWidgets -ine "true") {
	Log "Hiding widget button"
	reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f | Out-Host
} else {
	Log "Skipping Hide widget button"
}

# STEP 3: Set time zone (if specified)
if ($config.Config.TimeZone) {
	Log "Setting time zone: $($config.Config.TimeZone)"
	Set-Timezone -Id $config.Config.TimeZone
}
else {
	# Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Allow" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
	Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
}

# STEP 4: Remove specified provisioned apps if they exist
Log "Removing specified in-box provisioned apps"
$apps = Get-AppxProvisionedPackage -online
$config.Config.RemoveApps.App | % {
	$current = $_
	$apps | ? {$_.DisplayName -eq $current} | % {
		try {
			Log "Removing provisioned app: $current"
			$_ | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
		} catch { }
	}
}

# STEP 5: Install OneDrive per machine
if ($config.Config.OneDriveSetup) {
	$dest = "$($env:TEMP)\OneDriveSetup.exe"
	$client = new-object System.Net.WebClient
	if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
		$url = $config.Config.OneDriveARMSetup
	} else {
		$url = $config.Config.OneDriveSetup
	}
	Log "Downloading OneDriveSetup: $url"
	$client.DownloadFile($url, $dest)
	Log "Installing: $dest"
	$proc = Start-Process $dest -ArgumentList "/allusers" -WindowStyle Hidden -PassThru
	$proc.WaitForExit()
	Log "OneDriveSetup exit code: $($proc.ExitCode)"

	$OneDriveSetup = Get-ItemProperty "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object -ExpandProperty "OneDriveSetup"
	if ($OneDriveSetup) {
		Log "Cleaning up user OneDriveSetup key"
		Remove-ItemProperty -Path "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" | Out-Null
		Log "Creating new OneDriveSetup key and pointing it to the machine wide EXE"
		New-ItemProperty -Path "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Value '"C:\Program Files\Microsoft OneDrive\Onedrive.exe" /background' -Force | Out-Null
	}
}

# STEP 6: Don't let Edge create a desktop shortcut (roams to OneDrive, creates mess)
Log "Turning off (old) Edge desktop shortcut"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v DisableEdgeDesktopShortcutCreation /t REG_DWORD /d 1 /f /reg:64 | Out-Host

# STEP 7: Add language packs
Get-ChildItem "$($installFolder)LPs" -Filter *.cab | % {
	Log "Adding language pack: $($_.FullName)"
	Add-WindowsPackage -Online -NoRestart -PackagePath $_.FullName
}

# STEP 8: Change language
if ($config.Config.Language) {
	Log "Configuring language using: $($config.Config.Language)"
	& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$($installFolder)$($config.Config.Language)`""
}

# STEP 9: Add features on demand, Disable Optional Features, Remove Windows Capabilities
$currentWU = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Ignore).UseWuServer
if ($currentWU -eq 1)
{
	Log "Turning off WSUS"
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 0
	Restart-Service wuauserv
}

# Step 9A: Disable Optional features
if ($config.Config.DisableOptionalFeatures.Feature.Count -gt 0)
{
	$EnabledOptionalFeatures = Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"}
	foreach ($EnabledFeature in $EnabledOptionalFeatures) {
		if ($config.Config.DisableOptionalFeatures.Feature -contains $EnabledFeature.FeatureName) {
			Log "Disabling Optional Feature:  $($EnabledFeature.FeatureName)"
			try {
				Disable-WindowsOptionalFeature -Online -FeatureName $EnabledFeature.FeatureName -NoRestart | Out-Null
			} catch {}
		}
	}
}

# Step 9B: Remove Windows Capabilities
if ($config.Config.RemoveCapability.Capability.Count -gt 0)
{
	$InstalledCapabilities = Get-WindowsCapability -Online | Where-Object {$_.State -eq "Installed"}
	foreach ($InstalledCapability in $InstalledCapabilities) {
		if ($config.Config.RemoveCapability.Capability -contains $InstalledCapability.Name.Split("~")[0]) {
			Log "Removing Windows Capability:  $($InstalledCapability.Name)"
			try {
				Remove-WindowsCapability -Online -Name $InstalledCapability.Name  | Out-Null
			} catch {}
		}
	}
}

# Step 9C: Add features on demand
if ($config.Config.AddFeatures.Feature.Count -gt 0)
{
	$config.Config.AddFeatures.Feature | % {
		Log "Adding Windows feature: $_"
		try {
			$result = Add-WindowsCapability -Online -Name $_
			if ($result.RestartNeeded) {
				Log "  Feature $_ was installed but requires a restart"
			}
		} catch {}
	}
}

if ($currentWU -eq 1)
{
	Log "Turning on WSUS"
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 1
	Restart-Service wuauserv
}

# STEP 10: Customize default apps
if ($config.Config.DefaultApps) {
	Log "Setting default apps: $($config.Config.DefaultApps)"
	& Dism.exe /Online /Import-DefaultAppAssociations:`"$($installFolder)$($config.Config.DefaultApps)`"
}

# STEP 11: Set registered user and organization
if ($config.Config.RegisteredOwner) {
	Log "Configuring registered user information"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d "$($config.Config.RegisteredOwner)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d "$($config.Config.RegisteredOrganization)" /f /reg:64 | Out-Host
}

# STEP 12: Configure OEM branding info
if ($config.Config.OEMInfo)
{
	Log "Configuring OEM branding info"

	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /t REG_SZ /d "$($config.Config.OEMInfo.Manufacturer)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /t REG_SZ /d "$($config.Config.OEMInfo.Model)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /t REG_SZ /d "$($config.Config.OEMInfo.SupportPhone)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /t REG_SZ /d "$($config.Config.OEMInfo.SupportHours)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /t REG_SZ /d "$($config.Config.OEMInfo.SupportURL)" /f /reg:64 | Out-Host
	Copy-Item "$installFolder\$($config.Config.OEMInfo.Logo)" "C:\Windows\$($config.Config.OEMInfo.Logo)" -Force
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "C:\Windows\$($config.Config.OEMInfo.Logo)" /f /reg:64 | Out-Host
}

# STEP 13: Enable UE-V
if ($config.Config.SkipUEV -ine "true") 
{
	Log "Enabling UE-V"
	Enable-UEV
	Set-UevConfiguration -Computer -SettingsStoragePath "%OneDriveCommercial%\UEV" -SyncMethod External -DisableWaitForSyncOnLogon
	Get-ChildItem "$($installFolder)UEV" -Filter *.xml | % {
		Log "Registering template: $($_.FullName)"
		Register-UevTemplate -Path $_.FullName
	}
} else {
	Log "Skipping UE-V"
}

# STEP 14: Disable network location fly-out
Log "Turning off network location fly-out"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f

# STEP 15: Disable new Edge desktop icon
Log "Turning off Edge desktop icon"
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d 0 /f /reg:64 | Out-Host

# STEP 16: Remove the registry keys for Dev Home and Outlook New
# This is a workaround for the issue where the Dev Home and Outlook New apps are installed by default
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

# STEP 17: WinGet installs
if ($config.Config.SkipWinGet -ine "true") {
	$winget = (Get-ChildItem -Path "C:\Program Files\WindowsApps" -Recurse -Filter "winget.exe").FullName
	$config.Config.WinGetInstall.Id | % {
		Log "Installing $_"
		try {
			& $winget install "$_" --accept-package-agreements --accept-source-agreements --scope machine
		} catch {}
	}
}

# STEP 18: Try to get Windows to update stuff
if ($config.Config.SkipLeftAlignStart -ine "true") {
	try {
		Log "Updating in-box apps"
		Install-Script Update-InboxApp
		Get-AppxPackage | Select-Object -Unique PackageFamilyName | Update-InboxApp.ps1

		Log "Kicking off a Windows Update scan"
		$Namespace = "Root\cimv2\mdm\dmmap"
		$ClassName = "MDM_EnterpriseModernAppManagement_AppManagement01"
		Get-CimInstance -Namespace $Namespace -ClassName $ClassName |
		Invoke-CimMethod -MethodName UpdateScanMethod
	} catch {}
} else {
	Log "Skipping updates"
}

# CLEANUP: Unload the default registry profile
[GC]::Collect()
reg.exe unload HKLM\TempUser | Out-Host

Write-Host "All done!"

Stop-Transcript
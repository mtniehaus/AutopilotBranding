# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64")
{
    if (Test-Path "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        & "$env:SystemRoot\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

# Create a tag file just so Intune knows this was installed
if (-not (Test-Path "$env:ProgramData\Microsoft\AutopilotBranding"))
{
    Mkdir "$env:ProgramData\Microsoft\AutopilotBranding"
}
Set-Content -Path "$env:ProgramData\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"

# Start logging
Start-Transcript "$env:ProgramData\Microsoft\AutopilotBranding\AutopilotBranding.log"

# PREP: Load the Config.xml
Write-Host "Install folder: $PSScriptRoot"
Write-Host "Loading configuration: $PSScriptRoot\Config.xml"
[Xml]$config = Get-Content "$PSScriptRoot\Config.xml"

#Load the default user registry hive
reg.exe load HKLM\TempUser "$env:SystemDrive\Users\Default\NTUSER.DAT" | Out-Host

# STEP 1: Apply custom start menu layout
if ($config.Config.StartMenuLayout) {
	Write-Host "Importing layout: $PSScriptRoot\$($config.Config.StartMenuLayout)"
	Copy-Item "$PSScriptRoot\$($config.Config.StartMenuLayout)" "$env:SystemDrive\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Force
}

# STEP 2: Configure background (if specified)
if ($config.Config.Theme) {
	Write-Host "Setting up Autopilot theme"
	Mkdir "$env:SystemRoot\Resources\OEM Themes" -Force | Out-Null
	Copy-Item "$PSScriptRoot\$($config.Config.Theme)" "$env:SystemRoot\Resources\OEM Themes\$($config.Config.Theme)" -Force
	Mkdir "$env:SystemRoot\web\wallpaper\Autopilot" -Force | Out-Null
	Copy-Item "$PSScriptRoot\Background.jpg" "$env:SystemRoot\web\wallpaper\Autopilot\Background.jpg" -Force
	Write-Host "Setting Autopilot theme as the new user default"
	reg.exe add "HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v InstallTheme /t REG_EXPAND_SZ /d "%SystemRoot%\resources\OEM Themes\$($config.Config.Theme)" /f | Out-Host
}

# STEP 3: Set time zone (if specified)
if ($config.Config.TimeZone) {
	if($config.Config.TimeZone -eq 'Automatic') {
		# Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Allow" -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
		Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
	} else {
		Write-Host "Setting time zone: $($config.Config.TimeZone)"
		Set-Timezone -Id $config.Config.TimeZone
	}
}

# STEP 4: Remove specified provisioned apps if they exist
if($config.Config.RemoveApps.App) {
	Write-Host "Removing specified in-box provisioned apps"
	$apps = Get-AppxProvisionedPackage -Online
	$config.Config.RemoveApps.App | ForEach-Object {
		$current = $_
		$apps | Where-Object DisplayName -eq $current | ForEach-Object {
			Write-Host "Removing provisioned app: $current"
			$_ | Remove-AppxProvisionedPackage -Online | Out-Null
		}
	}
}

# STEP 5: Install OneDrive per machine
if ($config.Config.OneDriveSetup) {
	Write-Host "Downloading OneDriveSetup"
	$destination = "$env:TEMP\OneDriveSetup.exe"
	$client = new-object System.Net.WebClient
	$client.DownloadFile($config.Config.OneDriveSetup, $destination)
	Write-Host "Installing: $dest"
	$process = Start-Process -FilePath $destination -ArgumentList "/allusers" -WindowStyle Hidden -PassThru
	$process.WaitForExit()
	Write-Host "OneDriveSetup exit code: $($process.ExitCode)"
}

# STEP 6: Don't let Edge create a desktop shortcut (roams to OneDrive, creates mess)
if($config.Config.DisableEdgeDesktopShortcutCreation -eq 1) {
	Write-Host "Turning off (old) Edge desktop shortcut"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v DisableEdgeDesktopShortcutCreation /t REG_DWORD /d 1 /f /reg:64 | Out-Host
	Write-Host "Turning off (new) Edge desktop icon"
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d 0 /f /reg:64 | Out-Host
}

# STEP 7: Add language packs
Get-ChildItem "$PSScriptRoot\LPs" -Filter *.cab | ForEach-Object {
	Write-Host "Adding language pack: $($_.FullName)"
	Add-WindowsPackage -Online -NoRestart -PackagePath $_.FullName
}

# STEP 8: Change language
if ($config.Config.Language) {
	Write-Host "Configuring language using: $($config.Config.Language)"
	& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$PSScriptRoot\$($config.Config.Language)`""
}

# STEP 9: Add features on demand
if($config.Config.AddFeatures.Feature){
	$currentWU = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Ignore).UseWuServer
	if ($currentWU -eq 1)
	{
		Write-Host "Turning off WSUS"
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 0
		Restart-Service wuauserv
	}
	$config.Config.AddFeatures.Feature | ForEach-Object {
		Write-Host "Adding Windows feature: $_"
		Add-WindowsCapability -Online -Name $_
	}
	if ($currentWU -eq 1)
	{
		Write-Host "Turning on WSUS"
		Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 1
		Restart-Service wuauserv
	}
}

# STEP 10: Customize default apps
if ($config.Config.DefaultApps) {
	Write-Host "Setting default apps: $($config.Config.DefaultApps)"
	& Dism.exe /Online /Import-DefaultAppAssociations:`"$PSScriptRoot\$($config.Config.DefaultApps)`"
}

# STEP 11: Set registered user and organization
Write-Host "Configuring registered user information"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d "$($config.Config.RegisteredOwner)" /f /reg:64 | Out-Host
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d "$($config.Config.RegisteredOrganization)" /f /reg:64 | Out-Host

# STEP 12: Configure OEM branding info
if ($config.Config.OEMInfo)
{
	Write-Host "Configuring OEM branding info"

	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /t REG_SZ /d "$($config.Config.OEMInfo.Manufacturer)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /t REG_SZ /d "$($config.Config.OEMInfo.Model)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /t REG_SZ /d "$($config.Config.OEMInfo.SupportPhone)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /t REG_SZ /d "$($config.Config.OEMInfo.SupportHours)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /t REG_SZ /d "$($config.Config.OEMInfo.SupportURL)" /f /reg:64 | Out-Host
	Copy-Item "$PSScriptRoot\$($config.Config.OEMInfo.Logo)" "C:\Windows\$($config.Config.OEMInfo.Logo)" -Force
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "C:\Windows\$($config.Config.OEMInfo.Logo)" /f /reg:64 | Out-Host
}

# STEP 13: Enable UE-V
if($config.Config.EnableUEV -eq 1) {
	Write-Host "Enabling UE-V"
	Enable-UEV
	Set-UevConfiguration -Computer -SettingsStoragePath "%OneDriveCommercial%\UEV" -SyncMethod External -DisableWaitForSyncOnLogon
	Get-ChildItem "$PSScriptRoot\UEV" -Filter *.xml | ForEach-Object {
		Write-Host "Registering template: $($_.FullName)"
		Register-UevTemplate -Path $_.FullName
	}
}

# STEP 14: Disable network location fly-out
if($config.Config.NewNetworkWindowOff -eq 1) {
	Write-Host "Turning off network location fly-out"
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f
}

# STEP 15: Set SearchboxTaskbarMode
# 0: Hidden
# 1: Show Search Icon
# 2: Show Search Box
if($config.Config.SearchboxTaskbarMode){
	$path = "HKLM:\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
	Set-ItemProperty -Path $path -Name "SearchboxTaskbarMode" -Type "DWord" -Value $config.Config.SearchboxTaskbarMode -Force
}

# STEP 16: ShowCortanaButton
if($config.Config.ShowCortanaButton){
	$path = "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	Set-ItemProperty -Path $path -Name "ShowCortanaButton" -Type "DWord" -Value $config.Config.ShowCortanaButton -Force
}

# STEP 17: ShowTaskViewButton
if($config.Config.ShowTaskViewButton){
	reg.exe load HKLM\TempUser "$env:SystemDrive\Users\Default\NTUSER.DAT" | Out-Host
	$path = "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
	Set-ItemProperty -Path $path -Name "ShowTaskViewButton" -Type "DWord" -Value $config.Config.ShowTaskViewButton -Force
}

# STEP 18: Delete 3D Objects link from File Explorer
if($config.Config.Delete3DObjectsLink -eq 1) {
	Write-Host "Deleting 3D Objects link from File Explorer"
	$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
	If(Test-Path -Path $path) {Remove-Item -Path $path}
	$path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
	If(Test-Path -Path $path) {Remove-Item -Path $path}
}

#Unload the default user registry hive
reg.exe unload HKLM\TempUser | Out-Host

Stop-Transcript

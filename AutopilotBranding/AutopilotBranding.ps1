<#PSScriptInfo
.VERSION        3.0.2
.GUID           39efc9c5-7b51-4d1f-b650-0f3818e5327a
.AUTHOR         Michael Niehaus
.COMPANYNAME
.COPYRIGHT      Copyright (c) 2025 Michael Niehaus
.TAGS           intune endpoint autopilot branding windows
.LICENSEURI     https://github.com/mtniehaus/AutopilotBranding/blob/main/LICENSE
.PROJECTURI     https://github.com/mtniehaus/AutopilotBranding
.RELEASENOTES
  v3.0.2 - 2025-04-19 - Added Check-NuGetProvider and refactored STEPS 18 & 20
#>

function Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)][string]$message
    )
    $ts = Get-Date -Format 'yyyy/MM/dd hh:mm:ss tt'
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
        }
    Elseif ($provider.Version -lt $MinimumVersion) {
        Log "NuGet provider v$($provider.Version) is less than required v$MinimumVersion; updating."
        Install-PackageProvider -Name NuGet -Force | Out-Null
        
    }
	else{
	Log "NuGet provider meets min requirements (v:$($provider.Version))."
    }
    
}

#Get the Current start time in UTC format, so that Time Zone Changes don't affect total runtime calculation
$startUtc = [datetime]::UtcNow

# Relaunch as 64-bit if running under Wow64
if ($env:PROCESSOR_ARCHITEW6432) {
    $sysnative = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    if (Test-Path $sysnative) {
        & $sysnative -ExecutionPolicy Bypass -NoProfile -File $PSCommandPath
        Exit $LastExitCode
    }
}

# Prepare logging location
$logPath = "$env:ProgramData\Microsoft\AutopilotBranding"
if (-not (Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}
Start-Transcript "$logPath\AutopilotBranding.log"
Set-Content -Path "$logPath\AutopilotBranding.ps1.tag" -Value 'Installed'

# Load configuration and default registry
$installFolder = "$PSScriptRoot\"
Log "Install folder: $installFolder"
Log "Loading configuration: ${installFolder}Config.xml"
[xml]$config = Get-Content "${installFolder}Config.xml"
reg.exe load HKLM\TempUser 'C:\Users\Default\NTUSER.DAT' | Out-Null

$ProgressPreference = 'SilentlyContinue'

# STEP 1: Start & Taskbar layout
$ci = Get-ComputerInfo
if ($ci.OsBuildNumber -le 22000) {
    if ($config.Config.SkipStartLayout -ne 'true') {
        Log 'Applying Windows 10 Start layout'
        Copy-Item "${installFolder}Layout.xml" `
            'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml' -Force
    } else { Log 'Skipping Start layout (Win10)' }
} else {
    if ($config.Config.SkipStartLayout -ne 'true') {
        Log 'Applying Windows 11 Start layout'
        New-Item -Path 'C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState' -ItemType Directory -Force | Out-Null
        Copy-Item "${installFolder}Start2.bin" `
            'C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start2.bin' -Force
    } else { Log 'Skipping Start layout (Win11)' }
    if ($config.Config.SkipTaskbarLayout -ne 'true') {
        Log 'Applying Taskbar layout'
        New-Item -Path 'C:\Windows\OEM' -ItemType Directory -Force | Out-Null
        Copy-Item "${installFolder}TaskbarLayoutModification.xml" 'C:\Windows\OEM\TaskbarLayoutModification.xml' -Force
        reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer /v LayoutXMLPath /t REG_EXPAND_SZ /d '%SystemRoot%\OEM\TaskbarLayoutModification.xml' /f /reg:64 | Out-Null
        reg.exe add HKLM\TempUser\Software\Policies\Microsoft\Windows\Explorer /v NoPinningStoreToTaskbar /t REG_DWORD /d 1 /f /reg:64 | Out-Null
    } else { Log 'Skipping Taskbar layout (Win11)' }
}

# STEP 2: Theme & Spotlight
if ($config.Config.SkipTheme -ne 'true') {
    Log 'Configuring OEM theme'
    New-Item -Path 'C:\Windows\Resources\OEM Themes' -ItemType Directory -Force | Out-Null
    Copy-Item "${installFolder}Autopilot.theme" 'C:\Windows\Resources\OEM Themes\Autopilot.theme' -Force
    New-Item -Path 'C:\Windows\web\wallpaper\Autopilot' -ItemType Directory -Force | Out-Null
    Copy-Item "${installFolder}Autopilot.jpg" 'C:\Windows\web\wallpaper\Autopilot\Autopilot.jpg' -Force
    reg.exe add HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes /v InstallTheme /t REG_EXPAND_SZ /d '%SystemRoot%\resources\OEM Themes\Autopilot.theme' /f /reg:64 | Out-Null
    reg.exe add HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes /v CurrentTheme /t REG_EXPAND_SZ /d '%SystemRoot%\resources\OEM Themes\Autopilot.theme' /f /reg:64 | Out-Null
} else { Log 'Skipping OEM theme' }
if ($config.Config.SkipLockScreen -ne 'true') {
    Log 'Configuring lock screen'
    $csp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'
    New-Item -Path $csp -Force | Out-Null
    $img = 'C:\Windows\web\wallpaper\Autopilot\AutopilotLock.jpg'
    Copy-Item "${installFolder}AutopilotLock.jpg" $img -Force
    New-ItemProperty -Path $csp -Name LockScreenImagePath -Value $img -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $csp -Name LockScreenImageStatus -Value 1 -PropertyType DWord -Force | Out-Null
    reg.exe add HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v StartShownOnUpgrade /t REG_DWORD /d 1 /f /reg:64 | Out-Null
    reg.exe add HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel /v '{2cc5ca98-6485-489a-920e-b3e88a6ccce3}' /t REG_DWORD /d 1 /f /reg:64 | Out-Null
    Log 'Disabling Spotlight'
    reg.exe add HKLM\TempUser\Software\Policies\Microsoft\Windows\CloudContent /v DisableSpotlightCollectionOnDesktop /t REG_DWORD /d 1 /f /reg:64 | Out-Null
} else { Log 'Skipping lock screen' }

# STEP 3: Left-align Start
if ($config.Config.SkipLeftAlignStart -ne 'true') {
    reg.exe add HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v TaskbarAl /t REG_DWORD /d 0 /f /reg:64 | Out-Null
    Log 'Left-align Start enabled'
} else { Log 'Skipping left-align Start' }

# STEP 4: Widgets
if ($config.Config.SkipHideWidgets -ne 'true') {
    reg.exe add HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v TaskbarDa /t REG_DWORD /d 0 /f /reg:64 | Out-Null
    New-Item -Path 'HKLM:\Software\Policies\Microsoft\Dsh' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Dsh' -Name DisableWidgetsOnLockScreen -Value 1
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Dsh' -Name DisableWidgetsBoard -Value 1
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Dsh' -Name AllowNewsAndInterests -Value 0
    Log 'Widgets hidden'
} else { Log 'Skipping widget hide' }

# STEP 5: Time zone
if ($config.Config.TimeZone) {
    Set-TimeZone -Id $config.Config.TimeZone
    Log "Time zone set to $($config.Config.TimeZone)"
	} else {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name Value -Value Allow -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name SensorPermissionState -Value 1 -Force
    Start-Service lfsvc -ErrorAction SilentlyContinue
    Log 'Auto time zone via location enabled'
}

# STEP 6: Remove provisioned apps
Log 'Removing provisioned apps'
Get-AppxProvisionedPackage -Online | ForEach-Object {
    if ($config.Config.RemoveApps.App -contains $_.DisplayName) {
        Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue | Out-Null
        Log "Removed provisioned: $($_.DisplayName)"
    }
}

# STEP 7: Install OneDrive
if ($config.Config.OneDriveSetup) {
    $dest = "$env:TEMP\OneDriveSetup.exe"
    $url = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $config.Config.OneDriveARMSetup } else { $config.Config.OneDriveSetup }
	$OriginalVerbosePreference = $VerbosePreference
    $VerbosePreference = 'SilentlyContinue'
	Log 'Downloading lastet OneDrive.exe'
    Invoke-WebRequest $url -OutFile $dest -UseBasicParsing
	Log 'Installing OneDrive Machine wide'
    Start-Process $dest -ArgumentList '/allusers /silent' -WindowStyle Hidden -Wait
	$VerbosePreference = $OriginalVerbosePreference
    reg.exe --% add HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Run /v OneDriveSetup /t REG_SZ /d "C:\Program Files\Microsoft OneDrive\OneDrive.exe /background" /f /reg:64 | Out-Null
    Log 'OneDrive installed'
}

# STEP 8: Disable Edge shortcuts
reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer /v DisableEdgeDesktopShortcutCreation /t REG_DWORD /d 1 /f /reg:64 | Out-Null
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate /v CreateDesktopShortcutDefault /t REG_DWORD /d 0 /f /reg:64 | Out-Null
Log 'Edge shortcuts disabled'

# STEP 9: Language packs
Get-ChildItem "${installFolder}LPs\*.cab" | ForEach-Object {
    Add-WindowsPackage -Online -PackagePath $_.FullName -NoRestart
    Log "Language pack added: $($_.Name)"
}

# STEP 10: Configure user language
if ($config.Config.Language) {
    & control.exe "intl.cpl,,/f:`"${installFolder}${config.Config.Language}`""
    Log 'User language configured'
}

# STEP 11: WSUS toggle
$currentWU = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
if ($currentWU -eq 1) {
    Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name UseWUServer -Value 0
    Restart-Service wuauserv
}

# STEP 11A: Disable optional features
if ($config.Config.DisableOptionalFeatures.Feature.Count -gt 0) {
    Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' | ForEach-Object {
        if ($config.Config.DisableOptionalFeatures.Feature -contains $_.FeatureName) {
            Disable-WindowsOptionalFeature -Online -FeatureName $_.FeatureName -NoRestart | Out-Null
            Log "Disabled feature: $($_.FeatureName)"
        }
    }
}

# STEP 11B: Remove capabilities
if ($config.Config.RemoveCapability.Capability.Count -gt 0) {
    Get-WindowsCapability -Online | Where-Object State -eq 'Installed' | ForEach-Object {
        $capName = $_.Name.Split('~')[0]
        if ($config.Config.RemoveCapability.Capability -contains $capName) {
            Remove-WindowsCapability -Online -Name $_.Name | Out-Null
            Log "Removed capability: $($_.Name)"
        }
    }
}

# STEP 11C: Add features on demand
if ($config.Config.AddFeatures.Feature.Count -gt 0) {
    $config.Config.AddFeatures.Feature | ForEach-Object {
        Log "Adding Windows feature: $_"
        $result = Add-WindowsCapability -Online -Name $_
        if ($result.RestartNeeded) {
            Log "Feature $_ installed but requires a restart"
        }
    }
}

# STEP 12: Default app associations
if ($config.Config.DefaultApps) {
    Log 'Importing default app associations'
    Dism.exe /Online /Import-DefaultAppAssociations:"${installFolder}${config.Config.DefaultApps}"
}

# STEP 13: Registered user/org
if ($config.Config.RegisteredOwner) {
    Log 'Configuring registered user info'
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d "$($config.Config.RegisteredOwner)" /f | Out-Null
    reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d "$($config.Config.RegisteredOrganization)" /f | Out-Null
}

# STEP 14: OEM info
if ($config.Config.OEMInfo) {
    Log 'Configuring OEM branding'
    $info = $config.Config.OEMInfo
    reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation /v Manufacturer /t REG_SZ /d "$($info.Manufacturer)" /f | Out-Null
    reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation /v Model /t REG_SZ /d "$($info.Model)" /f | Out-Null
    reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation /v SupportPhone /t REG_SZ /d "$($info.SupportPhone)" /f | Out-Null
    reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation /v SupportHours /t REG_SZ /d "$($info.SupportHours)" /f | Out-Null
    reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation /v SupportURL /t REG_SZ /d "$($info.SupportURL)" /f | Out-Null
    Copy-Item "${installFolder}$($info.Logo)" "C:\Windows\$($info.Logo)" -Force
    reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation /v Logo /t REG_SZ /d "C:\Windows\$($info.Logo)" /f | Out-Null
}

# STEP 15: Enable UE-V
if ($config.Config.SkipUEV -ne 'true') {
    Log 'Enabling UE-V'
    Enable-UEV
    Set-UevConfiguration -Computer -SettingsStoragePath '%OneDriveCommercial%\UEV' -SyncMethod External -DisableWaitForSyncOnLogon
    Get-ChildItem "${installFolder}UEV\*.xml" | ForEach-Object {
        Log "Registering UE-V template: $($_.Name)"
        Register-UevTemplate -Path $_.FullName
    }
} else {
    Log 'Skipping UE-V'
}

# STEP 16: Disable network location fly-out
Log 'Turning off network location fly-out'
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff /f | Out-Null

# STEP 17: Disable Dev Home & Outlook New auto-install
if ($config.Config.SkipAutoinstallingApps -ne 'true') {
    Log 'Removing Dev Home & Outlook New keys'
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate',
        'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            Remove-Item $k -Force
            Log "Removed registry key $k"
        }
    }
} else { Log 'Skipping auto-install app logic' }

# STEP 18: WinGet installs
if ($config.Config.SkipWinGet -ne 'true') {
    # Ensure NuGet provider before installing modules
    Check-NuGetProvider 

    Log 'Installing WinGet.Client module'
    Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null
	Log 'Installing Lastest Winget package and dependencies'
    Repair-WinGetPackageManager -AllUsers -Force -Latest | Out-Null

    # $wingetExe = (Get-ChildItem -Path 'C:\Program Files\WindowsApps' -Recurse -Filter 'winget.exe' -ErrorAction SilentlyContinue).FullName
    foreach ($id in $config.Config.WinGetInstall.Id) {
        Log "WinGet installing: $id"
        & winget.exe install $id --silent --disable-interactivity --scope machine --accept-package-agreements --accept-source-agreements
    }
	
} else {
    Log 'Skipping WinGet installs'
}

# STEP 19: Disable extra APv2 pages
if ($config.Config.SkipAPv2 -ne 'true') {
    $reg = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE'
    New-ItemProperty -Path $reg -Name DisablePrivacyExperience -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $reg -Name DisableVoice -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $reg -Name PrivacyConsentStatus -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $reg -Name ProtectYourPC -PropertyType DWord -Value 3 -Force | Out-Null
    Log 'APv2 extra pages disabled'
} else {
    Log 'Skipping APv2 tweaks'
}

# STEP 20: Updates & Inbox-App script
if ($config.Config.SkipUpdates -ne 'true') {
    try {

		#Nuget v 2.8.5.201 is required to import mtniehaus's PS Gallery Script Update-InboxApp
        $minrequired = [version]'2.8.5.201'
		Check-NuGetProvider -MinimumVersion $required
		<#
        if (Check-NuGetProvider -MinimumVersion $required) {
            Log "NuGet has been installed to meet v$required"
        }
        else {
            Log "NuGet already at v$required"
        }
		#>

        Log 'Installing Update-InboxApp script'
        Install-Script Update-InboxApp -Force | Out-Null

        Log 'Updating inbox apps'
        Get-AppxPackage | Select-Object -Unique PackageFamilyName | Update-InboxApp.ps1

        Log 'Triggering Windows Update scan'
        $ns = 'Root\cimv2\mdm\dmmap'
        $class = 'MDM_EnterpriseModernAppManagement_AppManagement01'
        Get-CimInstance -Namespace $ns -ClassName $class | Invoke-CimMethod -MethodName UpdateScanMethod
    }
    catch {
        Log "Error in STEP 20: $_"
    }
} else {
    Log 'Skipping updates'
}

# CLEANUP: Unload default user registry
[GC]::Collect()
reg.exe unload HKLM\TempUser | Out-Null

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

Log 'Autopilot Branding Finsihed'
Log "Total $($runTimeFormatted)"
$ProgressPreference = 'Continue'
Stop-Transcript

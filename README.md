# Autopilot Branding

This repository contains a sample PowerShell script that can be packaged into an Intune Win32 app to customize Windows 10 devices via Windows Autopilot
(although there's no reason it can't be used with other deployment processes, e.g. MDT or ConfigMgr).

## Capabilities

These customizations are currently supported:

- Customize start menu layout.  By default it will apply a simple two-icon layout (similiar to the default one on Windows 10 Enterprise 1903).
- Configure background image.  A custom theme is deployed with a background image; the default user profile is then configured to use this theme.  (Note that this won't work if the user is enabled for Enterprise State Roaming and has previously configured a background image.)
- Set time zone.  The time zone will be set to the specified time zone name (Pacific Standard Time by default).
- Remove in-box provisioned apps.  A list of in-box provisioned apps will be removed.
- Install updated OneDrive client per-machine.  To support the latest OneDrive features, the client will be updated and installed per-machine (instead of the per-user default).
- Disable the Edge desktop icon.  When using OneDrive Known Folder Move, this can cause duplicate (and unnecessary) shortcuts to be synced.
- Install language packs.  You can embed language pack CAB files into the MSI (place them into the LPs folder), and each will be automatically installed.  (In a perfect world, these would be pulled from Windows Update, but there's no simple way to do that, hence the need to include these in the MSI.  You can download the language pack ISO from MSDN or VLSC.)
- Install features on demand (FOD).  Specify a list of features that you want to install, from the list at https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod.  The needed components will be downloaded from Windows Update automatically and added to the running OS.
- Remove features on demand (FOD). Specify a list of preinstalled Features on Demand to remove by their Capability Name, excluding the tilde characters and version number. Capability Names can be retrieved by running  `Get-WindowsCapability -Online` 
- Disable Optional Features. Specify a list of optional features to disable by per their Feature Name. Feature Names can be retrieved by running  `Get-WindowsOptionalFeature -Online`
- Configure language settings.  Adding a language pack isn't enough - you have to tell Windows that you want it to be configured for all users.  This is done through an XML file fed to INTL.CPL; customize the file as needed.  (Note this is commented out by default in the Config.xml file.)
- Configure default apps.  Import a list of file associations (as created by manually configuring the associations that you want and then using "DISM /Online /Export-DefaultAppAssociations:C:\Associations.xml" to export those settings) that should replace the default app associations.  (Note that even though an example is included from a customized Windows 10 1903 image, making IE 11 the default browser, you should replace this file with your own exported version.  Also, do not edit the file that you exported, e.g. to remove entries that you didn't change.)

## Requirements and Dependencies

This uses the Microsoft Win32 Content Prep Tool (a.k.a. IntuneWinAppUtil.exe, available from https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool) to package the PowerShell script and related files into a .intunewin file that can be uploaded to Intune as a Win32 app. 

## Building

Run the makeapp.cmd file from a command prompt.  (It will not work if you using Terminal.)

## Using

Add the resulting Win32 app (.intunewin) to Intune.  The installation command line should be:

powershell.exe -noprofile -executionpolicy bypass -file .\AutopilotBranding.ps1

The uninstall command line should be:

cmd.exe /c del %ProgramData%\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag

The detection rule should look for the existence of this file:

Path: %ProgramData%\Microsoft\AutopilotBranding
File or filder:  AutopilotBranding.ps1.tag

See https://oofhours.com/2020/05/18/two-for-one-updated-autopilot-branding-and-update-os-scripts/ for more information.

## Change history

- 2023-09-23: Added logic to handle the Windows 11 Start menu proces using Start2.bin; Windows 10 will continue to use Layout.xml.  Added additional Windows 11 in-box apps to remove.
- 2024-01-31: Added additional apps to remove, adding timestamps to log messages, cleaned up error logging.
- 2024-04-27: Added logic to stop the Start menu from popping up each time a new user signs in.
- 2024-12-26: Added support for removing FODs and disabling optional features.

## Suggestions?

If you have suggestions on other customizations that would be useful, contact me at michael@oofhours.com.

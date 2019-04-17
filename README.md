# Autopilot Branding

This repository contains a sample Windows Installer (MSI) definition that can be used to customize Windows 10 devices via Windows Autopilot
(although there's no reason it can't be used with other deployment processes, e.g. MDT or ConfigMgr).

## Capabilities

These customizations are currently supported:

- Customize start menu layout.  By default it will apply a simple two-icon layout (similiar to the default one on Windows 10 1903, but without the Office app).
- Configure background image.  A custom theme is deployed with a background image; the default user profile is then configured to use this theme.  (Note that this won't work if the user is enabled for Enterprise State Roaming and has previously configured a background image.)
- Set time zone.  The time zone will be set to the specified time zone name (Pacific Standard Time by default).
- Remove in-box provisioned apps.  A list of in-box provisioned apps will be removed.
- Install updated OneDrive client per-machine.  To support the latest OneDrive features, the client will be updated and installed per-machine (instead of the per-user default).
- Disable the Edge desktop icon.  When using OneDrive Known Folder Move, this can cause duplicate (and unnecessary) shortcuts to be synced.
- Install language packs.  You can embed language pack CAB files into the MSI (place them into the LPs folder), and each will be automatically installed.  (In a perfect world, these would be pulled from Windows Update, but there's no simple way to do that, hence the need to include these in the MSI.  You can download the language pack ISO from MSDN or VLSC.)
- Install features on demand (FOD).  Specify a list of features that you want to install, from the list at https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod.  The needed components will be downloaded from Windows Update automatically and added to the running OS.
- Configure language settings.  Adding a language pack isn't enough - you have to tell Windows that you want it to be configured for all users.  This is done through an XML file fed to INTL.CPL; customize the file as needed.  (Note this is commented out by default in the Config.xml file.)

## Requirements and Dependencies

This uses the Wix Toolkit 3.x, available for download from http://wixtoolset.org/releases/, to build the MSI.  This must be downloaded and installed separately.

This also uses the PowerShell Wix extension, https://github.com/flcdrg/PowerShellWixExtension.  The necessary components are included in this repository.  (Note that these components are 32-bit only, hence the PowerShell script included in the MSI will run as 32-bit as well.)

## Building

To build the MSI, make any changes that you want (e.g. changing the list of apps to be removed), set the MSI version in the Product.wxs file, and then build it using the "Make.cmd" file.

## Using

Add the resulting MSI to Intune, or your deployment tool of choice.  It should be installed per-machine, elevated, before users sign in.  With Windows Autopilot, the Enrollment Status Page should be used (with Windows 10 1803 or higher) so that the machine-targeted MSI installs before any user signs in.

In the initial version, the "packages" folder wasn't included in the repository, so you could have gotten an error when trying to build the MSI.  Now it's been added to fix that issue.

## Suggestions?

If you have suggestions on other customizations that would be useful, contact me at mniehaus@microsoft.com.

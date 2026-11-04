# Autopilot Branding

This repository contains a PowerShell module, and a set of tools around it, that you can package into an Intune
Win32 app to customize Windows devices during Windows Autopilot. (There's no reason it can't be used with other
deployment processes too, e.g. MDT or ConfigMgr.)

Starting with v4, the old single `AutopilotBranding.ps1` script and its `Config.xml` file have been replaced by:

- **The `AutopilotBranding` module** (`Module\AutopilotBranding`). Each configuration task is a cmdlet in its own
  `.ps1` file, and its settings are passed as parameters instead of being read from a configuration file.
- **A builder UI** (the `Show-AutopilotBrandingBuilder` cmdlet, started by `ShowBuilder.cmd`). It lists every
  task with the parameters it supports. You pick the tasks to run and set the parameter values, then save your
  choices to a JSON file. It also generates the output folder and packages it as an Intune Win32 app (`.intunewin`).
- **A headless builder** (the `Build-AutopilotBranding` cmdlet, run by `makeapp.cmd`). It does the same from a JSON
  file without the UI, which is useful for CI.

Both cmdlets are part of the module, and everything works with Windows PowerShell 5.1 and PowerShell 7 (the tests
run with 5.1 and 7.6).

## Repository layout

```
AutopilotBranding.json            Default configuration (equivalent to the v3 Config.xml defaults)
ShowBuilder.cmd                   Loads the module and runs Show-AutopilotBrandingBuilder (the builder UI)
makeapp.cmd                       Loads the module and runs Build-AutopilotBranding on AutopilotBranding.json
Assets\                           Sample files used by the default configuration (theme, wallpaper, layouts, ...)
Tests\Test-AutopilotBranding.ps1  Automated tests (run with each PowerShell version)
Module\AutopilotBranding\
    AutopilotBranding.psd1/.psm1  Module manifest and loader
    Public\Show-AutopilotBrandingBuilder.ps1, Build-AutopilotBranding.ps1
                                  The builder UI and headless builder cmdlets
    Public\Builder.ps1            Builder functions (task discovery, JSON handling, output generation, packaging)
    Public\Session.ps1            Run framework (Start-/Stop-AutopilotBranding, Invoke-ABTask, Write-ABLog, ...)
    Private\Common.ps1            Shared task helpers (default user hive, registry, downloads, OOBE check, ...)
    Private\BuilderUI.ps1         The builder window (WPF)
    Private\BuilderHelpers.ps1    Internal builder helpers
    Tasks\<order>-<Cmdlet>.ps1    One configuration task (cmdlet) per file
```

`ShowBuilder.cmd` and `makeapp.cmd` use PowerShell 7 (`pwsh.exe`) if it is installed, otherwise Windows PowerShell
5.1. Set the `AB_POWERSHELL` environment variable to the PowerShell executable to use a specific one.

## Configuration tasks

The tasks run in the order shown here, which comes from the numeric prefix of each task file.

| Cmdlet | What it does | Parameters |
| --- | --- | --- |
| `Rename-ABComputer` | Renames the computer; `%SERIAL%` is replaced with the BIOS serial number (max. 15 characters). Don't use with hybrid Entra join. | NewName |
| `Set-ABStartLayout` | Custom Start menu layout: `Layout.xml` on Windows 10, `start2.bin` + `settings.dat` on Windows 11. | LayoutXmlPath, Start2BinPath, SettingsDatPath |
| `Set-ABTaskbarLayout` | Custom Windows 11 taskbar layout; optionally unpins the Store. | TaskbarLayoutPath, UnpinStore |
| `Set-ABTheme` | Installs a theme and wallpaper and makes it the default for new users. | ThemePath, WallpaperPath, UpdateThemeWallpaper |
| `Set-ABLockScreen` | Lock screen image. | ImagePath |
| `Disable-ABStartOnFirstLogon` | Stops Start from opening the first time a new user signs in. | |
| `Disable-ABDesktopSpotlight` | Hides "Learn about this picture" and disables desktop Spotlight so the wallpaper is used. | HideLearnAboutThisPicture, DisableSpotlightCollection |
| `Set-ABStartAlignment` | Default taskbar alignment (Left/Center). | Alignment |
| `Hide-ABWidgets` | Hides the Widgets button (with a workaround for the 24H2 UCPD driver). | |
| `Disable-ABWidgets` | Disables Widgets completely via policy. | DisableOnLockScreen |
| `Set-ABSearchBoxMode` | Taskbar search box mode (Hidden/IconOnly/SearchBox/IconAndLabel). | Mode |
| `Set-ABTimeZone` | Sets the time zone, or enables location services so that it is detected automatically. | TimeZone |
| `Remove-ABProvisionedApps` | Removes in-box provisioned apps, and the same apps if installed for all users. | AppNames, RemoveInstalledPackages |
| `Disable-ABCopilotPWA` | Prevents the Copilot PWA from being installed. | |
| `Install-ABOneDrive` | Installs the OneDrive client per-machine. | Url, ArmUrl |
| `Disable-ABEdgeDesktopShortcut` | Stops Edge from creating a desktop shortcut. | |
| `Update-ABEdge` | Installs the latest Stable Edge for Business MSI for the device's architecture, looked up from the edgeupdates API with its hash verified; `Url`/`ArmUrl` are fallbacks. | LookUpLatest, Url, ArmUrl |
| `Remove-ABEdgeBookmarks` | Removes OEM Edge bookmarks from the default profile. | |
| `Add-ABLanguagePacks` | Installs all language pack CABs in a folder. | LanguagePackFolder |
| `Set-ABLanguage` | Configures language settings for all users through an INTL.CPL XML file. | LanguageXmlPath |
| `Set-ABLanguageSettings` | Windows 11 alternative to `Set-ABLanguage`: installs a language from Windows Update and sets the display language, locale, culture and home location for new users. | Language, Locale, GeoId |
| `Disable-ABOptionalFeatures` | Disables optional features (`Get-WindowsOptionalFeature -Online`). | FeatureNames |
| `Remove-ABWindowsCapabilities` | Removes capabilities/FODs (`Get-WindowsCapability -Online`, without the tildes and version). | CapabilityNames |
| `Add-ABWindowsCapabilities` | Adds capabilities/FODs from Windows Update (temporarily bypassing WSUS). | CapabilityNames, BypassWsus |
| `Set-ABDefaultApps` | Imports default app associations exported with `DISM /Online /Export-DefaultAppAssociations`. | AssociationsXmlPath |
| `Set-ABRegisteredOwner` | Registered owner and organization. | Owner, Organization |
| `Set-ABOEMInfo` | OEM manufacturer/model/support info (and the logo on Windows 10). | Manufacturer, Model, UseDetectedHardware, SupportPhone, SupportHours, SupportURL, LogoPath |
| `Set-ABEnterpriseEdition` | Switches to Enterprise using a GVLK. | ProductKey |
| `Enable-ABUEV` | Enables UE-V and registers templates. | TemplateFolder, SettingsStorageLocation |
| `Disable-ABNetworkLocationFlyout` | Turns off the network location fly-out. | |
| `Disable-ABAutoInstalledApps` | Stops Dev Home and the new Outlook from being installed automatically. | DevHome, OutlookNew |
| `Install-ABWinGetPackages` | Installs apps with WinGet (machine scope), with the VC++ runtime for the OS architecture. | PackageIds, VCRedistUrl, VCRedistArmUrl |
| `Set-ABChromeConfig` | Chrome `initial_preferences`; removes the Chrome desktop shortcut. | InitialPreferencesPath, RemoveDesktopShortcut |
| `Disable-ABAPv2Pages` | Hides the extra Autopilot device preparation (APv2) OOBE pages. | |
| `Update-ABApps` | Updates in-box apps (Update-InboxApp) and triggers a Store update scan. | UpdateInboxApps, TriggerStoreScan |
| `Disable-ABFirstLogonAnimation` | Skips the first sign-in animation and the delayed desktop switch. | |
| `Remove-ABOffice` | Removes all preinstalled Office products using the Office Deployment Tool. | OdtUrl |

Each cmdlet has comment-based help (`Get-Help Set-ABTheme -Full`). The builder UI shows the same help text.

## Using the builder UI

Run `ShowBuilder.cmd`, or from PowerShell:

```powershell
Import-Module .\Module\AutopilotBranding\AutopilotBranding.psd1
Show-AutopilotBrandingBuilder -ConfigPath .\AutopilotBranding.json
```

1. The default configuration (`AutopilotBranding.json`) is loaded. Use **Open...** to load another configuration,
   **New** to start with every task disabled, or **Import Config.xml...** to convert a v3 `Config.xml`.
2. The tasks are listed on the left. Tick the ones that should run. Select a task to see its description and
   parameters, then enter the values: check boxes for on/off settings, drop-down lists for fixed choices, one value
   per line for lists, and **Browse...** for files and folders.
3. **Save** / **Save As...** writes your choices to a JSON file.
4. Choose an output folder and click **Generate output and .intunewin**. This generates the output folder and
   packages it as `AutopilotBranding.intunewin` in the output folder's parent folder.

## The JSON configuration

```json
{
  "Version": 1,
  "Description": "My configuration",
  "Tasks": {
    "Set-ABTheme": {
      "Enabled": true,
      "Parameters": {
        "ThemePath": "Assets/Autopilot.theme",
        "WallpaperPath": "Assets/Autopilot.jpg",
        "UpdateThemeWallpaper": true
      }
    },
    "Set-ABTimeZone": { "Enabled": true, "Parameters": { "TimeZone": "Pacific Standard Time" } }
  }
}
```

- The keys under `Tasks` are cmdlet names. The keys under `Parameters` are that cmdlet's parameter names.
- Parameters that end in `Path` are files and parameters that end in `Folder` are folders. A relative path is
  resolved against the JSON file's folder. These files are copied into the output's `Assets` folder.
- When a task or parameter is missing from the file, its default is used. Tasks added in a newer module version show
  up disabled.

## The generated output folder and package

Every build creates the output folder and then packages it as `AutopilotBranding.intunewin`. By default the
package goes in the output folder's parent folder; for example, `.\Output` produces `.\AutopilotBranding.intunewin`.
The output folder contains:

```
AutopilotBranding.ps1    Runner script: loads the module and calls each enabled task with its parameters
AutopilotBranding\       The AutopilotBranding module
Assets\                  Files and folders referenced by the configuration
AutopilotBranding.json   The configuration that was used
```

The runner script looks like this:

```powershell
Import-Module (Join-Path $PSScriptRoot 'AutopilotBranding\AutopilotBranding.psd1') -Force
if (-not (Start-AutopilotBranding -Force:$Force)) { exit 0 }   # logging, tag file, OOBE check, load default user hive
try {
	Invoke-ABTask -Name 'Set-ABTheme' -ScriptBlock {
		$parameters = @{
			ThemePath = (Join-Path $AssetRoot 'Autopilot.theme')
			WallpaperPath = (Join-Path $AssetRoot 'Autopilot.jpg')
		}
		Set-ABTheme @parameters
	}
	...
} finally {
	Stop-AutopilotBranding                                       # unload hive, task summary, stop logging
}
```

Each task runs inside `Invoke-ABTask`, so a failure in one task is logged and the remaining tasks still run. The
log ends with a summary of every task's status. Parameters left at their default values are not written into
the script.

## Building the Intune app

Packaging uses `New-IntuneWinPackage` from the SvRooij.ContentPrep.Cmdlet module. The module, and the NuGet
package provider it needs, are installed for the current user from the PowerShell Gallery the first time you
package. Every build creates the package. You can build in any of these ways:

- In the UI, click **Generate output and .intunewin**.
- From PowerShell (`-PackagePath` is optional and defaults to the output folder's parent folder):

  ```powershell
  Import-Module .\Module\AutopilotBranding\AutopilotBranding.psd1
  Build-AutopilotBranding -ConfigPath .\MyConfig.json -OutputPath .\Output -PackagePath .
  ```

- Run `makeapp.cmd`. It builds `.\Output` from `AutopilotBranding.json` and creates `AutopilotBranding.intunewin`
  in the repository folder.

## Using

Add the resulting Win32 app (.intunewin) to Intune. The installation command line should be:

    powershell.exe -noprofile -executionpolicy bypass -file .\AutopilotBranding.ps1

The uninstall command line should be:

    cmd.exe /c del %ProgramData%\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag

The detection rule should look for the existence of this file:

    Path: %ProgramData%\Microsoft\AutopilotBranding
    File or folder: AutopilotBranding.ps1.tag

The log is written to `%ProgramData%\Microsoft\AutopilotBranding\AutopilotBranding.log`. By default nothing is
changed if OOBE has already completed; run `AutopilotBranding.ps1 -Force` to override this.

The commands and detection rule are the same as in v3, so you can replace an existing app's content without
changing how the app is set up.

## Troubleshooting

- The log is written to `%ProgramData%\Microsoft\AutopilotBranding\AutopilotBranding.log`. Each task is logged
  separately, a failure in one task doesn't stop the others, and the log ends with a summary of every task's status.
- Wallpaper, Start menu and taskbar customizations don't apply (seen on 25H2): check whether the Intune enrollment
  policy "Windows Backup and Restore > Show restore page" is enabled. When it is, the restore experience can
  override the default user profile settings.
- To make apps (not just Windows) use dark mode, add `AppMode=Dark` below `SystemMode=Dark` in the `[VisualStyles]`
  section of `Autopilot.theme`.
- Edge update: `Update-ABEdge` looks up the latest Stable Edge MSI for the device's architecture (x64 or ARM64)
  from the edgeupdates.microsoft.com API and verifies its hash before installing. If the lookup fails, it falls
  back to `Url` (x64) or `ArmUrl` (ARM64); with no `ArmUrl`, the update is then skipped on ARM64. ARM64 devices
  never use the x64 MSI (it breaks Edge and WebView2 there).
- "The User Profile Service failed the sign-in": this happens if the default user registry hive is left loaded.
  The module always unloads it when the run finishes (with retries), and unloads a hive left over from an earlier
  run before loading it again.

## Testing

`Tests\Test-AutopilotBranding.ps1` checks the module, the builder functions, the builder UI (created and driven
without being shown), the generated runner script, packaging, and the `.cmd` launchers. Run it with each PowerShell
version you use:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Tests\Test-AutopilotBranding.ps1
pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Tests\Test-AutopilotBranding.ps1
```

The GitHub workflow runs it with Windows PowerShell 5.1 and PowerShell 7.6 before building the app.

## Adding your own task

Add a file named `Tasks\<order>-<Verb>-AB<Noun>.ps1` to the module that contains a single function with
comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`) and a `param()` block. The builder finds it
automatically. Supported parameter types are `[string]`, `[string[]]`, `[bool]`, `[switch]`, and `[int]`.
`[ValidateSet()]` becomes a drop-down list. Name a parameter `...Path` or `...Folder` if it refers to a file or
folder that should be copied into the package. Use the helpers in `Private\Common.ps1`, such as
`Set-ABRegistryValue -Hive DefaultUser`, `Copy-ABFile`, and `Write-ABLog`, to stay consistent with the other tasks.

## Migrating from v3 (Config.xml)

Use **Import Config.xml...** in the UI, or:

```powershell
Import-Module .\Module\AutopilotBranding\AutopilotBranding.psd1
Build-AutopilotBranding -LegacyConfigXml C:\Old\AutopilotBranding\Config.xml -ConfigPath .\MyConfig.json
```

Every `Skip*` flag becomes a task that is enabled or disabled, and every setting becomes a parameter (including the
v3.3.2 `ComputerName` and `LanguageSettings` elements). File
parameters point at the files that sit next to the old `Config.xml`.

## Change history

- 2023-09-23: Added logic to handle the Windows 11 Start menu proces using Start2.bin; Windows 10 will continue to use Layout.xml.  Added additional Windows 11 in-box apps to remove.
- 2024-01-31: Added additional apps to remove, adding timestamps to log messages, cleaned up error logging.
- 2024-04-27: Added logic to stop the Start menu from popping up each time a new user signs in.
- 2024-12-26: Added support for removing FODs and disabling optional features.
- 2026-11-04 (PR #100): The Edge update looks up the latest Stable MSI for x64 and ARM64 from the edgeupdates.microsoft.com API and verifies its hash.
- 2026-11-03 (v3.3.2): Failures in one step no longer skip the rest; the default user hive is always unloaded; ARM64 fixes for Edge and the VC++ runtime; optional computer rename; optional PowerShell-based language settings; in-box app removal also removes installed packages; removed obsolete IE http/https associations.
- v4.0.0 (dev): Restructured into the AutopilotBranding module (one cmdlet per task, settings as parameters), added the builder UI, JSON configuration, and generated runner script.

## Suggestions?

If you have suggestions on other customizations that would be useful, contact me at michael@oofhours.com.

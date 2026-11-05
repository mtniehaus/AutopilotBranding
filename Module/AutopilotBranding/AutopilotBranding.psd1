@{
	RootModule           = 'AutopilotBranding.psm1'
	ModuleVersion        = '4.0.0'
	GUID                 = '5d0b2c47-6a8e-4d0f-9a4c-6c2f0b9e8a31'
	Author               = 'Michael Niehaus'
	CompanyName          = ''
	Copyright            = 'Copyright (c) 2025 Michael Niehaus'
	Description          = 'Configuration tasks used to customize Windows devices during Windows Autopilot (start menu, taskbar, theme, apps, features, OEM info, and more).'
	PowerShellVersion    = '5.1'
	CompatiblePSEditions = @('Desktop', 'Core')

	# Functions are exported by AutopilotBranding.psm1 (all Public\*.ps1 and Tasks\*.ps1 functions).
	FunctionsToExport    = '*'
	CmdletsToExport      = @()
	VariablesToExport    = @()
	AliasesToExport      = @('Build-AutopilotBranding')

	PrivateData          = @{
		PSData = @{
			Tags         = @('intune', 'endpoint', 'autopilot', 'branding', 'windows')
			LicenseUri   = 'https://github.com/mtniehaus/AutopilotBranding/blob/main/LICENSE'
			ProjectUri   = 'https://github.com/mtniehaus/AutopilotBranding'

			# New-AutopilotBrandingPackage / Show-AutopilotBrandingBuilder use New-IntuneWinPackage from this module to
			# create the .intunewin file, and install it for the current user (version 0.4.0 or later) on first use.
			# It isn't in RequiredModules: the module also runs on devices (inside the generated package), where only
			# the configuration tasks are used and the content prep module isn't needed or installed.
			ExternalModuleDependencies = @('SvRooij.ContentPrep.Cmdlet')
			ReleaseNotes = @'
v4.0.0 - Restructured the monolithic AutopilotBranding.ps1 script into a module with one cmdlet per
         configuration task.  Settings are now passed as cmdlet parameters (instead of Config.xml);
         a builder UI generates the runner script and output folder.  Includes the v3.3.2 fixes from main
         (hive unload retries, ARM64 handling for Edge and the VC++ runtime, removal of installed appx packages,
         more resilient WinGet/feature steps), the new Rename-ABComputer and Set-ABLanguageSettings tasks, and
         the Edge MSI lookup from the edgeupdates API with hash verification (PR #100).  Per-user settings and
         files are also applied to existing user profiles (needed with Autopilot device preparation, where the
         user's profile exists before apps install).
v3.3.2 - 2026-11-03 - Fixes for step failures, ARM64, hive unload; optional computer rename and language settings (last version of the monolithic script)
v3.3.1 - 2025-10-10 - Minor bug fixes
'@
		}
	}
}

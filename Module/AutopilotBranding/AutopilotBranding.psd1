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
	AliasesToExport      = @()

	PrivateData          = @{
		PSData = @{
			Tags         = @('intune', 'endpoint', 'autopilot', 'branding', 'windows')
			LicenseUri   = 'https://github.com/mtniehaus/AutopilotBranding/blob/main/LICENSE'
			ProjectUri   = 'https://github.com/mtniehaus/AutopilotBranding'
			ReleaseNotes = @'
v4.0.0 - Restructured the monolithic AutopilotBranding.ps1 script into a module with one cmdlet per
         configuration task.  Settings are now passed as cmdlet parameters (instead of Config.xml);
         a builder UI generates the runner script and output folder.
v3.3.1 - 2025-10-10 - Minor bug fixes (last version of the monolithic script)
'@
		}
	}
}

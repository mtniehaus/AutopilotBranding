<#
.SYNOPSIS
Automated tests for the AutopilotBranding module, builder, builder UI, generated runner script and .cmd launchers.

.DESCRIPTION
Run this with each PowerShell version to verify, for example:
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Tests\Test-AutopilotBranding.ps1
  pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Tests\Test-AutopilotBranding.ps1

The tests run on Windows.  They create (if needed) and build the repository's Project folder (via makeapp.cmd),
use a temporary folder, install the SvRooij.ContentPrep.Cmdlet module for the current user if
needed, and (when running elevated) run the generated runner script, which writes its log and tag file to
%ProgramData%\Microsoft\AutopilotBranding and exits without changing anything because OOBE has already completed.
The builder UI is created and exercised without being shown.  ShowBuilder.cmd is started and stopped again after a
few seconds.

Exits with code 1 if any test fails.

.PARAMETER SkipCmd
Don't run the makeapp.cmd and ShowBuilder.cmd tests.
#>
[CmdletBinding()]
param (
	[switch] $SkipCmd
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$manifest = Join-Path $repoRoot 'Module\AutopilotBranding\AutopilotBranding.psd1'
$templateDir = Join-Path $repoRoot 'Module\AutopilotBranding\Template'
$defaultConfig = Join-Path $templateDir 'AutopilotBranding.json'
$psExe = (Get-Process -Id $PID).Path
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("ABTest-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -Path $temp -ItemType Directory -Force | Out-Null

$script:passed = 0
$script:failed = New-Object System.Collections.Generic.List[string]

function Test-Case {
	param (
		[Parameter(Mandatory = $true)] [string] $Name,
		[Parameter(Mandatory = $true)] [scriptblock] $Test
	)
	Write-Host "[....] $Name" -ForegroundColor DarkGray
	try {
		& $Test
		$script:passed++
		Write-Host "[PASS] $Name" -ForegroundColor Green
	}
	catch {
		$script:failed.Add($Name)
		Write-Host "[FAIL] $Name" -ForegroundColor Red
		Write-Host "       $($_.Exception.Message)" -ForegroundColor Red
		if ($_.ScriptStackTrace) {
			Write-Host ($_.ScriptStackTrace -replace '(?m)^', '       ') -ForegroundColor DarkGray
		}
	}
}

function Assert-True {
	param ($Condition, [string] $Message = 'Assertion failed')
	if (-not $Condition) { throw $Message }
}

function Assert-Equal {
	param ($Expected, $Actual, [string] $Message = 'Values differ')
	$e = ConvertTo-Json -InputObject $Expected -Compress -Depth 5
	$a = ConvertTo-Json -InputObject $Actual -Compress -Depth 5
	if ($e -ne $a) { throw "$($Message): expected $e, got $a" }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)), $psExe"
Write-Host "Apartment: $([System.Threading.Thread]::CurrentThread.GetApartmentState()), elevated: $isAdmin, temp: $temp"
Write-Host ''


#region Static checks

Test-Case 'All PowerShell files parse without errors' {
	$problems = @()
	$files = Get-ChildItem -Path $repoRoot -Recurse -Include *.ps1, *.psm1, *.psd1 |
		Where-Object { $_.FullName -notlike (Join-Path $repoRoot 'Output\*') -and $_.FullName -notlike (Join-Path $repoRoot 'Project\*') -and $_.FullName -notlike (Join-Path $repoRoot 'web\node_modules\*') }
	foreach ($file in $files) {
		$tokens = $null
		$errors = $null
		[System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
		foreach ($e in $errors) {
			$problems += "$($file.FullName):$($e.Extent.StartLineNumber): $($e.Message)"
		}
	}
	Assert-True ($files.Count -gt 40) "Only $($files.Count) files found"
	Assert-True ($problems.Count -eq 0) ($problems -join "`n")
}

Test-Case 'PowerShell files are ASCII (Windows PowerShell 5.1 reads BOM-less files as ANSI)' {
	$bad = @(Get-ChildItem -Path (Join-Path $repoRoot 'Module'), (Join-Path $repoRoot 'Tests') -Recurse -Include *.ps1, *.psm1, *.psd1 |
			Where-Object { [System.IO.File]::ReadAllBytes($_.FullName) | Where-Object { $_ -gt 127 } | Select-Object -First 1 })
	Assert-True ($bad.Count -eq 0) "Non-ASCII files: $($bad.FullName -join ', ')"
}

#endregion


#region Module

$module = $null
Test-Case 'Module imports without errors or warnings' {
	$warnings = $null
	$script:module = Import-Module $manifest -Force -PassThru -WarningVariable warnings -WarningAction SilentlyContinue
	Assert-True ($null -ne $script:module) 'Module not imported'
	Assert-True (@($warnings).Count -eq 0) "Warnings: $($warnings -join '; ')"
}
$module = Get-Module AutopilotBranding
if (-not $module) {
	Write-Host 'Module could not be imported, stopping.' -ForegroundColor Red
	exit 1
}

Test-Case 'Module manifest is valid (for publishing to the PowerShell Gallery)' {
	$info = Test-ModuleManifest -Path $manifest
	Assert-True ($info.Version -ge [version]'4.0.0') "Unexpected version $($info.Version)"
	Assert-True ($info.ExportedAliases.ContainsKey('Build-AutopilotBranding')) 'Alias not declared in the manifest'
	Assert-True (@($info.PrivateData.PSData.ExternalModuleDependencies) -contains 'SvRooij.ContentPrep.Cmdlet') 'SvRooij.ContentPrep.Cmdlet not declared as an external module dependency'
	Assert-True (@($info.RequiredModules).Count -eq 0) 'RequiredModules must stay empty (the module runs on devices without the content prep module)'
	Assert-True (Test-Path (Join-Path $templateDir 'AutopilotBranding.json')) 'Template missing from the module'
}

$taskFiles = @(Get-ChildItem (Join-Path $repoRoot 'Module\AutopilotBranding\Tasks') -Filter *.ps1 | Sort-Object Name)
$taskNames = @($taskFiles | ForEach-Object { $_.BaseName -replace '^\d+-', '' })

Test-Case 'Exports the cmdlets, tasks and builder functions, and nothing private' {
	$exported = @((Get-Command -Module AutopilotBranding).Name)
	$expected = @('Show-AutopilotBrandingBuilder', 'New-AutopilotBrandingPackage', 'Build-AutopilotBranding', 'New-AutopilotBrandingProject', 'Get-ABTemplatePath', 'Test-ABOutputSelfContained', 'Invoke-AutopilotBranding', 'Get-ABTaskInvocation', 'Start-AutopilotBranding', 'Stop-AutopilotBranding',
		'Invoke-ABTask', 'Write-ABLog', 'Mount-ABDefaultUserHive', 'Dismount-ABDefaultUserHive', 'Get-ABTaskDefinition',
		'Read-ABConfiguration', 'Save-ABConfiguration', 'Test-ABConfiguration', 'New-ABOutput', 'New-ABIntuneWinPackage',
		'ConvertFrom-ABLegacyConfig') + $taskNames
	$missing = @($expected | Where-Object { $exported -notcontains $_ })
	Assert-True ($missing.Count -eq 0) "Not exported: $($missing -join ', ')"
	$private = @('Get-Value', 'Get-List', 'Get-File', 'Invoke-ABHiveUnload', 'Show-ABUIMessage', 'Initialize-ABBuilderWindow',
		'ConvertTo-ABFullPath', 'Test-ABArm64', 'Set-ABRegistryValue', 'Get-ABAstValue', 'Show-TaskDetail', 'Invoke-Safely',
		'Update-ABAssetBase', 'Copy-ABItemNoOverwrite', 'Test-ABPathUnder', 'Get-DialogFolder', 'Copy-ABProjectAsset',
		'Get-ABProjectAssetTarget', 'Set-AssetFromSelection', 'Test-ABSameContent')
	$leaked = @($private | Where-Object { $exported -contains $_ })
	Assert-True ($leaked.Count -eq 0) "Private functions exported: $($leaked -join ', ')"
}

Test-Case 'Every task cmdlet has help (synopsis and parameter descriptions)' {
	foreach ($name in $taskNames) {
		$help = Get-Help $name -Full
		Assert-True ($help.Synopsis -and $help.Synopsis -notmatch "^\s*$name") "$name has no synopsis"
		foreach ($p in (Get-Command $name).Parameters.Values | Where-Object { [System.Management.Automation.Cmdlet]::CommonParameters -notcontains $_.Name }) {
			$ph = $help.parameters.parameter | Where-Object { $_.name -eq $p.Name }
			Assert-True ($ph -and ($ph.description | Out-String).Trim()) "$name -$($p.Name) has no description"
		}
	}
}

Test-Case 'Get-ABTaskDefinition describes every task and parameter' {
	$definitions = @(Get-ABTaskDefinition)
	Assert-Equal $taskNames @($definitions.Name) 'Task names/order'
	foreach ($d in $definitions) {
		Assert-True $d.Synopsis "$($d.Name) has no synopsis"
		$cmd = Get-Command $d.Name
		foreach ($p in $d.Parameters) {
			Assert-True ($p.Kind -in 'String', 'StringArray', 'Boolean', 'Switch', 'Integer') "$($d.Name) -$($p.Name): unexpected kind $($p.Kind)"
			Assert-True $p.HelpText "$($d.Name) -$($p.Name) has no help text"
			Assert-True $cmd.Parameters.ContainsKey($p.Name) "$($d.Name) -$($p.Name) not found on the cmdlet"
		}
	}
}

Test-Case 'Invoke-ABTask logs a failing task and keeps going' {
	$output = Invoke-ABTask -Name 'Failing test task' -ScriptBlock { throw 'Expected test failure' } 6>&1 | Out-String
	Assert-True ($output -match 'ERROR in Failing test task') "Error not logged: $output"
	Assert-True ($output -match 'Finished: Failing test task \(Failed') "Failure status not logged: $output"
}

#endregion


#region Builder

Test-Case 'Default configuration is complete and valid' {
	$configuration = Read-ABConfiguration -Path $defaultConfig
	Assert-Equal $taskNames @($configuration.Tasks.Keys) 'Tasks in configuration'
	$problems = @(Test-ABConfiguration -Configuration $configuration -BasePath $templateDir)
	Assert-True ($problems.Count -eq 0) (($problems | ForEach-Object { "$($_.Task) -$($_.Parameter): $($_.Message)" }) -join '; ')
}

Test-Case 'Configuration round-trips through Save/Read' {
	$configuration = Read-ABConfiguration -Path $defaultConfig
	$path = Join-Path $temp 'roundtrip.json'
	Save-ABConfiguration -Configuration $configuration -Path $path
	$again = Read-ABConfiguration -Path $path
	Assert-Equal $configuration $again 'Round-tripped configuration'
}

Test-Case 'Relative paths resolve against the current location' {
	Push-Location $temp
	try {
		Save-ABConfiguration -Configuration (Read-ABConfiguration -Path $defaultConfig) -Path 'relative.json'
		Assert-True (Test-Path (Join-Path $temp 'relative.json')) 'relative.json was not written to the current location'
	}
	finally {
		Pop-Location
	}
}

Test-Case 'Legacy Config.xml converts to an equivalent configuration' {
	$c = ConvertFrom-ABLegacyConfig -Path (Join-Path $PSScriptRoot 'Config.legacy.xml')
	Assert-Equal $taskNames @($c.Tasks.Keys) 'Tasks'
	Assert-Equal $false $c.Tasks['Rename-ABComputer'].Enabled 'Rename-ABComputer enabled'
	Assert-Equal $false $c.Tasks['Set-ABStartAlignment'].Enabled 'Set-ABStartAlignment enabled (SkipLeftAlignStart)'
	Assert-Equal $false $c.Tasks['Enable-ABUEV'].Enabled 'Enable-ABUEV enabled (SkipUEV)'
	Assert-Equal $true $c.Tasks['Set-ABTheme'].Enabled 'Set-ABTheme enabled'
	Assert-Equal $false $c.Tasks['Set-ABLanguageSettings'].Enabled 'Set-ABLanguageSettings enabled (commented out)'
	Assert-Equal 'https://go.microsoft.com/fwlink/?LinkID=2093437' $c.Tasks['Update-ABEdge'].Parameters.Url 'Edge URL'
	Assert-Equal 'Contoso' $c.Tasks['Set-ABRegisteredOwner'].Parameters.Organization 'Organization'
	Assert-True ($c.Tasks['Remove-ABProvisionedApps'].Parameters.AppNames -contains 'Microsoft.BingNews') 'AppNames'
	Assert-Equal @('Google.Chrome', '9WZDNCRD29V9') $c.Tasks['Install-ABWinGetPackages'].Parameters.PackageIds 'PackageIds'
}

Test-Case 'Get-ABTaskInvocation passes only non-default values and resolves files; the runner is generic' {
	$configuration = Read-ABConfiguration -Path $defaultConfig
	$configuration.Tasks['Set-ABTimeZone'].Parameters.TimeZone = "O'Brien Standard Time"
	$invocations = @(Get-ABTaskInvocation -Configuration $configuration -BasePath $templateDir)
	$names = @($invocations | ForEach-Object { $_.Name })
	$enabled = @($taskNames | Where-Object { $configuration.Tasks[$_].Enabled })
	Assert-Equal $enabled $names 'Invoked tasks (enabled, in order)'
	$theme = $invocations | Where-Object { $_.Name -eq 'Set-ABTheme' }
	Assert-Equal (Join-Path $templateDir 'Assets\Autopilot.theme') $theme.Parameters.ThemePath 'ThemePath resolved against the base path'
	Assert-True (-not $theme.Parameters.Contains('UpdateThemeWallpaper')) 'Default value passed'
	Assert-Equal "O'Brien Standard Time" ($invocations | Where-Object { $_.Name -eq 'Set-ABTimeZone' }).Parameters.TimeZone 'Non-default value'
	Assert-True ($names -notcontains 'Set-ABStartAlignment') 'Disabled task invoked'
	foreach ($invocation in $invocations) {
		$cmd = Get-Command $invocation.Name
		foreach ($key in $invocation.Parameters.Keys) {
			Assert-True $cmd.Parameters.ContainsKey($key) "$($invocation.Name) has no parameter -$key"
		}
	}

	# The runner script is the same for every configuration and just calls Invoke-AutopilotBranding
	$runner = Get-ABRunnerScript
	$errors = $null
	[System.Management.Automation.Language.Parser]::ParseInput($runner, [ref]$null, [ref]$errors) | Out-Null
	Assert-True ($errors.Count -eq 0) "Runner parse errors: $($errors[0].Message)"
	Assert-True ($runner -match 'Invoke-AutopilotBranding -ConfigPath \(Join-Path \$PSScriptRoot ''AutopilotBranding\.json''\)') 'Runner does not call Invoke-AutopilotBranding'
}

$project = Join-Path $temp 'Project'
Test-Case 'New-AutopilotBrandingProject creates a project from the template in the module' {
	Assert-Equal $templateDir (Get-ABTemplatePath) 'Template path'
	$result = New-AutopilotBrandingProject -Path $project
	Assert-Equal (Join-Path $project 'AutopilotBranding.json') $result.ConfigPath 'ConfigPath'
	$templateFiles = @(Get-ChildItem (Join-Path $templateDir 'Assets') -Recurse -File | ForEach-Object { $_.FullName.Substring($templateDir.Length + 1) })
	Assert-True ($templateFiles.Count -gt 10) "Only $($templateFiles.Count) template files"
	foreach ($relative in $templateFiles) {
		Assert-True (Test-Path (Join-Path $project $relative)) "Missing $relative in the project"
	}
	$problems = @(Test-ABConfiguration -Configuration (Read-ABConfiguration -Path $result.ConfigPath) -BasePath $project)
	Assert-True ($problems.Count -eq 0) 'Project configuration does not validate against its own folder'

	# An existing project is refused without -Force; -Force replaces the configuration and sample files
	$threw = $false
	try { New-AutopilotBrandingProject -Path $project | Out-Null } catch { $threw = $_.Exception.Message -match 'already contains a project' }
	Assert-True $threw 'Existing project not refused'
	Set-Content -Path (Join-Path $project 'Assets\Autopilot.theme') -Value 'customized'
	New-AutopilotBrandingProject -Path $project -Force | Out-Null
	Assert-Equal (Get-FileHash (Join-Path $templateDir 'Assets\Autopilot.theme')).Hash (Get-FileHash (Join-Path $project 'Assets\Autopilot.theme')).Hash '-Force did not restore the sample file'
}

$build = $null
Test-Case 'Build-AutopilotBranding (alias) builds a project into its Output folder and .intunewin package' {
	Assert-Equal 'New-AutopilotBrandingPackage' (Get-Alias Build-AutopilotBranding).Definition 'Alias target'
	$script:build = Build-AutopilotBranding -ProjectPath $project -PassThru 6>$null
	Assert-Equal (Join-Path $project 'Output') $script:build.OutputPath 'Output path'
	foreach ($relative in 'AutopilotBranding.ps1', 'AutopilotBranding.json', 'AutopilotBranding\AutopilotBranding.psd1',
		'AutopilotBranding\Tasks\030-Set-ABTheme.ps1', 'Assets\Autopilot.theme', 'Assets\start2.bin', 'Assets\Contoso.bmp') {
		Assert-True (Test-Path (Join-Path $script:build.OutputPath $relative)) "Missing $relative"
	}
	Assert-True (-not (Test-Path (Join-Path $script:build.OutputPath 'AutopilotBranding\Template'))) 'The module template was copied into the output'
	Assert-Equal (Join-Path $project 'AutopilotBranding.intunewin') $script:build.Package 'Package path'
	Assert-True ((Get-Item $script:build.Package).Length -gt 10000) 'Package is too small'
	Assert-Equal (Get-FileHash (Join-Path $repoRoot 'Module\AutopilotBranding\Runner\AutopilotBranding.ps1')).Hash (Get-FileHash $script:build.RunnerScript).Hash 'Runner script is not the generic one'
	$problems = @(Test-ABConfiguration -Configuration (Read-ABConfiguration -Path (Join-Path $script:build.OutputPath 'AutopilotBranding.json')) -BasePath $script:build.OutputPath)
	Assert-True ($problems.Count -eq 0) 'Output configuration does not validate against the copied assets'
	$selfContained = @(Test-ABOutputSelfContained -OutputPath $script:build.OutputPath)
	Assert-True ($selfContained.Count -eq 0) "Output not self-contained: $(($selfContained | ForEach-Object { $_.Message }) -join '; ')"
	$outputConfig = Read-ABConfiguration -Path (Join-Path $script:build.OutputPath 'AutopilotBranding.json')
	Assert-Equal '' $outputConfig.Tasks['Set-ABLanguage'].Parameters.LanguageXmlPath 'File parameter of a disabled task not cleared in the packaged configuration'
	Assert-True ($outputConfig.Tasks['Set-ABTheme'].Parameters.ThemePath -like 'Assets\*') 'Packaged ThemePath not relative'
}

Test-Case 'Files outside the project are copied into the package and referenced relatively' {
	$external = Join-Path $temp 'External files'
	New-Item -Path $external -ItemType Directory -Force | Out-Null
	$wallpaper = Join-Path $external 'Outside Wallpaper.jpg'
	Copy-Item (Join-Path $templateDir 'Assets\Autopilot.jpg') $wallpaper
	$configuration = Read-ABConfiguration -Path (Join-Path $project 'AutopilotBranding.json')
	$configuration.Tasks['Set-ABTheme'].Parameters.WallpaperPath = $wallpaper
	$configPath = Join-Path $temp 'external.json'
	Save-ABConfiguration -Configuration $configuration -Path $configPath
	# Relative paths in this configuration are relative to $temp, so point them back at the project's files
	Copy-Item (Join-Path $project 'Assets') (Join-Path $temp 'Assets') -Recurse -Force

	$result = New-ABOutput -Configuration (Read-ABConfiguration -Path $configPath) -BasePath $temp -OutputPath (Join-Path $temp 'ExternalOutput') -Force
	Assert-True (Test-Path (Join-Path $result.OutputPath 'Assets\Outside Wallpaper.jpg')) 'External file not copied into the output'
	$packagedConfig = Read-ABConfiguration -Path (Join-Path $result.OutputPath 'AutopilotBranding.json')
	Assert-Equal 'Assets\Outside Wallpaper.jpg' $packagedConfig.Tasks['Set-ABTheme'].Parameters.WallpaperPath 'Packaged WallpaperPath'
	$theme = Get-ABTaskInvocation -Configuration $packagedConfig -BasePath $result.OutputPath | Where-Object { $_.Name -eq 'Set-ABTheme' }
	Assert-Equal (Join-Path $result.OutputPath 'Assets\Outside Wallpaper.jpg') $theme.Parameters.WallpaperPath 'WallpaperPath on the device resolves inside the package'
	Assert-True ((Get-Content (Join-Path $result.OutputPath 'AutopilotBranding.json') -Raw) -notmatch [regex]::Escape($temp.Replace('\', '\\'))) 'Packaged configuration refers to the build machine'
	Assert-True (@(Test-ABOutputSelfContained -OutputPath $result.OutputPath).Count -eq 0) 'Output not self-contained'

	# A packaged configuration that refers outside the package is reported
	$packaged = Read-ABConfiguration -Path (Join-Path $result.OutputPath 'AutopilotBranding.json')
	$packaged.Tasks['Set-ABTheme'].Parameters.WallpaperPath = $wallpaper
	Save-ABConfiguration -Configuration $packaged -Path (Join-Path $result.OutputPath 'AutopilotBranding.json')
	$problems = @(Test-ABOutputSelfContained -OutputPath $result.OutputPath | Where-Object { $_.Severity -eq 'Error' })
	Assert-True ($problems.Count -eq 1 -and $problems[0].Message -match 'WallpaperPath') 'Full path in the packaged configuration not reported'
}

Test-Case 'Files and folders are copied into a project''s Assets folder (replace only when asked)' {
	$external = Join-Path $temp 'Copy source'
	New-Item -Path (Join-Path $external 'Templates') -ItemType Directory -Force | Out-Null
	Set-Content -Path (Join-Path $external 'Logo.bmp') -Value 'logo'
	Set-Content -Path (Join-Path $external 'Templates\One.xml') -Value '<one/>'
	Set-Content -Path (Join-Path $external 'Autopilot.jpg') -Value 'different wallpaper'

	$copied = & $module { param ($s, $p) Copy-ABProjectAsset -Source $s -ProjectPath $p } (Join-Path $external 'Logo.bmp') $project
	Assert-Equal 'Assets\Logo.bmp' $copied 'Relative path of the copied file'
	Assert-True (Test-Path (Join-Path $project 'Assets\Logo.bmp')) 'File not copied'
	$copied = & $module { param ($s, $p) Copy-ABProjectAsset -Source $s -ProjectPath $p } (Join-Path $external 'Templates') $project
	Assert-True (Test-Path (Join-Path $project 'Assets\Templates\One.xml')) 'Folder not copied'
	# Identical: no error, nothing to replace
	& $module { param ($s, $p) Copy-ABProjectAsset -Source $s -ProjectPath $p } (Join-Path $external 'Logo.bmp') $project | Out-Null
	# Different file with the same name: refused without -Replace, replaced with it
	$threw = $false
	try { & $module { param ($s, $p) Copy-ABProjectAsset -Source $s -ProjectPath $p } (Join-Path $external 'Autopilot.jpg') $project } catch { $threw = $true }
	Assert-True $threw 'Existing different file replaced without -Replace'
	& $module { param ($s, $p) Copy-ABProjectAsset -Source $s -ProjectPath $p -Replace } (Join-Path $external 'Autopilot.jpg') $project | Out-Null
	Assert-Equal (Get-FileHash (Join-Path $external 'Autopilot.jpg')).Hash (Get-FileHash (Join-Path $project 'Assets\Autopilot.jpg')).Hash 'File not replaced'
	Copy-Item (Join-Path $templateDir 'Assets\Autopilot.jpg') (Join-Path $project 'Assets\Autopilot.jpg') -Force
}

Test-Case 'Package destination inside the output folder is rejected' {
	$threw = $false
	try {
		New-ABIntuneWinPackage -SourcePath $build.OutputPath -DestinationPath (Join-Path $build.OutputPath 'sub')
	}
	catch {
		$threw = $_.Exception.Message -match 'must not be inside'
	}
	Assert-True $threw 'No error for a destination inside the source folder'
}

Test-Case 'Generated runner script runs (log, tag file, OOBE check) in this PowerShell version' {
	if (-not $isAdmin) {
		Write-Host '       Skipped: requires elevation (writes to %ProgramData%)' -ForegroundColor Yellow
		return
	}
	$logFolder = "$($env:ProgramData)\Microsoft\AutopilotBranding"
	Remove-Item (Join-Path $logFolder 'AutopilotBranding.log') -Force -ErrorAction SilentlyContinue
	$output = & $psExe -NoProfile -ExecutionPolicy Bypass -File $build.RunnerScript 2>&1 | Out-String
	Assert-Equal 0 $LASTEXITCODE "Runner exit code (output: $output)"
	$log = Get-Content (Join-Path $logFolder 'AutopilotBranding.log') -Raw
	Assert-True ($log -match 'AutopilotBranding module v') "Module not loaded by the runner: $log"
	Assert-True ($log -match 'OOBE is completed, bailing out') "OOBE check not logged: $log"
	Assert-True (Test-Path (Join-Path $logFolder 'AutopilotBranding.ps1.tag')) 'Tag file not created'
}

Test-Case 'Existing user profiles are found (and system and OOBE accounts are not)' {
	$profiles = @(& $module { Get-ABExistingUserProfile })
	foreach ($p in $profiles) {
		Assert-True ($p.Sid -match '^S-1-5-21-|^S-1-12-1-') "Unexpected SID $($p.Sid)"
		Assert-True ((Split-Path $p.ProfilePath -Leaf) -notlike 'defaultuser*') "OOBE account included: $($p.ProfilePath)"
	}
	$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
	if ($me -match '^S-1-5-21-|^S-1-12-1-') {
		$mine = $profiles | Where-Object { $_.Sid -eq $me }
		Assert-True $mine "The current user's profile ($me) wasn't found"
		Assert-True $mine.Loaded "The current user's profile isn't reported as loaded"
	}
}

Test-Case 'Per-user settings go to the default profile and existing profiles (unless turned off)' {
	# Writes a test key to the default profile and the current user's profile, so it only runs on a CI runner
	if (-not $isAdmin -or $env:GITHUB_ACTIONS -ne 'true') {
		Write-Host '       Skipped: only runs elevated on a GitHub Actions runner (it changes user profiles)' -ForegroundColor Yellow
		return
	}
	try {
		& $module {
			Set-ABRegistryValue -Hive DefaultUser -Path 'Software\AutopilotBrandingTest' -Name Probe -Type REG_SZ -Value 'both'
			$script:ABIncludeExistingProfiles = $false
			try { Set-ABRegistryValue -Hive DefaultUser -Path 'Software\AutopilotBrandingTest' -Name DefaultOnly -Type REG_SZ -Value 'default' }
			finally { $script:ABIncludeExistingProfiles = $true }
			Set-ABRegistryValue -Hive ExistingUsers -Path 'Software\AutopilotBrandingTest' -Name ExistingOnly -Type REG_SZ -Value 'existing'
		}
		$hkcu = Get-ItemProperty 'HKCU:\Software\AutopilotBrandingTest'
		Assert-Equal 'both' $hkcu.Probe 'Value not written to the existing (signed-in) profile'
		Assert-True ($null -eq $hkcu.DefaultOnly) 'Value written to existing profiles with IncludeExistingProfiles off'
		Assert-Equal 'existing' $hkcu.ExistingOnly 'ExistingUsers value not written to the existing profile'
		$default = & $module {
			Mount-ABDefaultUserHive
			try { Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\TempUser\Software\AutopilotBrandingTest' } finally { Dismount-ABDefaultUserHive }
		}
		Assert-Equal 'both' $default.Probe 'Value not written to the default profile'
		Assert-Equal 'default' $default.DefaultOnly 'Value not written to the default profile with IncludeExistingProfiles off'
		Assert-True ($null -eq $default.ExistingOnly) 'ExistingUsers value written to the default profile'
	}
	finally {
		Remove-Item 'HKCU:\Software\AutopilotBrandingTest' -Recurse -Force -ErrorAction SilentlyContinue
		& $module {
			Mount-ABDefaultUserHive
			try { Remove-Item 'Registry::HKEY_LOCAL_MACHINE\TempUser\Software\AutopilotBrandingTest' -Recurse -Force -ErrorAction SilentlyContinue } finally { Dismount-ABDefaultUserHive }
		}
	}
}

Test-Case 'Remove-ABOffice does nothing when no Office is installed' {
	# On a CI runner without Office, it must skip without downloading or running the Office Deployment Tool
	if (-not $isAdmin -or $env:GITHUB_ACTIONS -ne 'true') {
		Write-Host '       Skipped: only runs elevated on a GitHub Actions runner' -ForegroundColor Yellow
		return
	}
	if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration') {
		Write-Host '       Skipped: Office is installed on this runner' -ForegroundColor Yellow
		return
	}
	$output = Remove-ABOffice 6>&1 | Out-String
	Assert-True ($output -match 'No Office products are installed') "Unexpected output: $output"
	Assert-True ($output -notmatch 'Running ODT') 'The Office Deployment Tool was run'
}

Test-Case 'Remove-ABInstalledPrograms uninstalls a program by ID with the Programs provider in this PowerShell version' {
	# Registers a fake program whose (silent) uninstall command deletes its own uninstall key, then removes it by its
	# key name.  On PowerShell 7 this goes through Import-Module PackageManagement -UseWindowsPowerShell.
	if (-not $isAdmin -or $env:GITHUB_ACTIONS -ne 'true') {
		Write-Host '       Skipped: only runs elevated on a GitHub Actions runner' -ForegroundColor Yellow
		return
	}
	$keyName = 'AutopilotBrandingTestProgram'
	$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$keyName"
	$command = "`"$env:SystemRoot\System32\reg.exe`" delete `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$keyName`" /f /reg:64"
	New-Item -Path $key -Force | Out-Null
	try {
		New-ItemProperty -Path $key -Name DisplayName -Value 'Autopilot Branding Test Program' -Force | Out-Null
		New-ItemProperty -Path $key -Name DisplayVersion -Value '1.0.0' -Force | Out-Null
		New-ItemProperty -Path $key -Name Publisher -Value 'AutopilotBranding tests' -Force | Out-Null
		New-ItemProperty -Path $key -Name UninstallString -Value $command -Force | Out-Null
		New-ItemProperty -Path $key -Name QuietUninstallString -Value $command -Force | Out-Null
		$output = Remove-ABInstalledPrograms -PackageIds $keyName, 'No-Such-Package-*' 6>&1 | Out-String
		Assert-True ($output -match 'No installed package matches No-Such-Package-\*') "Missing package not reported: $output"
		Assert-True ($output -match 'Uninstalling Autopilot Branding Test Program') "Test program not found: $output"
		Assert-True ($output -notmatch 'Unable to uninstall') "Uninstall failed: $output"
		Assert-True ($output -match 'Uninstalled') "Uninstall not confirmed: $output"
		# The uninstall command may run asynchronously
		for ($i = 0; $i -lt 30 -and (Test-Path $key); $i++) { Start-Sleep -Seconds 1 }
		Assert-True (-not (Test-Path $key)) "The test program's uninstall command was not run: $output"
		if ($PSVersionTable.PSEdition -eq 'Core') {
			Assert-True ($null -eq (Get-Command Get-ABWinPSPackage -ErrorAction SilentlyContinue)) 'The Windows PowerShell compatibility module was left loaded'
		}
	}
	finally {
		Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
	}
}

Test-Case 'Generic runner runs a configuration end to end (-Force, three tasks) in this PowerShell version' {
	# This changes the computer (registered owner, lock screen image), so it only runs on a CI runner
	if (-not $isAdmin -or $env:GITHUB_ACTIONS -ne 'true') {
		Write-Host '       Skipped: only runs elevated on a GitHub Actions runner (it changes the computer)' -ForegroundColor Yellow
		return
	}
	$ntKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
	$cspKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'
	$original = Get-ItemProperty $ntKey
	$searchKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search'
	$originalSearch = (Get-ItemProperty $searchKey -ErrorAction SilentlyContinue).SearchboxTaskbarMode
	try {
		$configuration = New-ABConfiguration
		foreach ($key in @($configuration.Tasks.Keys)) { $configuration.Tasks[$key].Enabled = $false }
		$configuration.Tasks['Set-ABRegisteredOwner'].Enabled = $true
		$configuration.Tasks['Set-ABRegisteredOwner'].Parameters.Owner = 'AB Runner Test'
		$configuration.Tasks['Set-ABRegisteredOwner'].Parameters.Organization = 'AB Test Org'
		$configuration.Tasks['Set-ABLockScreen'].Enabled = $true
		$configuration.Tasks['Set-ABLockScreen'].Parameters.ImagePath = Join-Path $project 'Assets\AutopilotLock.jpg'
		# A per-user task: applied to the signed-in (existing) profile running the test, like an APv2 user profile
		$configuration.Tasks['Set-ABSearchBoxMode'].Enabled = $true
		$configuration.Tasks['Set-ABSearchBoxMode'].Parameters.Mode = 'Hidden'
		$output = New-ABOutput -Configuration $configuration -BasePath $project -OutputPath (Join-Path $temp 'RunnerOutput') -Force
		$log = & $psExe -NoProfile -ExecutionPolicy Bypass -File $output.RunnerScript -Force 2>&1 | Out-String
		Assert-Equal 0 $LASTEXITCODE "Runner exit code (output: $log)"
		Assert-True ($log -match 'Succeeded\s+Set-ABRegisteredOwner') "Set-ABRegisteredOwner did not succeed: $log"
		Assert-True ($log -match 'Succeeded\s+Set-ABLockScreen') "Set-ABLockScreen did not succeed: $log"
		Assert-True ($log -match 'Succeeded\s+Set-ABSearchBoxMode') "Set-ABSearchBoxMode did not succeed: $log"
		$now = Get-ItemProperty $ntKey
		Assert-Equal 'AB Runner Test' $now.RegisteredOwner 'RegisteredOwner'
		Assert-Equal 'AB Test Org' $now.RegisteredOrganization 'RegisteredOrganization'
		$lockImage = (Get-ItemProperty $cspKey).LockScreenImagePath
		Assert-Equal "$($env:SystemRoot)\Web\Wallpaper\Autopilot\AutopilotLock.jpg" $lockImage 'Lock screen image (copied from the package Assets)'
		Assert-True (Test-Path $lockImage) 'Lock screen image not copied'
		Assert-Equal 0 (Get-ItemProperty $searchKey).SearchboxTaskbarMode 'Search box mode not set in the existing (signed-in) profile'
		Assert-True ($log -match 'Existing user profile') "Existing profiles not logged: $log"
	}
	finally {
		Set-ItemProperty $ntKey -Name RegisteredOwner -Value ([string]$original.RegisteredOwner)
		Set-ItemProperty $ntKey -Name RegisteredOrganization -Value ([string]$original.RegisteredOrganization)
		Remove-ItemProperty $cspKey -Name LockScreenImagePath, LockScreenImageUrl, LockScreenImageStatus -ErrorAction SilentlyContinue
		if ($null -ne $originalSearch) { Set-ItemProperty $searchKey -Name SearchboxTaskbarMode -Value $originalSearch }
		else { Remove-ItemProperty $searchKey -Name SearchboxTaskbarMode -ErrorAction SilentlyContinue }
		Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name SetSearchIconOnly -ErrorAction SilentlyContinue
	}
}

#endregion


#region Builder UI

Test-Case 'Builder UI loads and its controls update the configuration' {
	Assert-True ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA') 'Not running in an STA thread'
	$uiConfig = Join-Path $temp 'ui\AutopilotBranding.json'
	New-Item -Path (Split-Path $uiConfig) -ItemType Directory -Force | Out-Null
	# Files outside the project for the Browse / copy-to-Assets tests
	$uiExternal = Join-Path $temp 'ui external'
	New-Item -Path (Join-Path $uiExternal 'UEV Templates') -ItemType Directory -Force | Out-Null
	Set-Content -Path (Join-Path $uiExternal 'New Wallpaper.jpg') -Value 'new wallpaper'
	Set-Content -Path (Join-Path $uiExternal 'Autopilot.jpg') -Value 'a different Autopilot.jpg'
	Set-Content -Path (Join-Path $uiExternal 'Other.jpg') -Value 'other'
	Set-Content -Path (Join-Path $uiExternal 'UEV Templates\Custom.xml') -Value '<custom/>'

	& $module {
		param ($SavePath, $TaskNames, $ProjectConfig, $ExternalDir)
		$ErrorActionPreference = 'Stop'

		function Get-Descendants($Element) {
			foreach ($child in [System.Windows.LogicalTreeHelper]::GetChildren($Element)) {
				if ($child -is [System.Windows.DependencyObject]) { $child; Get-Descendants $child }
			}
		}
		function Find-Editor([string] $Parameter) {
			foreach ($element in (Get-Descendants $ui.DetailPanel)) {
				if ($element.Tag -is [hashtable] -and $element.Tag.Parameter -and $element.Tag.Parameter.Name -eq $Parameter -and
					$element -isnot [System.Windows.Controls.Button]) {
					return $element
				}
			}
			throw "Editor for -$Parameter not found"
		}
		function Select-Task([string] $Name) {
			$item = $ui.TaskList.Items | Where-Object { $_.Tag -eq $Name }
			$ui.TaskList.SelectedItem = $item
			if ($ui.DetailPanel.Children[0].Text -ne $Name) { throw "Details not shown for $Name" }
		}
		function Click($Element) {
			$Element.RaiseEvent((New-Object System.Windows.RoutedEventArgs ([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
		}

		$script:ABUISuppressDialogs = $true
		try {
			# No configuration: the default template is loaded, unsaved
			Initialize-ABBuilderWindow -ConfigPath '' -OutputPath ''

			if ($ui.TaskList.Items.Count -ne $TaskNames.Count) { throw "Task list has $($ui.TaskList.Items.Count) items" }
			if ($State.ConfigPath) { throw 'Expected the unsaved default template' }
			if (-not $State.Configuration.Tasks['Set-ABTheme'].Enabled) { throw 'Default template not loaded' }
			if ($ui.OutputPathBox.Text) { throw 'Output folder set for an unsaved configuration' }

			# Every task's details render (editors for every parameter type)
			foreach ($name in $TaskNames) { Select-Task $name }

			# Text box
			Select-Task 'Set-ABRegisteredOwner'
			(Find-Editor 'Owner').Text = 'Test Owner'
			if ($State.Configuration.Tasks['Set-ABRegisteredOwner'].Parameters.Owner -ne 'Test Owner') { throw 'Text box edit not applied' }
			if (-not $State.Dirty) { throw 'Not marked dirty' }

			# Multi-line list
			Select-Task 'Remove-ABProvisionedApps'
			(Find-Editor 'AppNames').Text = "App.One`r`n`r`n  App.Two  "
			if (($State.Configuration.Tasks['Remove-ABProvisionedApps'].Parameters.AppNames -join '|') -ne 'App.One|App.Two') { throw 'List edit not applied' }

			# Drop-down list
			Select-Task 'Set-ABSearchBoxMode'
			(Find-Editor 'Mode').SelectedItem = 'Hidden'
			if ($State.Configuration.Tasks['Set-ABSearchBoxMode'].Parameters.Mode -ne 'Hidden') { throw 'Drop-down edit not applied' }

			# Check box parameter
			Select-Task 'Disable-ABDesktopSpotlight'
			$checkBox = Find-Editor 'HideLearnAboutThisPicture'
			$checkBox.IsChecked = $false
			Click $checkBox
			if ($State.Configuration.Tasks['Disable-ABDesktopSpotlight'].Parameters.HideLearnAboutThisPicture -ne $false) { throw 'Check box edit not applied' }

			# Integer parameter
			Select-Task 'Set-ABLanguageSettings'
			(Find-Editor 'GeoId').Text = '244'
			if ($State.Configuration.Tasks['Set-ABLanguageSettings'].Parameters.GeoId -ne 244) { throw 'Integer edit not applied' }

			# Task check box in the list, and the details check box follows it
			Select-Task 'Set-ABStartAlignment'
			$listCheckBox = $State.ListCheckBoxes['Set-ABStartAlignment']
			$listCheckBox.IsChecked = $true
			Click $listCheckBox
			if (-not $State.Configuration.Tasks['Set-ABStartAlignment'].Enabled) { throw 'Task check box not applied' }
			if (-not $State.DetailEnabledCheckBox.IsChecked) { throw 'Details check box not updated' }

			# None / All buttons
			Click $ui.NoneButton
			if (@($State.Configuration.Tasks.Values | Where-Object { $_.Enabled }).Count -ne 0) { throw 'None button did not disable all tasks' }
			Click $ui.AllButton
			if (@($State.Configuration.Tasks.Values | Where-Object { -not $_.Enabled }).Count -ne 0) { throw 'All button did not enable all tasks' }

			# Saving into the module's template folder is refused
			$refused = $false
			try { Save-Configuration -Path (Join-Path (Get-ABTemplatePath) 'Test.json') | Out-Null } catch { $refused = $true }
			if (-not $refused) { throw 'Saving into the template folder was not refused' }

			# Saving the template elsewhere creates a project: the template files it uses are copied there
			if (-not (Save-Configuration -Path $SavePath)) { throw 'Save failed' }
			foreach ($relative in 'Assets\Autopilot.jpg', 'Assets\start2.bin', 'Assets\UEV\MicrosoftOffice2016Win64.xml', 'Assets\LPs\readme.txt') {
				if (-not (Test-Path (Join-Path (Split-Path $SavePath) $relative))) { throw "$relative was not copied into the project" }
			}
			if ($ui.OutputPathBox.Text -ne (Join-Path (Split-Path $SavePath) 'Output')) { throw "Output folder not set to the project's: $($ui.OutputPathBox.Text)" }
			if ($State.ConfigPath -ne $SavePath) { throw 'Configuration path not updated after saving' }
			if ($State.Dirty) { throw 'Still dirty after saving' }
			$saved = Read-ABConfiguration -Path $SavePath
			if ($saved.Tasks['Set-ABRegisteredOwner'].Parameters.Owner -ne 'Test Owner') { throw 'Saved value missing' }
			$problems = @(Test-ABConfiguration -Configuration $saved -BasePath (Split-Path $SavePath))
			if ($problems.Count -gt 0) { throw "Saved configuration has problems: $(($problems | ForEach-Object { "$($_.Task) -$($_.Parameter): $($_.Message)" }) -join '; ')" }
			if (@($saved.Tasks.Values | Where-Object { $_.Parameters.Values | Where-Object { $_ -is [string] -and $_ -like '*\Template\*' } }).Count -gt 0) {
				throw 'Saved configuration still points into the module template'
			}

			# Browsing to a file outside the project's Assets folder offers to copy it there
			$projectDir = Split-Path $SavePath
			Select-Task 'Set-ABTheme'
			$wallpaperBox = Find-Editor 'WallpaperPath'
			$wallpaperDefinition = $wallpaperBox.Tag.Parameter
			$script:ABUIDialogLog.Clear()

			$script:ABUIDialogAnswers.Enqueue('Yes')
			Set-AssetFromSelection -TextBox $wallpaperBox -Definition $wallpaperDefinition -SelectedPath (Join-Path $ExternalDir 'New Wallpaper.jpg')
			if ($wallpaperBox.Text -ne 'Assets\New Wallpaper.jpg') { throw "Copy (Yes): unexpected path $($wallpaperBox.Text)" }
			if (-not (Test-Path (Join-Path $projectDir 'Assets\New Wallpaper.jpg'))) { throw 'Copy (Yes): file not copied into Assets' }
			if ($State.Configuration.Tasks['Set-ABTheme'].Parameters.WallpaperPath -ne 'Assets\New Wallpaper.jpg') { throw 'Copy (Yes): configuration not updated' }

			# A file already in Assets is used without asking
			$prompts = $script:ABUIDialogLog.Count
			Set-AssetFromSelection -TextBox $wallpaperBox -Definition $wallpaperDefinition -SelectedPath (Join-Path $projectDir 'Assets\AutopilotLock.jpg')
			if ($script:ABUIDialogLog.Count -ne $prompts) { throw 'Prompted for a file that is already in Assets' }
			if ($wallpaperBox.Text -ne 'Assets\AutopilotLock.jpg') { throw "In Assets: unexpected path $($wallpaperBox.Text)" }

			# Same name, different content: declining the replace leaves the parameter and the file unchanged
			$originalHash = (Get-FileHash (Join-Path $projectDir 'Assets\Autopilot.jpg')).Hash
			$script:ABUIDialogAnswers.Enqueue('Yes'); $script:ABUIDialogAnswers.Enqueue('No')
			Set-AssetFromSelection -TextBox $wallpaperBox -Definition $wallpaperDefinition -SelectedPath (Join-Path $ExternalDir 'Autopilot.jpg')
			if ($script:ABUIDialogLog[-1] -notmatch '^Replace file in Assets') { throw 'No replace confirmation' }
			if ($wallpaperBox.Text -ne 'Assets\AutopilotLock.jpg') { throw 'Declined replace changed the parameter' }
			if ((Get-FileHash (Join-Path $projectDir 'Assets\Autopilot.jpg')).Hash -ne $originalHash) { throw 'Declined replace changed the file' }

			# ... confirming it replaces the file
			$script:ABUIDialogAnswers.Enqueue('Yes'); $script:ABUIDialogAnswers.Enqueue('Yes')
			Set-AssetFromSelection -TextBox $wallpaperBox -Definition $wallpaperDefinition -SelectedPath (Join-Path $ExternalDir 'Autopilot.jpg')
			if ($wallpaperBox.Text -ne 'Assets\Autopilot.jpg') { throw 'Confirmed replace: parameter not set' }
			if ((Get-FileHash (Join-Path $projectDir 'Assets\Autopilot.jpg')).Hash -ne (Get-FileHash (Join-Path $ExternalDir 'Autopilot.jpg')).Hash) { throw 'Confirmed replace: file not replaced' }

			# No: use the file where it is;  Cancel: leave the parameter unchanged
			$script:ABUIDialogAnswers.Enqueue('No')
			Set-AssetFromSelection -TextBox $wallpaperBox -Definition $wallpaperDefinition -SelectedPath (Join-Path $ExternalDir 'Other.jpg')
			if ($wallpaperBox.Text -ne (Join-Path $ExternalDir 'Other.jpg')) { throw "No: unexpected path $($wallpaperBox.Text)" }
			if (Test-Path (Join-Path $projectDir 'Assets\Other.jpg')) { throw 'No: file was copied' }
			$script:ABUIDialogAnswers.Enqueue('Cancel')
			Set-AssetFromSelection -TextBox $wallpaperBox -Definition $wallpaperDefinition -SelectedPath (Join-Path $ExternalDir 'New Wallpaper.jpg')
			if ($wallpaperBox.Text -ne (Join-Path $ExternalDir 'Other.jpg')) { throw 'Cancel changed the parameter' }

			# Folders are copied too
			Select-Task 'Enable-ABUEV'
			$folderBox = Find-Editor 'TemplateFolder'
			$script:ABUIDialogAnswers.Enqueue('Yes')
			Set-AssetFromSelection -TextBox $folderBox -Definition $folderBox.Tag.Parameter -SelectedPath (Join-Path $ExternalDir 'UEV Templates')
			if ($folderBox.Text -ne 'Assets\UEV Templates') { throw "Folder copy: unexpected path $($folderBox.Text)" }
			if (-not (Test-Path (Join-Path $projectDir 'Assets\UEV Templates\Custom.xml'))) { throw 'Folder copy: folder not copied' }
			if ($script:ABUIDialogAnswers.Count -ne 0) { throw "Unused dialog answers: $($script:ABUIDialogAnswers.Count)" }

			# Opening a project sets the output folder to the project's
			Set-Configuration -Configuration (Read-ABConfiguration -Path $ProjectConfig -TaskDefinitions $State.Definitions) -Path $ProjectConfig
			if ($ui.OutputPathBox.Text -ne (Join-Path (Split-Path $ProjectConfig) 'Output')) { throw 'Output folder not set when opening a project' }
		}
		finally {
			$script:ABUISuppressDialogs = $false
			$script:ABUIDialogAnswers.Clear()
			if ($State) { $State.Dirty = $false }
			if ($window) { $window.Close() }
			$script:window = $null
			$script:ui = $null
			$script:State = $null
		}
	} $uiConfig $taskNames (Join-Path $project 'AutopilotBranding.json') $uiExternal
}

Test-Case 'Show-AutopilotBrandingBuilder has the expected parameters' {
	$cmd = Get-Command Show-AutopilotBrandingBuilder
	Assert-True ($cmd.Parameters.ContainsKey('ConfigPath') -and $cmd.Parameters.ContainsKey('OutputPath')) 'Parameters missing'
}

#endregion


#region Command scripts

if (-not $SkipCmd) {
	Test-Case 'makeapp.cmd creates and builds the default Project folder with this PowerShell version' {
		$package = Join-Path $repoRoot 'Project\AutopilotBranding.intunewin'
		Remove-Item $package -Force -ErrorAction SilentlyContinue
		$env:AB_POWERSHELL = $psExe
		try {
			$output = & cmd.exe /c "`"$(Join-Path $repoRoot 'makeapp.cmd')`"" 2>&1 | Out-String
			$exitCode = $LASTEXITCODE
		}
		finally {
			Remove-Item Env:\AB_POWERSHELL -ErrorAction SilentlyContinue
		}
		Assert-Equal 0 $exitCode "makeapp.cmd exit code (output: $output)"
		Assert-True (Test-Path $package) "Package not created (output: $output)"
		Assert-True (Test-Path (Join-Path $repoRoot 'Project\AutopilotBranding.json')) 'Project not created'
		Assert-True (Test-Path (Join-Path $repoRoot 'Project\Output\AutopilotBranding.ps1')) 'Output not created'
	}

	Test-Case 'ShowBuilder.cmd starts the builder UI with this PowerShell version' {
		$env:AB_POWERSHELL = $psExe
		try {
			$stdout = Join-Path $temp 'showbuilder.out.txt'
			$stderr = Join-Path $temp 'showbuilder.err.txt'
			$proc = Start-Process -FilePath cmd.exe -ArgumentList '/c', "`"$(Join-Path $repoRoot 'ShowBuilder.cmd')`"" -PassThru `
				-RedirectStandardOutput $stdout -RedirectStandardError $stderr
		}
		finally {
			Remove-Item Env:\AB_POWERSHELL -ErrorAction SilentlyContinue
		}
		# The UI keeps running until it is closed; if it exits within a few seconds, something went wrong
		$exited = $proc.WaitForExit(20000)
		if (-not $exited) {
			& taskkill.exe /T /F /PID $proc.Id 2>&1 | Out-Null
		}
		$text = (Get-Content $stdout, $stderr -Raw -ErrorAction SilentlyContinue) -join "`n"
		Assert-True (-not $exited) "ShowBuilder.cmd exited (code $($proc.ExitCode)): $text"
	}
}

#endregion


Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
Write-Host "PowerShell $($PSVersionTable.PSVersion): $($script:passed) passed, $($script:failed.Count) failed"
if ($script:failed.Count -gt 0) {
	Write-Host "Failed: $($script:failed -join ', ')" -ForegroundColor Red
	exit 1
}
exit 0

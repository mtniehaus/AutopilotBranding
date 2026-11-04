<#
.SYNOPSIS
Automated tests for the AutopilotBranding module, builder, builder UI, generated runner script and .cmd launchers.

.DESCRIPTION
Run this with each PowerShell version to verify, for example:
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Tests\Test-AutopilotBranding.ps1
  pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Tests\Test-AutopilotBranding.ps1

The tests run on Windows.  They create the Output folder and AutopilotBranding.intunewin in the repository folder
(via makeapp.cmd) and a temporary folder, install the SvRooij.ContentPrep.Cmdlet module for the current user if
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
$defaultConfig = Join-Path $repoRoot 'AutopilotBranding.json'
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
		Where-Object { $_.FullName -notlike (Join-Path $repoRoot 'Output\*') }
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

$taskFiles = @(Get-ChildItem (Join-Path $repoRoot 'Module\AutopilotBranding\Tasks') -Filter *.ps1 | Sort-Object Name)
$taskNames = @($taskFiles | ForEach-Object { $_.BaseName -replace '^\d+-', '' })

Test-Case 'Exports the cmdlets, tasks and builder functions, and nothing private' {
	$exported = @((Get-Command -Module AutopilotBranding).Name)
	$expected = @('Show-AutopilotBrandingBuilder', 'Build-AutopilotBranding', 'Start-AutopilotBranding', 'Stop-AutopilotBranding',
		'Invoke-ABTask', 'Write-ABLog', 'Mount-ABDefaultUserHive', 'Dismount-ABDefaultUserHive', 'Get-ABTaskDefinition',
		'Read-ABConfiguration', 'Save-ABConfiguration', 'Test-ABConfiguration', 'New-ABOutput', 'New-ABIntuneWinPackage',
		'ConvertFrom-ABLegacyConfig') + $taskNames
	$missing = @($expected | Where-Object { $exported -notcontains $_ })
	Assert-True ($missing.Count -eq 0) "Not exported: $($missing -join ', ')"
	$private = @('Get-Value', 'Get-List', 'Get-File', 'Invoke-ABHiveUnload', 'Show-ABUIMessage', 'Initialize-ABBuilderWindow',
		'ConvertTo-ABFullPath', 'Test-ABArm64', 'Set-ABRegistryValue', 'Get-ABAstValue', 'Show-TaskDetail', 'Invoke-Safely')
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
	$problems = @(Test-ABConfiguration -Configuration $configuration -BasePath $repoRoot)
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

Test-Case 'Runner script only passes non-default values and parses' {
	$configuration = Read-ABConfiguration -Path $defaultConfig
	$configuration.Tasks['Set-ABTimeZone'].Parameters.TimeZone = "O'Brien Standard Time"
	$runner = Get-ABRunnerScript -Configuration $configuration -TaskDefinitions @(Get-ABTaskDefinition) -AssetMap @{ 'Set-ABTheme|ThemePath' = 'Autopilot.theme' }
	$errors = $null
	[System.Management.Automation.Language.Parser]::ParseInput($runner, [ref]$null, [ref]$errors) | Out-Null
	Assert-True ($errors.Count -eq 0) "Runner parse errors: $($errors[0].Message)"
	Assert-True ($runner -match "Invoke-ABTask -Name 'Set-ABTheme'") 'Set-ABTheme not called'
	Assert-True ($runner -notmatch "Invoke-ABTask -Name 'Set-ABStartAlignment'") 'Disabled task called'
	Assert-True ($runner -match "TimeZone = 'O''Brien Standard Time'") 'Quoted string value not emitted'
	Assert-True ($runner -match "ThemePath = \(Join-Path \`$AssetRoot 'Autopilot.theme'\)") 'Asset path not emitted'
	Assert-True ($runner -notmatch 'UpdateThemeWallpaper') 'Default value emitted'
}

$build = $null
Test-Case 'Build-AutopilotBranding creates the output folder and .intunewin package' {
	$script:build = Build-AutopilotBranding -ConfigPath $defaultConfig -OutputPath (Join-Path $temp 'Output') -PassThru 6>$null
	foreach ($relative in 'AutopilotBranding.ps1', 'AutopilotBranding.json', 'AutopilotBranding\AutopilotBranding.psd1',
		'AutopilotBranding\Tasks\030-Set-ABTheme.ps1', 'Assets\Autopilot.theme', 'Assets\start2.bin', 'Assets\LPs') {
		Assert-True (Test-Path (Join-Path $script:build.OutputPath $relative)) "Missing $relative"
	}
	Assert-Equal (Join-Path $temp 'AutopilotBranding.intunewin') $script:build.Package 'Package path'
	Assert-True ((Get-Item $script:build.Package).Length -gt 10000) 'Package is too small'
	$errors = $null
	[System.Management.Automation.Language.Parser]::ParseFile($script:build.RunnerScript, [ref]$null, [ref]$errors) | Out-Null
	Assert-True ($errors.Count -eq 0) "Runner parse errors: $($errors[0].Message)"
	$problems = @(Test-ABConfiguration -Configuration (Read-ABConfiguration -Path (Join-Path $script:build.OutputPath 'AutopilotBranding.json')) -BasePath $script:build.OutputPath)
	Assert-True ($problems.Count -eq 0) 'Output configuration does not validate against the copied assets'
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

#endregion


#region Builder UI

Test-Case 'Builder UI loads and its controls update the configuration' {
	Assert-True ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA') 'Not running in an STA thread'
	$uiConfig = Join-Path $temp 'ui\AutopilotBranding.json'
	New-Item -Path (Split-Path $uiConfig) -ItemType Directory -Force | Out-Null

	& $module {
		param ($ConfigPath, $SavePath, $TaskNames)
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
			Initialize-ABBuilderWindow -ConfigPath $ConfigPath -OutputPath (Join-Path (Split-Path $SavePath) 'Output')

			if ($ui.TaskList.Items.Count -ne $TaskNames.Count) { throw "Task list has $($ui.TaskList.Items.Count) items" }
			if ($State.ConfigPath -ne $ConfigPath) { throw 'Configuration not loaded' }

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

			# Save to another folder: file paths are rebased so they still point at the same files
			if (-not (Save-Configuration -Path $SavePath)) { throw 'Save failed' }
			if ($State.ConfigPath -ne $SavePath) { throw 'Configuration path not updated after saving' }
			if ($State.Dirty) { throw 'Still dirty after saving' }
			$saved = Read-ABConfiguration -Path $SavePath
			if ($saved.Tasks['Set-ABRegisteredOwner'].Parameters.Owner -ne 'Test Owner') { throw 'Saved value missing' }
			$problems = @(Test-ABConfiguration -Configuration $saved -BasePath (Split-Path $SavePath))
			if ($problems.Count -gt 0) { throw "Saved configuration has problems: $(($problems | ForEach-Object { "$($_.Task) -$($_.Parameter): $($_.Message)" }) -join '; ')" }
		}
		finally {
			$script:ABUISuppressDialogs = $false
			if ($State) { $State.Dirty = $false }
			if ($window) { $window.Close() }
			$script:window = $null
			$script:ui = $null
			$script:State = $null
		}
	} $defaultConfig $uiConfig $taskNames
}

Test-Case 'Show-AutopilotBrandingBuilder has the expected parameters' {
	$cmd = Get-Command Show-AutopilotBrandingBuilder
	Assert-True ($cmd.Parameters.ContainsKey('ConfigPath') -and $cmd.Parameters.ContainsKey('OutputPath')) 'Parameters missing'
}

#endregion


#region Command scripts

if (-not $SkipCmd) {
	Test-Case 'makeapp.cmd builds Output and AutopilotBranding.intunewin with this PowerShell version' {
		$package = Join-Path $repoRoot 'AutopilotBranding.intunewin'
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
		Assert-True (Test-Path (Join-Path $repoRoot 'Output\AutopilotBranding.ps1')) 'Output not created'
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

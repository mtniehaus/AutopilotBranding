# Builder functions: used by Show-AutopilotBrandingBuilder (UI) and New-AutopilotBrandingPackage (headless) to
#   - discover the configuration tasks (cmdlets) and their parameters from the module's Tasks folder
#   - load, complete, validate and save JSON configuration files
#   - convert a legacy (v3) Config.xml file into a JSON configuration
#   - generate an output folder containing the module, the assets, and a runner script (AutopilotBranding.ps1)
#   - package the output folder as an Intune Win32 app (.intunewin)
#
# Parameter conventions used by the builder:
#   - Parameters whose name ends in "Path" are local files and parameters whose name ends in "Folder" are local
#     folders.  They are copied into the Assets folder of the output and passed to the cmdlet using a path relative
#     to the runner script.  Relative paths in the JSON file are relative to the JSON file's folder.
#   - [string[]] parameters are edited one value per line.
#   - [bool] and [switch] parameters are shown as check boxes; [ValidateSet()] parameters as drop-down lists.

$script:ConfigurationVersion = 1

function Get-ABDefaultModulePath {
	<#
	.SYNOPSIS
	Returns the folder of the loaded AutopilotBranding module (the module that is copied into the output).
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param ()

	$script:ABModuleRoot
}


function Get-ABDefaultConfigurationPath {
	<#
	.SYNOPSIS
	Returns the path of the default configuration file: AutopilotBranding.json in the current folder.
	.DESCRIPTION
	The file doesn't need to exist.  Create a project (configuration plus assets) with New-AutopilotBrandingProject.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param ()

	Join-Path (Get-Location).ProviderPath 'AutopilotBranding.json'
}


function Get-ABTemplatePath {
	<#
	.SYNOPSIS
	Returns the folder of the default project template included in the module.
	.DESCRIPTION
	The template contains the default configuration (AutopilotBranding.json) and the sample files it uses (Assets).
	New-AutopilotBrandingProject copies it to a project folder; don't edit the template itself.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param ()

	Join-Path $script:ABModuleRoot 'Template'
}


function Get-ABTaskDefinition {
	<#
	.SYNOPSIS
	Returns the configuration tasks (cmdlets) of the AutopilotBranding module and their parameters, in run order.
	.DESCRIPTION
	The task files (Tasks\<order>-<CmdletName>.ps1) are parsed - the module doesn't need to be imported - and the
	comment-based help and param() block of each cmdlet are used to describe the task and its parameters.
	.PARAMETER ModulePath
	Folder containing the AutopilotBranding module source.
	.PARAMETER Name
	Only return the task(s) with these names.
	#>
	[CmdletBinding()]
	param (
		[string] $ModulePath = (Get-ABDefaultModulePath),
		[string[]] $Name
	)

	$taskFolder = Join-Path $ModulePath 'Tasks'
	if (-not (Test-Path $taskFolder)) {
		throw "Task folder not found: $taskFolder"
	}

	foreach ($file in (Get-ChildItem -Path $taskFolder -Filter '*.ps1' | Sort-Object Name)) {
		$order = 0
		$functionName = $file.BaseName
		if ($file.BaseName -match '^(\d+)-(.+)$') {
			$order = [int]$Matches[1]
			$functionName = $Matches[2]
		}
		if ($Name -and $Name -notcontains $functionName) {
			continue
		}

		$tokens = $null
		$errors = $null
		$ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
		if ($errors -and $errors.Count -gt 0) {
			Write-Warning "Parse errors in $($file.Name): $($errors[0].Message)"
		}
		$function = $ast.Find({
				param($node)
				$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
			}, $true)
		if (-not $function) {
			Write-Warning "Function $functionName not found in $($file.Name), skipping"
			continue
		}

		$help = $function.GetHelpContent()
		$synopsis = ''
		$description = ''
		$parameterHelp = @{}
		if ($help) {
			if ($help.Synopsis) { $synopsis = ($help.Synopsis.Trim() -replace '\s*\r?\n\s*', ' ') }
			if ($help.Description) { $description = ($help.Description.Trim() -replace '\s*\r?\n\s*', ' ') }
			foreach ($key in $help.Parameters.Keys) {
				$parameterHelp[$key.ToUpperInvariant()] = ($help.Parameters[$key].Trim() -replace '\s*\r?\n\s*', ' ')
			}
		}

		$parameters = New-Object System.Collections.Generic.List[object]
		$paramBlock = $function.Body.ParamBlock
		if ($paramBlock) {
			foreach ($p in $paramBlock.Parameters) {
				$paramName = $p.Name.VariablePath.UserPath
				$mandatory = $false
				$validateSet = $null
				foreach ($attribute in $p.Attributes) {
					if ($attribute -isnot [System.Management.Automation.Language.AttributeAst]) {
						continue
					}
					switch ($attribute.TypeName.Name) {
						'Parameter' {
							foreach ($named in $attribute.NamedArguments) {
								if ($named.ArgumentName -eq 'Mandatory') {
									$mandatory = $named.ExpressionOmitted -or [bool](Get-ABAstValue $named.Argument)
								}
							}
						}
						'ValidateSet' {
							$validateSet = @($attribute.PositionalArguments | ForEach-Object { [string](Get-ABAstValue $_) })
						}
					}
				}

				$staticType = $p.StaticType
				if ($staticType -eq [switch]) { $kind = 'Switch' }
				elseif ($staticType -eq [bool]) { $kind = 'Boolean' }
				elseif ($staticType -eq [string[]]) { $kind = 'StringArray' }
				elseif ($staticType -eq [int] -or $staticType -eq [long]) { $kind = 'Integer' }
				else { $kind = 'String' }

				$assetKind = $null
				if ($kind -eq 'String') {
					if ($paramName -like '*Path') { $assetKind = 'File' }
					elseif ($paramName -like '*Folder') { $assetKind = 'Folder' }
				}

				switch ($kind) {
					'Switch' { $default = $false }
					'Boolean' {
						$default = Get-ABAstValue $p.DefaultValue
						if ($null -eq $default) { $default = $false }
						$default = [bool]$default
					}
					'StringArray' {
						$default = Get-ABAstValue $p.DefaultValue
						if ($null -eq $default) { $default = @() } else { $default = [string[]]@($default) }
					}
					'Integer' {
						$default = Get-ABAstValue $p.DefaultValue
						if ($null -ne $default) { $default = [int]$default }
					}
					default {
						$default = Get-ABAstValue $p.DefaultValue
						if ($null -eq $default) { $default = '' }
						$default = [string]$default
					}
				}

				$helpText = ''
				if ($parameterHelp.ContainsKey($paramName.ToUpperInvariant())) {
					$helpText = $parameterHelp[$paramName.ToUpperInvariant()]
				}

				$parameters.Add([pscustomobject]@{
						Name         = $paramName
						Kind         = $kind
						TypeName     = $staticType.Name
						Mandatory    = [bool]$mandatory
						ValidateSet  = $validateSet
						DefaultValue = $default
						AssetKind    = $assetKind
						HelpText     = $helpText
					})
			}
		}

		[pscustomobject]@{
			Name        = $functionName
			Order       = $order
			FileName    = $file.Name
			Synopsis    = $synopsis
			Description = $description
			Parameters  = $parameters.ToArray()
		}
	}
}


function ConvertTo-ABParameterValue {
	<#
	.SYNOPSIS
	Coerces a configuration value to the type expected by a task parameter.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] $Definition,
		[AllowNull()] $Value
	)

	switch ($Definition.Kind) {
		{ $_ -in 'Switch', 'Boolean' } {
			if ($null -eq $Value) { return [bool]$Definition.DefaultValue }
			if ($Value -is [string]) { return ($Value -eq 'true' -or $Value -eq '1' -or $Value -eq '$true') }
			return [bool]$Value
		}
		'StringArray' {
			if ($null -eq $Value) { return , [string[]]@() }
			$items = @(foreach ($item in @($Value)) {
					if ($null -ne $item) {
						foreach ($line in ("$item" -split '\r?\n')) { $line.Trim() }
					}
				}) | Where-Object { $_ -ne '' }
			$items = @($items)
			return , [string[]]$items
		}
		'Integer' {
			if ($null -eq $Value -or "$Value" -eq '') { return $null }
			return [int]$Value
		}
		default {
			if ($null -eq $Value) { return '' }
			return [string]$Value
		}
	}
}


function New-ABConfiguration {
	<#
	.SYNOPSIS
	Creates a new configuration with every task enabled and every parameter set to its default value.
	#>
	[CmdletBinding()]
	param (
		[object[]] $TaskDefinitions = @(Get-ABTaskDefinition)
	)

	$configuration = [ordered]@{
		Version     = $script:ConfigurationVersion
		Description = 'Autopilot Branding configuration'
		Tasks       = [ordered]@{}
	}
	foreach ($task in $TaskDefinitions) {
		$configuration.Tasks[$task.Name] = [ordered]@{ Enabled = $true; Parameters = [ordered]@{} }
	}
	Complete-ABConfiguration -Configuration $configuration -TaskDefinitions $TaskDefinitions
}


function Complete-ABConfiguration {
	<#
	.SYNOPSIS
	Makes sure a configuration contains an entry for every task and a value for every parameter.
	.DESCRIPTION
	Tasks that aren't in the configuration (e.g. tasks added in a newer version of the module) are added disabled.
	Parameters without a value get their default value.  Values are coerced to the parameter types.  Tasks and
	parameters that are unknown are kept (and reported by Test-ABConfiguration).  The tasks are reordered to match
	the module's run order.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Configuration,
		[object[]] $TaskDefinitions = @(Get-ABTaskDefinition)
	)

	if (-not $Configuration.Contains('Version')) { $Configuration['Version'] = $script:ConfigurationVersion }
	if (-not $Configuration.Contains('Tasks') -or $null -eq $Configuration['Tasks']) { $Configuration['Tasks'] = [ordered]@{} }
	$existing = $Configuration['Tasks']

	$tasks = [ordered]@{}
	foreach ($definition in $TaskDefinitions) {
		if ($existing.Contains($definition.Name) -and $null -ne $existing[$definition.Name]) {
			$entry = $existing[$definition.Name]
		} else {
			$entry = [ordered]@{ Enabled = $false; Parameters = [ordered]@{} }
		}
		if (-not $entry.Contains('Enabled')) { $entry['Enabled'] = $true }
		$entry['Enabled'] = [bool]$entry['Enabled']
		if (-not $entry.Contains('Parameters') -or $null -eq $entry['Parameters']) { $entry['Parameters'] = [ordered]@{} }

		$parameters = [ordered]@{}
		foreach ($p in $definition.Parameters) {
			if ($entry['Parameters'].Contains($p.Name)) {
				$value = $entry['Parameters'][$p.Name]
			} else {
				$value = $p.DefaultValue
			}
			$parameters[$p.Name] = ConvertTo-ABParameterValue -Definition $p -Value $value
		}
		# Keep unknown parameters so nothing is silently lost
		foreach ($key in @($entry['Parameters'].Keys)) {
			if (-not $parameters.Contains($key)) {
				$parameters[$key] = $entry['Parameters'][$key]
			}
		}
		$entry['Parameters'] = $parameters
		$tasks[$definition.Name] = $entry
	}
	foreach ($key in @($existing.Keys)) {
		if (-not $tasks.Contains($key)) {
			$tasks[$key] = $existing[$key]
		}
	}
	$Configuration['Tasks'] = $tasks
	return $Configuration
}


function Read-ABConfiguration {
	<#
	.SYNOPSIS
	Reads a JSON configuration file and completes it with default values.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $Path,
		[object[]] $TaskDefinitions = @(Get-ABTaskDefinition)
	)

	$json = Get-Content -Path $Path -Raw -Encoding UTF8
	$configuration = ConvertTo-ABOrderedHashtable (ConvertFrom-Json -InputObject $json)
	if ($configuration -isnot [System.Collections.IDictionary]) {
		throw "Invalid configuration file: $Path"
	}
	Complete-ABConfiguration -Configuration $configuration -TaskDefinitions $TaskDefinitions
}


function Save-ABConfiguration {
	<#
	.SYNOPSIS
	Saves a configuration as a JSON file.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Configuration,
		[Parameter(Mandatory = $true)] [string] $Path
	)

	$folder = Split-Path -Path $Path -Parent
	if ($folder -and -not (Test-Path $folder)) {
		New-Item -Path $folder -ItemType Directory -Force | Out-Null
	}
	$json = ConvertTo-Json -InputObject $Configuration -Depth 10
	# Windows PowerShell 5.1 escapes some characters and uses wide indentation; both are valid JSON.
	$fullPath = ConvertTo-ABFullPath $Path
	[System.IO.File]::WriteAllText($fullPath, $json, (New-Object System.Text.UTF8Encoding($false)))
}


function Resolve-ABAssetPath {
	<#
	.SYNOPSIS
	Resolves a file or folder path from a configuration (relative paths are relative to BasePath).
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param (
		[Parameter(Mandatory = $true)] [string] $Path,
		[Parameter(Mandatory = $true)] [string] $BasePath
	)

	$expanded = [Environment]::ExpandEnvironmentVariables($Path)
	if ([System.IO.Path]::IsPathRooted($expanded)) {
		return ConvertTo-ABFullPath $expanded
	}
	return ConvertTo-ABFullPath (Join-Path $BasePath $expanded)
}


function Get-ABRelativePath {
	<#
	.SYNOPSIS
	Returns Path relative to BasePath if it is inside BasePath, otherwise the full path.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param (
		[Parameter(Mandatory = $true)] [string] $Path,
		[Parameter(Mandatory = $true)] [string] $BasePath
	)

	$full = ConvertTo-ABFullPath $Path
	$base = (ConvertTo-ABFullPath $BasePath).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
	if ($full.StartsWith($base, [System.StringComparison]::OrdinalIgnoreCase)) {
		return $full.Substring($base.Length)
	}
	return $full
}


function Test-ABConfiguration {
	<#
	.SYNOPSIS
	Validates a configuration and returns a list of problems (Severity = Error or Warning).
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Configuration,
		[Parameter(Mandatory = $true)] [string] $BasePath,
		[object[]] $TaskDefinitions = @(Get-ABTaskDefinition)
	)

	$definitions = @{}
	foreach ($d in $TaskDefinitions) { $definitions[$d.Name] = $d }

	foreach ($taskName in $Configuration.Tasks.Keys) {
		$entry = $Configuration.Tasks[$taskName]
		if (-not $definitions.ContainsKey($taskName)) {
			[pscustomobject]@{ Severity = 'Warning'; Task = $taskName; Parameter = $null; Message = 'Unknown task, it will be ignored.' }
			continue
		}
		if (-not $entry.Enabled) {
			continue
		}
		$definition = $definitions[$taskName]
		foreach ($key in $entry.Parameters.Keys) {
			if (-not ($definition.Parameters | Where-Object { $_.Name -eq $key })) {
				[pscustomobject]@{ Severity = 'Warning'; Task = $taskName; Parameter = $key; Message = 'Unknown parameter, it will be ignored.' }
			}
		}
		foreach ($p in $definition.Parameters) {
			$value = $entry.Parameters[$p.Name]
			$isEmpty = ($null -eq $value) -or ($value -is [string] -and $value.Trim() -eq '') -or ($value -is [array] -and $value.Count -eq 0)
			if ($p.Mandatory -and $isEmpty) {
				[pscustomobject]@{ Severity = 'Error'; Task = $taskName; Parameter = $p.Name; Message = 'A value is required.' }
				continue
			}
			if ($p.ValidateSet -and -not $isEmpty -and $p.ValidateSet -notcontains $value) {
				[pscustomobject]@{ Severity = 'Error'; Task = $taskName; Parameter = $p.Name; Message = "Value must be one of: $($p.ValidateSet -join ', ')" }
			}
			if ($p.AssetKind -and -not $isEmpty) {
				$resolved = Resolve-ABAssetPath -Path $value -BasePath $BasePath
				if ($p.AssetKind -eq 'File' -and -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
					[pscustomobject]@{ Severity = 'Error'; Task = $taskName; Parameter = $p.Name; Message = "File not found: $resolved" }
				} elseif ($p.AssetKind -eq 'Folder' -and -not (Test-Path -LiteralPath $resolved -PathType Container)) {
					[pscustomobject]@{ Severity = 'Error'; Task = $taskName; Parameter = $p.Name; Message = "Folder not found: $resolved" }
				}
			}
		}
	}
}


function ConvertTo-ABLiteral {
	<#
	.SYNOPSIS
	Converts a value into PowerShell source code.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param (
		[AllowNull()] $Value,
		[string] $Indent = ''
	)

	if ($null -eq $Value) { return '$null' }
	if ($Value -is [bool] -or $Value -is [switch]) { if ([bool]$Value) { return '$true' } else { return '$false' } }
	if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
		return ([System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture))
	}
	if ($Value -is [array]) {
		if ($Value.Count -eq 0) { return '@()' }
		if ($Value.Count -eq 1) { return "@($(ConvertTo-ABLiteral -Value $Value[0]))" }
		$lines = foreach ($item in $Value) { "$Indent`t$(ConvertTo-ABLiteral -Value $item)" }
		return "@(`r`n$($lines -join "`r`n")`r`n$Indent)"
	}
	return "'" + ([string]$Value).Replace("'", "''") + "'"
}


function Get-ABRunnerScript {
	<#
	.SYNOPSIS
	Returns the runner script (AutopilotBranding.ps1) that goes into every package.
	.DESCRIPTION
	The runner is the same for every configuration: it loads the module next to it and calls Invoke-AutopilotBranding
	with the AutopilotBranding.json next to it.  The configuration decides which tasks run with which parameters.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param ()

	[System.IO.File]::ReadAllText((Join-Path $script:ABModuleRoot 'Runner\AutopilotBranding.ps1'))
}


function New-ABOutput {
	<#
	.SYNOPSIS
	Generates an output folder containing the module, the assets, the configuration and the runner script.
	.DESCRIPTION
	The runner script is the same for every configuration (see Get-ABRunnerScript): on the device it runs the tasks in
	the packaged AutopilotBranding.json, whose file and folder parameters refer to the output's Assets folder.
	The output folder can be packaged as an Intune Win32 app with New-ABIntuneWinPackage; the install command is
	powershell.exe -noprofile -executionpolicy bypass -file .\AutopilotBranding.ps1
	.PARAMETER Configuration
	Configuration (see Read-ABConfiguration).
	.PARAMETER BasePath
	Folder that relative file and folder paths in the configuration are relative to (normally the JSON file's folder).
	.PARAMETER OutputPath
	Output folder.  It is emptied first if -Force is specified.
	.PARAMETER ModulePath
	AutopilotBranding module source folder.
	.PARAMETER RunnerName
	File name of the runner script.
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Configuration,
		[Parameter(Mandatory = $true)] [string] $BasePath,
		[Parameter(Mandatory = $true)] [string] $OutputPath,
		[string] $ModulePath = (Get-ABDefaultModulePath),
		[string] $RunnerName = 'AutopilotBranding.ps1',
		[switch] $Force
	)

	$definitions = @(Get-ABTaskDefinition -ModulePath $ModulePath)
	$Configuration = Complete-ABConfiguration -Configuration $Configuration -TaskDefinitions $definitions

	$problems = @(Test-ABConfiguration -Configuration $Configuration -BasePath $BasePath -TaskDefinitions $definitions)
	foreach ($warning in ($problems | Where-Object { $_.Severity -eq 'Warning' })) {
		Write-Warning "$($warning.Task) $($warning.Parameter): $($warning.Message)"
	}
	$errors = @($problems | Where-Object { $_.Severity -eq 'Error' })
	if ($errors.Count -gt 0) {
		$text = ($errors | ForEach-Object { "  $($_.Task) -$($_.Parameter): $($_.Message)" }) -join [Environment]::NewLine
		throw "The configuration has errors:$([Environment]::NewLine)$text"
	}

	$OutputPath = ConvertTo-ABFullPath $OutputPath
	if (Test-Path $OutputPath) {
		$existing = @(Get-ChildItem -Path $OutputPath -Force)
		if ($existing.Count -gt 0) {
			if (-not $Force) {
				throw "Output folder $OutputPath is not empty; specify -Force to replace its contents."
			}
			if ($PSCmdlet.ShouldProcess($OutputPath, 'Remove existing contents')) {
				$existing | Remove-Item -Recurse -Force
			}
		}
	} else {
		New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
	}

	# Copy the module
	$moduleDest = Join-Path $OutputPath 'AutopilotBranding'
	Copy-Item -Path $ModulePath -Destination $moduleDest -Recurse -Force
	# The project template (sample assets) isn't needed on the device
	$templateCopy = Join-Path $moduleDest 'Template'
	if (Test-Path -LiteralPath $templateCopy) {
		Remove-Item -LiteralPath $templateCopy -Recurse -Force
	}

	# Copy the assets used by enabled tasks
	$assetRoot = Join-Path $OutputPath 'Assets'
	New-Item -Path $assetRoot -ItemType Directory -Force | Out-Null
	$assetMap = [ordered]@{}
	$sourceToName = @{}
	$usedNames = @{}
	foreach ($definition in $definitions) {
		$entry = $Configuration.Tasks[$definition.Name]
		if (-not $entry.Enabled) {
			continue
		}
		foreach ($p in ($definition.Parameters | Where-Object { $_.AssetKind })) {
			$value = $entry.Parameters[$p.Name]
			if ([string]::IsNullOrWhiteSpace($value)) {
				continue
			}
			$source = Resolve-ABAssetPath -Path $value -BasePath $BasePath
			$sourceKey = $source.ToLowerInvariant()
			if (-not $sourceToName.ContainsKey($sourceKey)) {
				$leaf = Split-Path -Path $source -Leaf
				$name = $leaf
				$i = 2
				while ($usedNames.ContainsKey($name.ToLowerInvariant())) {
					$name = '{0}_{1}{2}' -f [System.IO.Path]::GetFileNameWithoutExtension($leaf), $i, [System.IO.Path]::GetExtension($leaf)
					$i++
				}
				$usedNames[$name.ToLowerInvariant()] = $true
				$sourceToName[$sourceKey] = $name
				$destination = Join-Path $assetRoot $name
				if ($p.AssetKind -eq 'Folder') {
					Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force
				} else {
					Copy-Item -LiteralPath $source -Destination $destination -Force
				}
			}
			$assetMap["$($definition.Name)|$($p.Name)"] = $sourceToName[$sourceKey]
		}
	}

	# Save the configuration used, with asset paths pointing at the copied files.  File and folder parameters of
	# disabled tasks are cleared: their files aren't in the package, and the package must not refer to anything outside it.
	$outputConfiguration = ConvertTo-ABOrderedHashtable (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Configuration -Depth 10))
	foreach ($definition in $definitions) {
		if (-not $outputConfiguration.Tasks.Contains($definition.Name)) {
			continue
		}
		foreach ($p in ($definition.Parameters | Where-Object { $_.AssetKind })) {
			$key = "$($definition.Name)|$($p.Name)"
			if ($assetMap.Contains($key)) {
				$outputConfiguration.Tasks[$definition.Name].Parameters[$p.Name] = "Assets\$($assetMap[$key])"
			} elseif ($outputConfiguration.Tasks[$definition.Name].Parameters.Contains($p.Name)) {
				$outputConfiguration.Tasks[$definition.Name].Parameters[$p.Name] = ''
			}
		}
	}
	Save-ABConfiguration -Configuration $outputConfiguration -Path (Join-Path $OutputPath 'AutopilotBranding.json')

	# The runner script (the same for every configuration)
	$runnerPath = Join-Path $OutputPath $RunnerName
	Copy-Item -LiteralPath (Join-Path $ModulePath 'Runner\AutopilotBranding.ps1') -Destination $runnerPath -Force

	# Make sure everything the package refers to is inside it
	$problems = @(Test-ABOutputSelfContained -OutputPath $OutputPath -RunnerName $RunnerName -TaskDefinitions $definitions)
	foreach ($warning in ($problems | Where-Object { $_.Severity -eq 'Warning' })) {
		Write-Warning $warning.Message
	}
	$errors = @($problems | Where-Object { $_.Severity -eq 'Error' })
	if ($errors.Count -gt 0) {
		throw "The output isn't self-contained:$([Environment]::NewLine)$(($errors | ForEach-Object { '  ' + $_.Message }) -join [Environment]::NewLine)"
	}

	[pscustomobject]@{
		OutputPath   = $OutputPath
		RunnerScript = $runnerPath
		EnabledTasks = @($definitions | Where-Object { $Configuration.Tasks[$_.Name].Enabled } | ForEach-Object { $_.Name })
		Assets       = @($sourceToName.Values)
	}
}


function Test-ABOutputSelfContained {
	<#
	.SYNOPSIS
	Checks that a generated output folder (the content of the .intunewin package) only refers to files inside it.
	.DESCRIPTION
	Returns a list of problems (Severity = Error or Warning, Message):
	  - Error: a file or folder parameter in the output's AutopilotBranding.json that is a full path, goes outside the
	    output folder (..), or doesn't exist in the output folder.
	  - Warning: another text value of an enabled task that looks like a full path on the build machine (for
	    example C:\Users\...), which won't exist on the device.  Device paths such as C:\Windows aren't reported.
	  - Warning: a runner script that differs from the module's.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $OutputPath,
		[string] $RunnerName = 'AutopilotBranding.ps1',
		[object[]] $TaskDefinitions
	)

	$OutputPath = ConvertTo-ABFullPath $OutputPath
	if (-not $TaskDefinitions) {
		$TaskDefinitions = @(Get-ABTaskDefinition -ModulePath (Join-Path $OutputPath 'AutopilotBranding'))
	}

	# The packaged configuration
	$devicePrefixes = '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData)(\\|$)'
	$configPath = Join-Path $OutputPath 'AutopilotBranding.json'
	if (Test-Path -LiteralPath $configPath) {
		$configuration = Read-ABConfiguration -Path $configPath -TaskDefinitions $TaskDefinitions
		foreach ($definition in $TaskDefinitions) {
			$entry = $configuration.Tasks[$definition.Name]
			foreach ($p in ($definition.Parameters | Where-Object { $_.AssetKind })) {
				$value = [string]$entry.Parameters[$p.Name]
				if ([string]::IsNullOrWhiteSpace($value)) {
					continue
				}
				$where = "$($definition.Name) -$($p.Name) ($value)"
				if ([System.IO.Path]::IsPathRooted($value) -or $value -match '^%|^\$') {
					[pscustomobject]@{ Severity = 'Error'; Message = "$($where): not a path relative to the package" }
				} elseif (($value -split '[\\/]') -contains '..') {
					[pscustomobject]@{ Severity = 'Error'; Message = "$($where): goes outside the package" }
				} elseif (-not (Test-Path -LiteralPath (Join-Path $OutputPath $value))) {
					[pscustomobject]@{ Severity = 'Error'; Message = "$($where): not found in the package" }
				}
			}
			# Other text values that look like paths on the build computer (device paths such as C:\Windows are fine)
			if (-not $entry.Enabled) {
				continue
			}
			foreach ($p in ($definition.Parameters | Where-Object { -not $_.AssetKind -and $_.Kind -in 'String', 'StringArray' })) {
				foreach ($text in @($entry.Parameters[$p.Name])) {
					if (($text -match '^[A-Za-z]:\\' -or $text -match '^\\\\') -and $text -notmatch $devicePrefixes) {
						[pscustomobject]@{ Severity = 'Warning'; Message = "$($definition.Name) -$($p.Name): '$text' looks like a path on this computer; it won't be in the package." }
					}
				}
			}
		}
	}

	# The runner script
	$runnerPath = Join-Path $OutputPath $RunnerName
	if (-not (Test-Path -LiteralPath $runnerPath)) {
		[pscustomobject]@{ Severity = 'Error'; Message = "Runner script not found: $runnerPath" }
		return
	}
	$expected = Join-Path $script:ABModuleRoot 'Runner\AutopilotBranding.ps1'
	if ((Test-Path -LiteralPath $expected) -and -not (Test-ABSameContent -A $runnerPath -B $expected)) {
		[pscustomobject]@{ Severity = 'Warning'; Message = "The runner script differs from the module's ($expected)." }
	}
}


function New-ABIntuneWinPackage {
	<#
	.SYNOPSIS
	Packages an output folder (see New-ABOutput) as an Intune Win32 app (.intunewin file).
	.DESCRIPTION
	Uses New-IntuneWinPackage from the SvRooij.ContentPrep.Cmdlet module, which is installed for the current user
	from the PowerShell Gallery if needed (along with the NuGet package provider).  The .intunewin file is named
	after the setup file, e.g. AutopilotBranding.intunewin; an existing file with that name is replaced.
	.PARAMETER SourcePath
	Folder to package (the generated output folder).
	.PARAMETER DestinationPath
	Folder where the .intunewin file is created.  It must not be inside SourcePath.
	.PARAMETER SetupFile
	Setup file inside SourcePath (the runner script).
	.OUTPUTS
	The full path of the .intunewin file.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param (
		[Parameter(Mandatory = $true)] [string] $SourcePath,
		[Parameter(Mandatory = $true)] [string] $DestinationPath,
		[string] $SetupFile = 'AutopilotBranding.ps1'
	)

	$SourcePath = ConvertTo-ABFullPath $SourcePath
	$DestinationPath = ConvertTo-ABFullPath $DestinationPath
	if (-not (Test-Path -LiteralPath (Join-Path $SourcePath $SetupFile) -PathType Leaf)) {
		throw "Setup file $SetupFile not found in $SourcePath"
	}
	$sourcePrefix = $SourcePath.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
	if ($DestinationPath.Equals($SourcePath.TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase) -or
		$DestinationPath.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
		throw "The package destination ($DestinationPath) must not be inside the folder being packaged ($SourcePath)."
	}

	# Make sure the NuGet provider and the content prep module are available
	if (-not (Get-Module -ListAvailable -Name SvRooij.ContentPrep.Cmdlet | Where-Object { $_.Version -ge [version]'0.4.0' })) {
		$minimumNuGet = [version]'2.8.5.201'
		$provider = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
			Sort-Object Version -Descending |
			Select-Object -First 1
		if (-not $provider -or $provider.Version -lt $minimumNuGet) {
			Write-Verbose "Installing NuGet package provider $minimumNuGet or later"
			Install-PackageProvider -Name NuGet -MinimumVersion $minimumNuGet -Force | Out-Null
		}
		Write-Verbose 'Installing SvRooij.ContentPrep.Cmdlet module'
		Install-Module SvRooij.ContentPrep.Cmdlet -MinimumVersion 0.4.0 -Scope CurrentUser -Force
	}
	Import-Module SvRooij.ContentPrep.Cmdlet -MinimumVersion 0.4.0 -ErrorAction Stop

	if (-not (Test-Path -LiteralPath $DestinationPath)) {
		New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
	}
	$packagePath = Join-Path $DestinationPath ([System.IO.Path]::GetFileNameWithoutExtension($SetupFile) + '.intunewin')
	if (Test-Path -LiteralPath $packagePath) {
		Remove-Item -LiteralPath $packagePath -Force
	}
	New-IntuneWinPackage -SourcePath $SourcePath -SetupFile $SetupFile -DestinationPath $DestinationPath -ErrorAction Stop | Out-Null
	if (-not (Test-Path -LiteralPath $packagePath)) {
		throw "The package was not created: $packagePath"
	}
	return $packagePath
}


function ConvertFrom-ABLegacyConfig {
	<#
	.SYNOPSIS
	Converts a v3 Config.xml file (and the files next to it) into a JSON configuration.
	.DESCRIPTION
	File and folder parameters point at the files in the legacy folder (Layout.xml, start2.bin, Autopilot.theme, ...).
	Save the result with Save-ABConfiguration; you may want to copy the files next to the JSON file and use relative
	paths.
	.PARAMETER Path
	Path of the legacy Config.xml file.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $Path,
		[object[]] $TaskDefinitions = @(Get-ABTaskDefinition)
	)

	$folder = Split-Path -Path (ConvertTo-ABFullPath $Path) -Parent
	[xml]$xml = Get-Content -Path $Path -Raw
	$c = $xml.Config

	function Get-Value([string]$name) {
		$node = $c.SelectSingleNode($name)
		if ($node) { return $node.InnerText.Trim() }
		return ''
	}
	function Get-List([string]$parent, [string]$child) {
		$nodes = $c.SelectNodes("$parent/$child")
		return , [string[]]@($nodes | ForEach-Object { $_.InnerText.Trim() } | Where-Object { $_ })
	}
	function Test-NotSkipped([string]$name) { return (Get-Value $name) -ine 'true' }
	function Get-File([string]$name) {
		if (-not $name) { return '' }
		$candidate = Join-Path $folder $name
		if (Test-Path -LiteralPath $candidate) { return $candidate }
		return ''
	}

	$removeApps = Get-List 'RemoveApps' 'App'
	$winget = Get-List 'WinGetInstall' 'Id'
	$addFeatures = Get-List 'AddFeatures' 'Feature'
	$disableFeatures = Get-List 'DisableOptionalFeatures' 'Feature'
	$removeCapabilities = Get-List 'RemoveCapability' 'Capability'
	$oem = $c.SelectSingleNode('OEMInfo')
	function Get-OEM([string]$name) {
		if ($oem -and $oem.SelectSingleNode($name)) { return $oem.SelectSingleNode($name).InnerText.Trim() }
		return ''
	}

	$languageSettings = $c.SelectSingleNode('LanguageSettings')
	function Get-LanguageSetting([string]$name) {
		if ($languageSettings -and $languageSettings.SelectSingleNode($name)) { return $languageSettings.SelectSingleNode($name).InnerText.Trim() }
		return ''
	}
	$geoId = 0
	[void][int]::TryParse((Get-LanguageSetting 'GeoId'), [ref]$geoId)

	$tasks = [ordered]@{
		'Rename-ABComputer'               = @{ Enabled = [bool](Get-Value 'ComputerName'); Parameters = @{ NewName = (Get-Value 'ComputerName') } }
		'Set-ABStartLayout'               = @{ Enabled = (Test-NotSkipped 'SkipStartLayout'); Parameters = @{ LayoutXmlPath = (Get-File 'Layout.xml'); Start2BinPath = (Get-File 'start2.bin'); SettingsDatPath = (Get-File 'settings.dat') } }
		'Set-ABTaskbarLayout'             = @{ Enabled = (Test-NotSkipped 'SkipTaskbarLayout'); Parameters = @{ TaskbarLayoutPath = (Get-File 'TaskbarLayoutModification.xml') } }
		'Set-ABTheme'                     = @{ Enabled = (Test-NotSkipped 'SkipTheme'); Parameters = @{ ThemePath = (Get-File 'Autopilot.theme'); WallpaperPath = (Get-File 'Autopilot.jpg') } }
		'Set-ABLockScreen'                = @{ Enabled = (Test-NotSkipped 'SkipLockScreen'); Parameters = @{ ImagePath = (Get-File 'AutopilotLock.jpg') } }
		'Disable-ABStartOnFirstLogon'     = @{ Enabled = $true; Parameters = @{} }
		'Disable-ABDesktopSpotlight'      = @{ Enabled = $true; Parameters = @{} }
		'Set-ABStartAlignment'            = @{ Enabled = (Test-NotSkipped 'SkipLeftAlignStart'); Parameters = @{ Alignment = 'Left' } }
		'Hide-ABWidgets'                  = @{ Enabled = (Test-NotSkipped 'SkipHideWidgets'); Parameters = @{} }
		'Disable-ABWidgets'               = @{ Enabled = (Test-NotSkipped 'SkipDisableWidgets'); Parameters = @{} }
		'Set-ABSearchBoxMode'             = @{ Enabled = (Test-NotSkipped 'SkipSetSearchIcon'); Parameters = @{ Mode = 'IconOnly' } }
		'Set-ABTimeZone'                  = @{ Enabled = $true; Parameters = @{ TimeZone = (Get-Value 'TimeZone') } }
		'Remove-ABProvisionedApps'        = @{ Enabled = ($removeApps.Count -gt 0); Parameters = @{ AppNames = $removeApps } }
		'Disable-ABCopilotPWA'            = @{ Enabled = (Test-NotSkipped 'SkipRemoveCopilotPWA'); Parameters = @{} }
		'Install-ABOneDrive'              = @{ Enabled = [bool](Get-Value 'OneDriveSetup'); Parameters = @{ Url = (Get-Value 'OneDriveSetup'); ArmUrl = (Get-Value 'OneDriveARMSetup') } }
		'Disable-ABEdgeDesktopShortcut'   = @{ Enabled = $true; Parameters = @{} }
		'Update-ABEdge'                   = @{ Enabled = (Test-NotSkipped 'SkipEdgeUpdate'); Parameters = @{ Url = (Get-Value 'EdgeBusinessMSI'); ArmUrl = (Get-Value 'EdgeBusinessARM') } }
		'Remove-ABEdgeBookmarks'          = @{ Enabled = $true; Parameters = @{} }
		'Add-ABLanguagePacks'             = @{ Enabled = [bool](Get-ChildItem (Join-Path $folder 'LPs') -Filter *.cab -ErrorAction SilentlyContinue); Parameters = @{ LanguagePackFolder = (Get-File 'LPs') } }
		'Set-ABLanguage'                  = @{ Enabled = [bool](Get-Value 'Language'); Parameters = @{ LanguageXmlPath = (Get-File (Get-Value 'Language')) } }
		'Set-ABLanguageSettings'          = @{ Enabled = [bool](Get-LanguageSetting 'Language'); Parameters = @{ Language = (Get-LanguageSetting 'Language'); Locale = (Get-LanguageSetting 'Locale'); GeoId = $geoId } }
		'Disable-ABOptionalFeatures'      = @{ Enabled = ($disableFeatures.Count -gt 0); Parameters = @{ FeatureNames = $disableFeatures } }
		'Remove-ABWindowsCapabilities'    = @{ Enabled = ($removeCapabilities.Count -gt 0); Parameters = @{ CapabilityNames = $removeCapabilities } }
		'Add-ABWindowsCapabilities'       = @{ Enabled = ($addFeatures.Count -gt 0); Parameters = @{ CapabilityNames = $addFeatures } }
		'Set-ABDefaultApps'               = @{ Enabled = [bool](Get-Value 'DefaultApps'); Parameters = @{ AssociationsXmlPath = (Get-File (Get-Value 'DefaultApps')) } }
		'Set-ABRegisteredOwner'           = @{ Enabled = [bool](Get-Value 'RegisteredOwner'); Parameters = @{ Owner = (Get-Value 'RegisteredOwner'); Organization = (Get-Value 'RegisteredOrganization') } }
		'Set-ABOEMInfo'                   = @{ Enabled = [bool]$oem; Parameters = @{ Manufacturer = (Get-OEM 'Manufacturer'); Model = (Get-OEM 'Model'); SupportPhone = (Get-OEM 'SupportPhone'); SupportHours = (Get-OEM 'SupportHours'); SupportURL = (Get-OEM 'SupportURL'); LogoPath = (Get-File (Get-OEM 'Logo')) } }
		'Set-ABEnterpriseEdition'         = @{ Enabled = (Test-NotSkipped 'SkipEnterpriseGVLK'); Parameters = @{} }
		'Enable-ABUEV'                    = @{ Enabled = (Test-NotSkipped 'SkipUEV'); Parameters = @{ TemplateFolder = (Get-File 'UEV') } }
		'Disable-ABNetworkLocationFlyout' = @{ Enabled = $true; Parameters = @{} }
		'Disable-ABAutoInstalledApps'     = @{ Enabled = (Test-NotSkipped 'SkipAutoinstallingApps'); Parameters = @{} }
		'Install-ABWinGetPackages'        = @{ Enabled = ((Test-NotSkipped 'SkipWinGet') -and $winget.Count -gt 0); Parameters = @{ PackageIds = $winget } }
		'Set-ABChromeConfig'              = @{ Enabled = (Test-NotSkipped 'SkipChromeConfig'); Parameters = @{ InitialPreferencesPath = (Get-File 'initial_preferences') } }
		'Disable-ABAPv2Pages'             = @{ Enabled = (Test-NotSkipped 'SkipAPv2'); Parameters = @{} }
		'Update-ABApps'                   = @{ Enabled = (Test-NotSkipped 'SkipUpdates'); Parameters = @{} }
		'Disable-ABFirstLogonAnimation'   = @{ Enabled = (Test-NotSkipped 'SkipShowDesktopFaster'); Parameters = @{} }
		'Remove-ABOffice'                 = @{ Enabled = (Test-NotSkipped 'SkipRemoveOffice'); Parameters = @{} }
	}

	$configuration = [ordered]@{
		Version     = $script:ConfigurationVersion
		Description = "Converted from $Path"
		Tasks       = [ordered]@{}
	}
	foreach ($name in $tasks.Keys) {
		$parameters = [ordered]@{}
		foreach ($key in $tasks[$name].Parameters.Keys) {
			$value = $tasks[$name].Parameters[$key]
			# Don't override the cmdlet defaults with empty URLs
			if (($value -is [string]) -and $value -eq '' -and $key -like '*Url') {
				continue
			}
			$parameters[$key] = $value
		}
		$configuration.Tasks[$name] = [ordered]@{ Enabled = [bool]$tasks[$name].Enabled; Parameters = $parameters }
	}
	Complete-ABConfiguration -Configuration $configuration -TaskDefinitions $TaskDefinitions
}

# AutopilotBranding.Builder
#
# Build-time helpers used by Show-AutopilotBrandingBuilder.ps1 (UI) and Build-AutopilotBranding.ps1 (headless):
#   - discover the configuration tasks (cmdlets) and their parameters from the AutopilotBranding module source
#   - load, complete, validate and save JSON configuration files
#   - convert a legacy (v3) Config.xml file into a JSON configuration
#   - generate an output folder containing the module, the assets, and a runner script (AutopilotBranding.ps1)
#
# Parameter conventions used by the builder:
#   - Parameters whose name ends in "Path" are local files and parameters whose name ends in "Folder" are local
#     folders.  They are copied into the Assets folder of the output and passed to the cmdlet using a path relative
#     to the runner script.  Relative paths in the JSON file are relative to the JSON file's folder.
#   - [string[]] parameters are edited one value per line.
#   - [bool] and [switch] parameters are shown as check boxes; [ValidateSet()] parameters as drop-down lists.

$script:ConfigurationVersion = 1
$script:RepositoryRoot = Split-Path -Path $PSScriptRoot -Parent


function Get-ABDefaultModulePath {
	<#
	.SYNOPSIS
	Returns the path of the AutopilotBranding module source folder in this repository.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param ()

	Join-Path $script:RepositoryRoot 'Module\AutopilotBranding'
}


function Get-ABDefaultConfigurationPath {
	<#
	.SYNOPSIS
	Returns the path of the default configuration file (AutopilotBranding.json) in this repository.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param ()

	Join-Path $script:RepositoryRoot 'AutopilotBranding.json'
}


function Get-ABAstValue {
	# Evaluates a (constant) parameter default value AST.  Arrays are returned wrapped so they aren't unrolled.
	param ($Ast)

	if ($null -eq $Ast) {
		return $null
	}
	if ($Ast -is [System.Management.Automation.Language.VariableExpressionAst]) {
		switch ($Ast.VariablePath.UserPath) {
			'true' { return $true }
			'false' { return $false }
			'null' { return $null }
		}
	}
	try {
		$value = $Ast.SafeGetValue()
	}
	catch {
		$value = $Ast.Extent.Text
	}
	if ($value -is [array]) {
		return , $value
	}
	return $value
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


function ConvertTo-ABOrderedHashtable {
	# Recursively converts PSCustomObjects (from ConvertFrom-Json) into ordered hashtables.
	param ($InputObject)

	if ($null -eq $InputObject) {
		return $null
	}
	if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
		$result = [ordered]@{}
		foreach ($property in $InputObject.PSObject.Properties) {
			$result[$property.Name] = ConvertTo-ABOrderedHashtable $property.Value
		}
		return $result
	}
	if ($InputObject -is [System.Collections.IDictionary]) {
		$result = [ordered]@{}
		foreach ($key in $InputObject.Keys) {
			$result[$key] = ConvertTo-ABOrderedHashtable $InputObject[$key]
		}
		return $result
	}
	if ($InputObject -is [array]) {
		$items = @(foreach ($item in $InputObject) { ConvertTo-ABOrderedHashtable $item })
		return , $items
	}
	return $InputObject
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


function Test-ABValueEqual {
	# Compares two parameter values (including arrays).
	param ($A, $B)

	$jsonA = ConvertTo-Json -InputObject $A -Compress -Depth 5
	$jsonB = ConvertTo-Json -InputObject $B -Compress -Depth 5
	return $jsonA -eq $jsonB
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
	$fullPath = [System.IO.Path]::GetFullPath($Path)
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
		return [System.IO.Path]::GetFullPath($expanded)
	}
	return [System.IO.Path]::GetFullPath((Join-Path $BasePath $expanded))
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

	$full = [System.IO.Path]::GetFullPath($Path)
	$base = [System.IO.Path]::GetFullPath($BasePath).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
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
	Generates the runner script that imports the module and calls each enabled task with its parameters.
	.PARAMETER AssetMap
	Hashtable mapping "<Task>|<Parameter>" to the asset's path relative to the Assets folder.
	#>
	[CmdletBinding()]
	[OutputType([string])]
	param (
		[Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Configuration,
		[Parameter(Mandatory = $true)] [object[]] $TaskDefinitions,
		[System.Collections.IDictionary] $AssetMap = @{},
		[string] $ModuleVersion = ''
	)

	$nl = "`r`n"
	$enabled = @($TaskDefinitions | Where-Object { $Configuration.Tasks.Contains($_.Name) -and $Configuration.Tasks[$_.Name].Enabled })
	$disabled = @($TaskDefinitions | Where-Object { -not ($Configuration.Tasks.Contains($_.Name) -and $Configuration.Tasks[$_.Name].Enabled) })

	$sb = New-Object System.Text.StringBuilder
	$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
	$header = @"
<#
.SYNOPSIS
Autopilot Branding runner script.

.DESCRIPTION
Loads the AutopilotBranding module (v$ModuleVersion) and calls each configuration task with the configured
parameters.  This file was generated by the AutopilotBranding builder on $generated; rather than editing it, change
the configuration (AutopilotBranding.json) with Show-AutopilotBrandingBuilder.ps1 and generate it again.

Enabled tasks:
$(($enabled | ForEach-Object { "  $($_.Name)" }) -join $nl)

Disabled tasks:
$(($disabled | ForEach-Object { "  $($_.Name)" }) -join $nl)

.PARAMETER Force
Run the tasks even if OOBE has already been completed.
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory = `$false)] [Switch] `$Force = `$false
)

# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("`$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
	if (Test-Path "`$(`$env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
		`$relaunchArgs = @('-ExecutionPolicy', 'Bypass', '-NoProfile', '-File', `$PSCommandPath)
		if (`$Force) { `$relaunchArgs += '-Force' }
		& "`$(`$env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" @relaunchArgs
		exit `$LASTEXITCODE
	}
}

`$AssetRoot = Join-Path `$PSScriptRoot 'Assets'
Import-Module (Join-Path `$PSScriptRoot 'AutopilotBranding\AutopilotBranding.psd1') -Force

if (-not (Start-AutopilotBranding -Force:`$Force)) {
	exit 0
}

try {

"@
	[void]$sb.Append($header.Replace("`r`n", "`n").Replace("`n", $nl))

	foreach ($task in $enabled) {
		$entry = $Configuration.Tasks[$task.Name]
		$lines = New-Object System.Collections.Generic.List[string]
		foreach ($p in $task.Parameters) {
			if (-not $entry.Parameters.Contains($p.Name)) {
				continue
			}
			$value = ConvertTo-ABParameterValue -Definition $p -Value $entry.Parameters[$p.Name]
			$key = "$($task.Name)|$($p.Name)"
			if ($p.AssetKind) {
				if ([string]::IsNullOrWhiteSpace($value)) {
					continue
				}
				if ($AssetMap.Contains($key)) {
					$lines.Add("$($p.Name) = (Join-Path `$AssetRoot $(ConvertTo-ABLiteral -Value $AssetMap[$key]))")
				} else {
					$lines.Add("$($p.Name) = $(ConvertTo-ABLiteral -Value $value)")
				}
				continue
			}
			if ($p.Kind -eq 'Switch' -and -not $value) {
				continue
			}
			if (-not $p.Mandatory -and (Test-ABValueEqual $value $p.DefaultValue)) {
				continue
			}
			$lines.Add("$($p.Name) = $(ConvertTo-ABLiteral -Value $value -Indent "`t`t`t")")
		}

		[void]$sb.Append("`t# $($task.Synopsis)$nl")
		[void]$sb.Append("`tInvoke-ABTask -Name '$($task.Name)' -ScriptBlock {$nl")
		if ($lines.Count -gt 0) {
			[void]$sb.Append("`t`t`$parameters = @{$nl")
			foreach ($line in $lines) {
				[void]$sb.Append("`t`t`t$line$nl")
			}
			[void]$sb.Append("`t`t}$nl")
			[void]$sb.Append("`t`t$($task.Name) @parameters$nl")
		} else {
			[void]$sb.Append("`t`t$($task.Name)$nl")
		}
		[void]$sb.Append("`t}$nl$nl")
	}

	[void]$sb.Append("} finally {$nl`tStop-AutopilotBranding$nl}$nl")
	return $sb.ToString()
}


function New-ABOutput {
	<#
	.SYNOPSIS
	Generates an output folder containing the module, the assets, the configuration and the runner script.
	.DESCRIPTION
	The output folder can be packaged as an Intune Win32 app (see makeapp.ps1); the install command is
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
	File name of the generated runner script.
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

	$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
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
	$manifest = Import-PowerShellDataFile -Path (Join-Path $ModulePath 'AutopilotBranding.psd1')

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

	# Save the configuration used, with asset paths pointing at the copied files
	$outputConfiguration = ConvertTo-ABOrderedHashtable (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Configuration -Depth 10))
	foreach ($key in $assetMap.Keys) {
		$taskName, $paramName = $key -split '\|', 2
		$outputConfiguration.Tasks[$taskName].Parameters[$paramName] = "Assets\$($assetMap[$key])"
	}
	Save-ABConfiguration -Configuration $outputConfiguration -Path (Join-Path $OutputPath 'AutopilotBranding.json')

	# Generate the runner script
	$runner = Get-ABRunnerScript -Configuration $Configuration -TaskDefinitions $definitions -AssetMap $assetMap -ModuleVersion $manifest.ModuleVersion
	$runnerPath = Join-Path $OutputPath $RunnerName
	# UTF-8 with BOM so that Windows PowerShell 5.1 reads non-ASCII characters correctly
	[System.IO.File]::WriteAllText($runnerPath, $runner, (New-Object System.Text.UTF8Encoding($true)))

	[pscustomobject]@{
		OutputPath   = $OutputPath
		RunnerScript = $runnerPath
		EnabledTasks = @($definitions | Where-Object { $Configuration.Tasks[$_.Name].Enabled } | ForEach-Object { $_.Name })
		Assets       = @($sourceToName.Values)
	}
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

	$folder = Split-Path -Path ([System.IO.Path]::GetFullPath($Path)) -Parent
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

	$tasks = [ordered]@{
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


Export-ModuleMember -Function @(
	'Get-ABDefaultModulePath'
	'Get-ABDefaultConfigurationPath'
	'Get-ABTaskDefinition'
	'New-ABConfiguration'
	'Complete-ABConfiguration'
	'Read-ABConfiguration'
	'Save-ABConfiguration'
	'Test-ABConfiguration'
	'Resolve-ABAssetPath'
	'Get-ABRelativePath'
	'ConvertTo-ABParameterValue'
	'ConvertTo-ABLiteral'
	'Get-ABRunnerScript'
	'New-ABOutput'
	'ConvertFrom-ABLegacyConfig'
)

function Get-ABTaskInvocation {
	<#
	.SYNOPSIS
	Returns the task cmdlets that a configuration runs, in order, with the parameters each one is called with.
	.DESCRIPTION
	Only enabled tasks are returned.  A parameter is passed when it is mandatory or its value differs from the
	cmdlet's default; a switch is passed when it is on.  File and folder parameters (names ending in Path or Folder)
	are resolved against BasePath (the configuration's folder) and passed as full paths; empty ones are left out.
	Invoke-AutopilotBranding runs exactly these invocations.
	.PARAMETER Configuration
	The configuration (see Read-ABConfiguration).
	.PARAMETER BasePath
	Folder that relative file and folder paths in the configuration are relative to.
	.OUTPUTS
	Objects with Name (the task cmdlet) and Parameters (a hashtable to splat).
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Configuration,
		[Parameter(Mandatory = $true)] [string] $BasePath,
		[object[]] $TaskDefinitions = @(Get-ABTaskDefinition)
	)

	foreach ($definition in $TaskDefinitions) {
		if (-not $Configuration.Tasks.Contains($definition.Name) -or -not $Configuration.Tasks[$definition.Name].Enabled) {
			continue
		}
		$entry = $Configuration.Tasks[$definition.Name]
		$parameters = [ordered]@{}
		foreach ($p in $definition.Parameters) {
			if (-not $entry.Parameters.Contains($p.Name)) {
				continue
			}
			$value = ConvertTo-ABParameterValue -Definition $p -Value $entry.Parameters[$p.Name]
			if ($p.AssetKind) {
				if (-not [string]::IsNullOrWhiteSpace($value)) {
					$parameters[$p.Name] = Resolve-ABAssetPath -Path $value -BasePath $BasePath
				}
				continue
			}
			if ($p.Kind -eq 'Switch') {
				if ($value) { $parameters[$p.Name] = $true }
				continue
			}
			if (-not $p.Mandatory -and (Test-ABValueEqual $value $p.DefaultValue)) {
				continue
			}
			$parameters[$p.Name] = $value
		}
		[pscustomobject]@{
			Name       = $definition.Name
			Synopsis   = $definition.Synopsis
			Parameters = $parameters
		}
	}
}


function Invoke-AutopilotBranding {
	<#
	.SYNOPSIS
	Runs the configuration tasks in a configuration file.
	.DESCRIPTION
	Reads the configuration (AutopilotBranding.json) and calls each enabled task cmdlet, in order, with its configured
	parameters.  File and folder parameters are relative to the configuration file's folder (in a generated package:
	Assets\...).  Each task runs inside Invoke-ABTask, so a failure is logged and the remaining tasks still run.

	This is what the generated runner script (AutopilotBranding.ps1) calls, between Start-AutopilotBranding and
	Stop-AutopilotBranding.
	.PARAMETER ConfigPath
	The configuration file.
	.EXAMPLE
	Start-AutopilotBranding -Force
	try { Invoke-AutopilotBranding -ConfigPath .\AutopilotBranding.json } finally { Stop-AutopilotBranding }
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $ConfigPath
	)

	$ConfigPath = ConvertTo-ABFullPath $ConfigPath
	Write-ABLog "Configuration: $ConfigPath"
	$definitions = @(Get-ABTaskDefinition)
	$configuration = Read-ABConfiguration -Path $ConfigPath -TaskDefinitions $definitions
	$invocations = @(Get-ABTaskInvocation -Configuration $configuration -BasePath (Split-Path -Path $ConfigPath -Parent) -TaskDefinitions $definitions)
	Write-ABLog "Enabled tasks: $(($invocations | ForEach-Object { $_.Name }) -join ', ')"

	foreach ($invocation in $invocations) {
		$name = $invocation.Name
		$parameters = @{}
		foreach ($key in $invocation.Parameters.Keys) {
			$parameters[$key] = $invocation.Parameters[$key]
		}
		Invoke-ABTask -Name $name -ScriptBlock {
			foreach ($key in $invocation.Parameters.Keys) {
				Write-ABLog "  -$key $(ConvertTo-ABLiteral -Value $parameters[$key])"
			}
			& $name @parameters
		}
	}
}

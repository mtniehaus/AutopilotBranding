# Internal helpers for the builder functions (Public\Builder.ps1).

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


function Test-ABValueEqual {
	# Compares two parameter values (including arrays).
	param ($A, $B)

	$jsonA = ConvertTo-Json -InputObject $A -Compress -Depth 5
	$jsonB = ConvertTo-Json -InputObject $B -Compress -Depth 5
	return $jsonA -eq $jsonB
}


function ConvertTo-ABFullPath {
	# Returns the full path for a (possibly relative) path.  Relative paths are resolved against PowerShell's current
	# location; [System.IO.Path]::GetFullPath would use the process's current directory, which PowerShell doesn't
	# keep in sync with Set-Location.  The path doesn't need to exist.
	param (
		[Parameter(Mandatory = $true)] [string] $Path
	)

	$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}


function Test-ABPathUnder {
	# Returns $true if Path is Folder or inside it (case-insensitive; both must be full paths)
	param (
		[Parameter(Mandatory = $true)] [string] $Path,
		[Parameter(Mandatory = $true)] [string] $Folder
	)

	$folderFull = $Folder.TrimEnd('\', '/')
	$pathFull = $Path.TrimEnd('\', '/')
	$pathFull.Equals($folderFull, [System.StringComparison]::OrdinalIgnoreCase) -or
	$pathFull.StartsWith($folderFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
}


function Copy-ABItemNoOverwrite {
	# Copies a file, or a folder recursively, without overwriting files that already exist at the destination
	# (unless -Force), so a user's customized files are never replaced.
	param (
		[Parameter(Mandatory = $true)] [string] $Source,
		[Parameter(Mandatory = $true)] [string] $Destination,
		[switch] $Force
	)

	if (Test-Path -LiteralPath $Source -PathType Container) {
		if (-not (Test-Path -LiteralPath $Destination)) {
			New-Item -Path $Destination -ItemType Directory -Force | Out-Null
		}
		foreach ($child in (Get-ChildItem -LiteralPath $Source -Force)) {
			Copy-ABItemNoOverwrite -Source $child.FullName -Destination (Join-Path $Destination $child.Name) -Force:$Force
		}
	} elseif ($Force -or -not (Test-Path -LiteralPath $Destination)) {
		$parent = Split-Path -Path $Destination -Parent
		if ($parent -and -not (Test-Path -LiteralPath $parent)) {
			New-Item -Path $parent -ItemType Directory -Force | Out-Null
		}
		Copy-Item -LiteralPath $Source -Destination $Destination -Force
	}
}


function Update-ABAssetBase {
	<#
	.SYNOPSIS
	Prepares a configuration's file and folder parameters for a configuration that moves from OldBase to NewBase.
	.DESCRIPTION
	Files and folders that come from the module's project template are copied into NewBase (at the same relative path,
	without overwriting existing files) and keep their relative paths, so saving the default template somewhere turns
	that folder into a project.  Other paths are rebased so they keep pointing at the same files: relative if they are
	inside NewBase, otherwise full paths.
	#>
	param (
		[Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Configuration,
		[Parameter(Mandatory = $true)] [object[]] $TaskDefinitions,
		[Parameter(Mandatory = $true)] [string] $OldBase,
		[Parameter(Mandatory = $true)] [string] $NewBase
	)

	$template = Get-ABTemplatePath
	foreach ($definition in $TaskDefinitions) {
		if (-not $Configuration.Tasks.Contains($definition.Name)) {
			continue
		}
		$entry = $Configuration.Tasks[$definition.Name]
		foreach ($p in ($definition.Parameters | Where-Object { $_.AssetKind })) {
			$value = $entry.Parameters[$p.Name]
			if ([string]::IsNullOrWhiteSpace($value)) {
				continue
			}
			$full = Resolve-ABAssetPath -Path $value -BasePath $OldBase
			if ((Test-ABPathUnder -Path $full -Folder $template) -and (Test-Path -LiteralPath $full)) {
				$relative = Get-ABRelativePath -Path $full -BasePath $template
				Copy-ABItemNoOverwrite -Source $full -Destination (Join-Path $NewBase $relative)
				$entry.Parameters[$p.Name] = $relative
			} else {
				$entry.Parameters[$p.Name] = Get-ABRelativePath -Path $full -BasePath $NewBase
			}
		}
	}
}

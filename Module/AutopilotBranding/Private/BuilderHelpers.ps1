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

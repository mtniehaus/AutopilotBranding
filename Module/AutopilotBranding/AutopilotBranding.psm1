# AutopilotBranding module loader.
#
#   Private\*.ps1  - helper functions (not exported): shared task helpers, builder helpers, builder UI
#   Public\*.ps1   - exported functions: the run framework used by the generated runner script, the builder
#                    functions, and the Show-AutopilotBrandingBuilder / Build-AutopilotBranding cmdlets
#   Tasks\*.ps1    - one configuration task (cmdlet) per file (exported)
#
# Task files are named "<order>-<Verb>-AB<Noun>.ps1".  The numeric prefix defines the order in
# which the tasks are listed in the builder UI and called by the generated runner script.

$script:ABModuleRoot = $PSScriptRoot

foreach ($folder in 'Private', 'Public', 'Tasks') {
	$path = Join-Path $PSScriptRoot $folder
	if (Test-Path $path) {
		foreach ($file in (Get-ChildItem -Path $path -Filter '*.ps1' | Sort-Object Name)) {
			. $file.FullName
		}
	}
}

# Export the top-level functions defined in Public\*.ps1 (not functions nested inside them)
$publicFunctions = @(foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1')) {
		$ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
		foreach ($statement in $ast.EndBlock.Statements) {
			if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
				$statement.Name
			}
		}
	})

$taskFunctions = @(foreach ($file in (Get-ChildItem -Path (Join-Path $PSScriptRoot 'Tasks') -Filter '*.ps1' | Sort-Object Name)) {
		if ($file.BaseName -match '^\d+-(.+)$') { $Matches[1] } else { $file.BaseName }
	})

Export-ModuleMember -Function ($publicFunctions + $taskFunctions)

# Don't leave the loader's variables in the module scope, where functions could pick them up by accident
Remove-Variable -Name folder, path, file, ast, statement, publicFunctions, taskFunctions -ErrorAction SilentlyContinue

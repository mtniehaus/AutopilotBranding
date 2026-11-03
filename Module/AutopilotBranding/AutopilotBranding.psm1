# AutopilotBranding module loader.
#
#   Private\*.ps1  - shared helper functions (not exported)
#   Public\*.ps1   - framework functions used by the generated runner script (exported)
#   Tasks\*.ps1    - one configuration task (cmdlet) per file (exported)
#
# Task files are named "<order>-<Verb>-AB<Noun>.ps1".  The numeric prefix defines the order in
# which the tasks are listed in the builder UI and called by the generated runner script.

foreach ($folder in 'Private', 'Public', 'Tasks') {
	$path = Join-Path $PSScriptRoot $folder
	if (Test-Path $path) {
		foreach ($file in (Get-ChildItem -Path $path -Filter '*.ps1' | Sort-Object Name)) {
			. $file.FullName
		}
	}
}

$publicFunctions = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' | ForEach-Object {
	[System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null).FindAll({
		param($ast) $ast -is [System.Management.Automation.Language.FunctionDefinitionAst]
	}, $false) | ForEach-Object { $_.Name }
})

$taskFunctions = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Tasks') -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
	if ($_.BaseName -match '^\d+-(.+)$') { $Matches[1] } else { $_.BaseName }
})

Export-ModuleMember -Function ($publicFunctions + $taskFunctions)

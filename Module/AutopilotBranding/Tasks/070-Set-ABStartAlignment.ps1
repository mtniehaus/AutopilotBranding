function Set-ABStartAlignment {
	<#
	.SYNOPSIS
	Sets the default taskbar (Start button) alignment for new users.
	.DESCRIPTION
	Configures the alignment in the default user profile; users can still change it if they want.
	.PARAMETER Alignment
	Left or Center.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [ValidateSet('Left', 'Center')] [string] $Alignment = 'Left'
	)

	Write-ABLog "Configuring $($Alignment.ToLower()) aligned Start menu"
	$value = if ($Alignment -eq 'Left') { 0 } else { 1 }
	Set-ABRegistryValue -Hive DefaultUser -Path 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name TaskbarAl -Type REG_DWORD -Value $value
}

function Rename-ABComputer {
	<#
	.SYNOPSIS
	Renames the computer (takes effect after the next reboot).
	.DESCRIPTION
	%SERIAL% in the name is replaced with the BIOS serial number.  Characters other than letters, digits and hyphens are
	removed and the result is truncated to 15 characters.  Don't use this with hybrid Entra join; set the name in the
	Autopilot profile or the domain join profile instead.
	.PARAMETER NewName
	New computer name, e.g. PC-%SERIAL%.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $NewName
	)

	$serial = ''
	if ($NewName -match '%SERIAL%') {
		$serial = (Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber -replace '[^A-Za-z0-9-]', ''
	}
	$name = $NewName -ireplace '%SERIAL%', $serial
	$name = $name -replace '[^A-Za-z0-9-]', ''
	$name = $name.Substring(0, [Math]::Min(15, $name.Length)).Trim('-')

	if ([string]::IsNullOrWhiteSpace($name)) {
		Write-ABLog 'Computer name is empty after substitution, skipping rename'
	} elseif ($env:COMPUTERNAME -ieq $name) {
		Write-ABLog "Computer is already named $name"
	} else {
		Write-ABLog "Renaming computer to $name (takes effect after reboot)"
		Rename-Computer -NewName $name -Force -ErrorAction Stop
	}
}

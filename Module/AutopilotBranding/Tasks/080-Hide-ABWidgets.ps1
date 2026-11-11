function Hide-ABWidgets {
	<#
	.SYNOPSIS
	Hides the Widgets button on the taskbar for new users (users can turn it back on).
	.DESCRIPTION
	On Windows 11 24H2 and later the UCPD driver blocks reg.exe from writing this value
	(see https://kolbi.cz/blog/2024/04/03/userchoice-protection-driver-ucpd-sys/), so if access is denied the
	value is written using a renamed copy of reg.exe instead.
	#>
	[CmdletBinding()]
	param ()

	$path = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
	try {
		Write-ABLog 'Attempting to hide widgets via registry'
		Set-ABRegistryValue -Hive DefaultUser -Path $path -Name TaskbarDa -Type REG_DWORD -Value 0
		Write-ABLog 'Widgets hidden'
	}
	catch {
		# Don't test the error text for "Access is denied": reg.exe localizes it (e.g. "Zugriff verweigert" on German
		# Windows), so the workaround would be skipped there.  Retry with the renamed reg.exe on any failure instead;
		# if the retry fails too, that error is thrown.
		Write-ABLog "Hiding widgets failed ($($_.Exception.Message)); UCPD driver may be active, attempting widget hiding workaround (TaskbarDa)"
		$tempRegExe = "$($env:TEMP)\reg1.exe"
		Copy-Item -Path (Get-Command reg.exe).Source -Destination $tempRegExe -Force -ErrorAction Stop
		try {
			Set-ABRegistryValue -Hive DefaultUser -Path $path -Name TaskbarDa -Type REG_DWORD -Value 0 -RegExe $tempRegExe
			Write-ABLog 'Widget workaround completed'
		}
		finally {
			Remove-Item $tempRegExe -Force -ErrorAction SilentlyContinue
		}
	}
}

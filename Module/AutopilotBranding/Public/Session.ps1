# Framework functions used by the generated runner script (AutopilotBranding.ps1).

$script:ABTaskResults = New-Object System.Collections.Generic.List[object]
$script:ABStartUtc = $null
$script:ABOriginalProgressPreference = $null
$script:ABTranscriptStarted = $false


function Write-ABLog {
	<#
	.SYNOPSIS
	Writes a timestamped log message (captured by the transcript).
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false, Position = 0)] [string] $Message
	)

	$ts = Get-Date -Format 'yyyy/MM/dd hh:mm:ss tt'
	Write-Host "$ts $Message"
}


function Mount-ABDefaultUserHive {
	<#
	.SYNOPSIS
	Loads the default user profile's NTUSER.DAT into HKLM\TempUser.
	.DESCRIPTION
	Calls are reference counted: the hive is only loaded by the first call and only unloaded when the
	matching number of Dismount-ABDefaultUserHive calls have been made.  A hive left loaded by a previous run
	that didn't finish is unloaded and loaded again.  Start-AutopilotBranding mounts
	the hive once for the whole run so individual tasks don't repeatedly load and unload it.
	#>
	[CmdletBinding()]
	param ()

	if ($script:ABHiveRefCount -le 0) {
		$script:ABHiveRefCount = 0
		if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$($script:ABDefaultUserHiveName)") {
			# Left over from a previous run that didn't finish; unload it first so the load below succeeds
			Write-ABLog 'Default user registry hive is already loaded (left over from a previous run), unloading it first'
			Invoke-ABHiveUnload | Out-Null
		}
		$ntuser = Join-Path (Get-ABDefaultUserProfilePath) 'NTUSER.DAT'
		Write-ABLog "Loading default user registry hive $ntuser"
		$output = & reg.exe load "$(Get-ABDefaultUserRegistryRoot)" "$ntuser" 2>&1
		if ($LASTEXITCODE -ne 0) {
			throw "Unable to load default user registry hive (exit code $LASTEXITCODE): $output"
		}
		$script:ABHiveLoadedByModule = $true
	}
	$script:ABHiveRefCount++
}


function Dismount-ABDefaultUserHive {
	<#
	.SYNOPSIS
	Unloads the default user registry hive (when the last reference is released).
	.PARAMETER Force
	Release all references and unload the hive immediately.
	#>
	[CmdletBinding()]
	param (
		[switch] $Force
	)

	if ($script:ABHiveRefCount -le 0) {
		return
	}
	if ($Force) {
		$script:ABHiveRefCount = 0
	} else {
		$script:ABHiveRefCount--
	}

	if ($script:ABHiveRefCount -eq 0 -and $script:ABHiveLoadedByModule) {
		Write-ABLog "Unloading default user registry hive"
		Invoke-ABHiveUnload | Out-Null
		$script:ABHiveLoadedByModule = $false
	}
}


function Invoke-ABTask {
	<#
	.SYNOPSIS
	Runs one configuration task, logging its start, end and any error.  An error in one task does
	not stop the remaining tasks from running.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $Name,
		[Parameter(Mandatory = $true)] [scriptblock] $ScriptBlock
	)

	Write-ABLog "===== Starting: $Name"
	$sw = [System.Diagnostics.Stopwatch]::StartNew()
	$status = 'Succeeded'
	try {
		& $ScriptBlock
	}
	catch {
		$status = 'Failed'
		Write-ABLog "ERROR in $($Name): $_"
		if ($_.ScriptStackTrace) {
			Write-ABLog $_.ScriptStackTrace
		}
	}
	finally {
		$sw.Stop()
		$script:ABTaskResults.Add([pscustomobject]@{
				Name     = $Name
				Status   = $status
				Duration = $sw.Elapsed
			})
		Write-ABLog "===== Finished: $Name ($status, $([int]$sw.Elapsed.TotalSeconds) sec)"
	}
}


function Start-AutopilotBranding {
	<#
	.SYNOPSIS
	Prepares for running the configuration tasks: starts logging, writes the Intune detection tag
	file, verifies that the device is still in OOBE, and loads the default user registry hive.
	.OUTPUTS
	$true if the tasks should run, $false if OOBE has already completed (and -Force wasn't specified).
	.PARAMETER Force
	Run even if OOBE has already been completed.
	.PARAMETER LogFolder
	Folder for the log (transcript) and tag file.
	.PARAMETER TagFileName
	Name of the file used by the Intune detection rule.
	#>
	[CmdletBinding()]
	[OutputType([bool])]
	param (
		[switch] $Force,
		[string] $LogFolder = "$($env:ProgramData)\Microsoft\AutopilotBranding",
		[string] $TagFileName = 'AutopilotBranding.ps1.tag'
	)

	# Use UTC so that time zone changes don't affect the total runtime calculation
	$script:ABStartUtc = [datetime]::UtcNow
	$script:ABTaskResults.Clear()

	# Don't show progress bars - there's a weird issue where the progress for Add-AppxPackage stays on the screen
	$script:ABOriginalProgressPreference = $global:ProgressPreference
	$global:ProgressPreference = 'SilentlyContinue'

	if (-not (Test-Path $LogFolder)) {
		New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
	}

	Start-Transcript -Path (Join-Path $LogFolder 'AutopilotBranding.log') | Out-Null
	$script:ABTranscriptStarted = $true

	Set-Content -Path (Join-Path $LogFolder $TagFileName) -Value 'Installed'

	$module = Get-Module AutopilotBranding
	Write-ABLog "AutopilotBranding module v$($module.Version) loaded from $($module.ModuleBase)"

	if (Test-ABOOBEComplete) {
		if (-not $Force) {
			Write-ABLog 'OOBE is completed, bailing out without doing any configuration.'
			Stop-AutopilotBranding
			return $false
		}
		Write-ABLog 'OOBE is completed but -Force specified, will run anyway.'
	}

	try {
		Mount-ABDefaultUserHive
	}
	catch {
		Write-ABLog "Unable to load the default user registry hive: $_"
	}
	return $true
}


function Stop-AutopilotBranding {
	<#
	.SYNOPSIS
	Finishes the run: unloads the default user registry hive, logs a summary, and stops logging.
	#>
	[CmdletBinding()]
	param ()

	Dismount-ABDefaultUserHive -Force

	if ($script:ABTaskResults.Count -gt 0) {
		Write-ABLog 'Task summary:'
		foreach ($result in $script:ABTaskResults) {
			Write-ABLog ('  {0,-10} {1} ({2} sec)' -f $result.Status, $result.Name, [int]$result.Duration.TotalSeconds)
		}
	}

	if ($script:ABStartUtc) {
		$runTime = [datetime]::UtcNow - $script:ABStartUtc
		if ($runTime.TotalHours -ge 1) {
			$runTimeFormatted = 'Duration: {0:hh} hr {0:mm} min {0:ss} sec' -f $runTime
		} else {
			$runTimeFormatted = 'Duration: {0:mm} min {0:ss} sec' -f $runTime
		}
		Write-ABLog 'Autopilot Branding Complete'
		Write-ABLog "Total Script $runTimeFormatted"
	}

	if ($null -ne $script:ABOriginalProgressPreference) {
		$global:ProgressPreference = $script:ABOriginalProgressPreference
	}

	if ($script:ABTranscriptStarted) {
		Stop-Transcript | Out-Null
		$script:ABTranscriptStarted = $false
	}
}

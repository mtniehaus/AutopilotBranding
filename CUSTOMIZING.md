# Customizing Autopilot Branding: adding your own task

You can add your own PowerShell code to the AutopilotBranding module as a **task**. A task you add works the same
way as the built-in ones:

- it's listed in the builder UI (`Show-AutopilotBrandingBuilder`), with its description and an editor for each
  parameter;
- its settings are saved in `AutopilotBranding.json`;
- it's copied into the output folder and the `.intunewin` package, along with any files it uses;
- on the device, it runs in order with the other enabled tasks, and its output goes to the log.

You don't register the task anywhere. The builder finds it by reading the module's `Tasks` folder.

- [How tasks are found](#how-tasks-are-found)
- [Step 1: Get a copy of the module you can change](#step-1-get-a-copy-of-the-module-you-can-change)
- [Step 2: Write the task file](#step-2-write-the-task-file)
- [Step 3: Load your copy and use the task](#step-3-load-your-copy-and-use-the-task)
- [Example: running a script you already have](#example-running-a-script-you-already-have)
- [Example: a task with settings and files](#example-a-task-with-settings-and-files)
- [How parameters appear in the builder](#how-parameters-appear-in-the-builder)
- [Where your task runs](#where-your-task-runs)
- [Helper functions you can use](#helper-functions-you-can-use)
- [Testing your task](#testing-your-task)
- [Things to know](#things-to-know)

## How tasks are found

Each task is a single PowerShell function in its own file in the module's `Tasks` folder:

```
AutopilotBranding\
    AutopilotBranding.psd1
    AutopilotBranding.psm1
    Tasks\
        005-Rename-ABComputer.ps1
        010-Set-ABStartLayout.ps1
        ...
        360-Remove-ABInstalledPrograms.ps1
        500-Add-ABDesktopShortcuts.ps1     <- your task
```

The file name has two parts, `<order>-<FunctionName>.ps1`:

- **`<order>`** is a number that decides where the task appears in the builder and when it runs on the device.
  Lower numbers run first. The files are sorted by name, so always use three digits (`005`, `370`, `500`). A
  four-digit prefix such as `1000` would sort before `200`.
- **`<FunctionName>`** must be exactly the name of the function in the file. The convention is
  `<Verb>-AB<Noun>` with an [approved verb](https://learn.microsoft.com/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands)
  (`Set`, `Add`, `Remove`, `Install`, `Disable`, ...). An unapproved verb makes `Import-Module` print a warning.

When you open or build a configuration, the builder parses every file in `Tasks` without running it. It uses:

- the function's **comment-based help**: `.SYNOPSIS` is the task's title, `.DESCRIPTION` is shown under it, and
  each `.PARAMETER` is the help text for that parameter;
- the function's **`param()` block**: each parameter's type, default value, `Mandatory` setting and
  `[ValidateSet()]` decide which editor the builder shows and how the value is checked.

When you generate the output, the builder copies the whole module folder, including your task file, into
`Output\AutopilotBranding`. The `.intunewin` is created from the output folder, so your task is in the package
without any other step.

## Step 1: Get a copy of the module you can change

Don't add files to the module that `Install-Module` installed. `Update-Module` installs each new version in a new
folder, so your task would be left behind in the old one. Keep your own copy instead. Either of these works:

**From the PowerShell Gallery:**

```powershell
Save-Module -Name AutopilotBranding -Path C:\AutopilotBranding\Module
# Creates C:\AutopilotBranding\Module\AutopilotBranding\<version>\
```

**From GitHub:** clone or fork this repository. The module is in `Module\AutopilotBranding`. With a fork you can
keep your tasks under source control and merge new versions as they're released. The repository's `ShowBuilder.cmd`
and `makeapp.cmd` load the module from the repository.

The rest of this document calls the folder that contains `AutopilotBranding.psd1` the **module folder**.

## Step 2: Write the task file

Create a file in the module folder's `Tasks` folder. Here's the smallest useful task:

```powershell
# Tasks\500-Set-ABSupportMessage.ps1
function Set-ABSupportMessage {
	<#
	.SYNOPSIS
	Shows a support message on the sign-in screen.
	.DESCRIPTION
	Sets the legal notice caption and text, which Windows shows before every sign-in.
	.PARAMETER Caption
	Title of the message.
	.PARAMETER Text
	The message.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $Caption,
		[Parameter(Mandatory = $true)] [string] $Text
	)

	Write-ABLog "Setting the sign-in message: $Caption"
	$path = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
	Set-ABRegistryValue -Hive Machine -Path $path -Name legalnoticecaption -Type REG_SZ -Value $Caption
	Set-ABRegistryValue -Hive Machine -Path $path -Name legalnoticetext -Type REG_SZ -Value $Text
	Write-ABLog 'Sign-in message set'
}
```

Rules:

- **One function per file**, named like the file. You can define helper functions in the same file. They're
  available to your task but aren't exported, and the builder ignores them.
- **Write help for the task and for every parameter.** The builder shows it, and the module's tests require it.
  Without `.SYNOPSIS`, the task has no title in the builder.
- **Use `[CmdletBinding()]` and a `param()` block**, even if the task has no parameters.
- **Use only the [supported parameter types](#how-parameters-appear-in-the-builder).**
- **Write progress with `Write-ABLog`.** It writes to the log on the device.
- **`throw` when the task fails.** The runner logs the error, marks the task as failed in the summary at the end
  of the log, and goes on with the next task. It doesn't stop the run.
- **Save the file as UTF-8 with BOM** if it contains any non-ASCII characters (accents, quotes, dashes). Windows
  PowerShell 5.1, which runs the tasks on the device, reads files without a BOM using the system code page.

## Step 3: Load your copy and use the task

Import the module from your copy before you open the builder or build a package:

```powershell
Import-Module C:\AutopilotBranding\Module\AutopilotBranding\<version>\AutopilotBranding.psd1 -Force
Get-Module AutopilotBranding | Select-Object Version, ModuleBase    # check that your copy is the one loaded

Show-AutopilotBrandingBuilder -ProjectPath C:\AutopilotBranding\Contoso
# or, without the UI:
Build-AutopilotBranding -ProjectPath C:\AutopilotBranding\Contoso
```

The builder and `Build-AutopilotBranding` use the module that's loaded, both to list the tasks and as the copy that
goes into the package. If `ModuleBase` shows the installed module, open a new PowerShell window and import your
copy first.

In the builder:

1. Your task appears in the task list, at the position its number gives it.
2. **It's not ticked in an existing project.** The builder adds tasks that the configuration doesn't mention yet
   as disabled, so a new task doesn't run until someone chooses it. Tick it and fill in its parameters.
3. **Save**, then **Generate output and .intunewin**.

To confirm the task is in the package, look in the output folder (by default the project's `Output` folder):

- `Output\AutopilotBranding\Tasks\` contains your task file;
- `Output\AutopilotBranding.json` has an entry for your task with `"Enabled": true`;
- `Output\Assets\` contains any files your task uses.

You can also check from PowerShell, without the UI:

```powershell
Get-ABTaskDefinition -Name Set-ABSupportMessage | Format-List         # what the builder found
Get-ABTaskDefinition -Name Set-ABSupportMessage | Select-Object -ExpandProperty Parameters
```

If the task is missing, see [Things to know](#things-to-know).

## Example: running a script you already have

If you already have a script, you don't need to rewrite it as a task. Write a small task that runs it, and
let the builder package the script as an asset:

```powershell
# Tasks\500-Invoke-ABCustomScript.ps1
function Invoke-ABCustomScript {
	<#
	.SYNOPSIS
	Runs your own PowerShell script.
	.DESCRIPTION
	The script is copied into the package and runs in the same 64-bit Windows PowerShell session as the other tasks,
	as SYSTEM.  Its output is written to the Autopilot Branding log.  If the script throws an error, or exits with an
	exit code other than 0, the task is marked as failed and the remaining tasks still run.
	.PARAMETER ScriptPath
	The script (.ps1) to run.
	.PARAMETER Arguments
	Arguments to pass to the script, one per line.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $ScriptPath,
		[Parameter(Mandatory = $false)] [string[]] $Arguments = @()
	)

	Write-ABLog "Running $ScriptPath"
	$global:LASTEXITCODE = 0
	& $ScriptPath @Arguments
	if ($LASTEXITCODE -ne 0) {
		throw "$ScriptPath exited with code $LASTEXITCODE"
	}
	Write-ABLog "$ScriptPath finished"
}
```

Because the parameter's name ends in `Path`, the builder shows a **Browse...** button for it. It copies the
script into the package's `Assets` folder and passes its full path on the device. If the script needs other files,
put them all in one folder and use a parameter that ends in `Folder` instead (for example `ScriptFolder`). The whole
folder is copied, and the task can run `Join-Path $ScriptFolder 'Setup.ps1'`.

To run more than one script, make a copy of the file for each one, with a different number and name (for example
`510-Invoke-ABPrinterScript.ps1` containing `function Invoke-ABPrinterScript`). Each one appears as its own task in
the builder.

## Example: a task with settings and files

This task copies shortcuts to the desktop. It shows a folder parameter, a drop-down list, a check box and a
helper that changes every user profile.

```powershell
# Tasks\500-Add-ABDesktopShortcuts.ps1
function Add-ABDesktopShortcuts {
	<#
	.SYNOPSIS
	Copies shortcuts (.lnk and .url files) to the desktop.
	.DESCRIPTION
	AllUsers puts the shortcuts on the public desktop, so every user sees them and can't delete them.  NewUsers puts
	them on the desktop of the default user profile (which new user profiles are created from) and of the user
	profiles that already exist; users can delete them.
	.PARAMETER ShortcutFolder
	Folder containing the shortcuts to copy.
	.PARAMETER Target
	Which desktop to copy the shortcuts to.
	.PARAMETER RemoveEdgeShortcut
	Also remove the Microsoft Edge shortcut from the public desktop.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)] [string] $ShortcutFolder,
		[Parameter(Mandatory = $false)] [ValidateSet('AllUsers', 'NewUsers')] [string] $Target = 'AllUsers',
		[Parameter(Mandatory = $false)] [bool] $RemoveEdgeShortcut = $false
	)

	$shortcuts = @(Get-ChildItem -LiteralPath $ShortcutFolder -File | Where-Object { $_.Extension -in '.lnk', '.url' })
	if ($shortcuts.Count -eq 0) {
		Write-ABLog "No shortcuts found in $ShortcutFolder"
		return
	}

	if ($Target -eq 'AllUsers') {
		$desktops = @("$($env:PUBLIC)\Desktop")
	} else {
		# The default user profile, plus existing profiles unless that was turned off
		$desktops = @(Get-ABUserProfilePaths | ForEach-Object { Join-Path $_ 'Desktop' })
	}

	foreach ($desktop in $desktops) {
		foreach ($shortcut in $shortcuts) {
			Write-ABLog "Copying $($shortcut.Name) to $desktop"
			Copy-ABFile -Path $shortcut.FullName -Destination (Join-Path $desktop $shortcut.Name)
		}
	}

	if ($RemoveEdgeShortcut) {
		Remove-Item -LiteralPath "$($env:PUBLIC)\Desktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
	}
	Write-ABLog 'Desktop shortcuts added'
}
```

In the builder, this task has:

- **ShortcutFolder**: a text box with **Browse...**. The folder you pick is copied into the project's `Assets`
  folder (the builder asks first) and then into the package. It's required, so the builder won't generate the
  package until it's set.
- **Target**: a drop-down list with `AllUsers` and `NewUsers`.
- **RemoveEdgeShortcut**: a check box.

The task's entry in `AutopilotBranding.json` looks like this:

```json
"Add-ABDesktopShortcuts": {
  "Enabled": true,
  "Parameters": {
    "ShortcutFolder": "Assets\\Shortcuts",
    "Target": "AllUsers",
    "RemoveEdgeShortcut": false
  }
}
```

## How parameters appear in the builder

| Parameter declaration | Editor in the builder | Value passed to your task |
| --- | --- | --- |
| `[string] $Name` | Text box | The text |
| `[string] $SomethingPath` | Text box with **Browse...** for a file | Full path of the file in the package's `Assets` folder, or nothing if empty |
| `[string] $SomethingFolder` | Text box with **Browse...** for a folder | Full path of the folder in the package's `Assets` folder, or nothing if empty |
| `[ValidateSet('A', 'B')] [string] $Name` | Drop-down list | The chosen value |
| `[string[]] $Names` | Multi-line text box, one value per line | An array; empty lines are dropped |
| `[bool] $Name` | Check box | `$true` or `$false` |
| `[switch] $Name` | Check box | The switch, when ticked |
| `[int] $Number` | Text box | The number |

More details:

- **File and folder parameters** are recognized by name only: a `[string]` parameter whose name ends in `Path`
  is a file and one whose name ends in `Folder` is a folder. Don't use these endings for anything else, such as a
  registry path or a folder on the device (`C:\Windows\...`). The builder would try to copy it into the package
  and report an error if it can't find it. Use a name such as `RegistryKey` or `Destination` instead.
  A `[string[]]` parameter is never treated as a file list, whatever its name.
- **Default values** in the `param()` block become the defaults in the builder and are shown under each
  parameter. Use plain values (`'text'`, `5`, `$true`, `@('a', 'b')`). The builder reads the code without running
  it, so a default such as `"$env:ProgramData\X"` is shown as that text. While the value is left unchanged, the
  parameter isn't passed and the task works out the real default on the device. If you want users to be able to
  change it, use an empty default and work out the real value in the task when the parameter is empty.
- **Values equal to the default aren't passed**, so your default is what the task gets. A parameter marked
  `Mandatory = $true` is always passed, and the builder reports an error if it's empty when the task is enabled.
- Other types (`[datetime]`, `[hashtable]`, `[string]` with `[ValidateScript()]` and so on) aren't supported.
  Use a `[string]` and convert or check it in the task.

## Where your task runs

On the device, the Intune app runs `AutopilotBranding.ps1`, which:

1. runs in **64-bit Windows PowerShell 5.1** as **SYSTEM**, during the Autopilot device setup (Enrollment Status
   Page), before any user has signed in. Don't depend on PowerShell 7 features or on a signed-in user.
2. starts the log (`%ProgramData%\Microsoft\AutopilotBranding\AutopilotBranding.log`), stops without doing
   anything if OOBE has already finished, and loads the default user profile's registry hive (and existing users'
   hives).
3. imports the packaged module and calls each enabled task in order, with the parameters from the packaged
   `AutopilotBranding.json`.
4. unloads the hives and writes a summary (succeeded or failed, and the time taken by each task) to the log.

What this means for your task:

- **Per-user settings:** don't use `HKCU:`, because that's SYSTEM's registry. Use
  `Set-ABRegistryValue -Hive DefaultUser`. It changes the default user profile, which new users get their settings
  from, and the profiles that already exist. Don't load or unload `NTUSER.DAT` yourself. The runner already loaded it.
- **Files:** use the file and folder parameters to reach the files you packaged. Don't build paths from
  `$PSScriptRoot` (that's the module's `Tasks` folder) or from the current folder.
- **Time:** the Enrollment Status Page waits for the whole app to finish. Keep downloads and installs short, and
  don't wait for user input (no `Read-Host` or message boxes).
- **Progress bars** are turned off during the run, so `Invoke-WebRequest` and similar commands aren't slowed
  down by them.

## Helper functions you can use

These functions are defined in `Private\Common.ps1` and `Public\Session.ps1`. Your task runs inside the module, so
it can call them, including the private ones. Use them to behave like the built-in tasks.

| Function | What it does |
| --- | --- |
| `Write-ABLog 'message'` | Writes a timestamped line to the log. |
| `Set-ABRegistryValue -Hive Machine\|DefaultUser\|ExistingUsers -Path <key> -Name <value> -Type REG_DWORD -Value 1` | Sets a registry value with reg.exe (64-bit view). `Machine` is HKLM. `DefaultUser` changes the default user profile and existing profiles. `ExistingUsers` changes only the existing profiles. `Path` is relative to the hive, e.g. `Software\Microsoft\...`. |
| `Get-ABUserProfilePaths` | The profile folders to change: the default user profile and, unless turned off, the existing ones. |
| `Get-ABUserRegistryRoots` | The reg.exe roots (`HKLM\TempUser`, `HKU\<SID>`) of the loaded user hives, for when `Set-ABRegistryValue` isn't enough. |
| `Get-ABDefaultUserProfilePath` | The default user profile folder (normally `C:\Users\Default`). |
| `Copy-ABFile -Path <file> -Destination <file>` | Copies a file and creates the destination folder if needed. |
| `Invoke-ABDownload -Url <url> -Destination <file>` | Downloads a file. |
| `Get-ABOSBuild` | The Windows build number, e.g. `26100`. |
| `Test-ABLegacyStartMenu` | `$true` on Windows 10 (build 22000 or earlier). |
| `Test-ABArm64` | `$true` on an ARM64 device. |

The private helpers can change between versions. After you update the module, check that the ones you use still
exist and work the same way.

## Testing your task

**On your build computer**, check that the builder finds the task and its parameters. After any change, import
the module again with `-Force`:

```powershell
Import-Module C:\AutopilotBranding\Module\AutopilotBranding\<version>\AutopilotBranding.psd1 -Force
Get-ABTaskDefinition -Name Add-ABDesktopShortcuts | Format-List
Get-Help Add-ABDesktopShortcuts -Full
```

**On a test device or virtual machine**, run the task by itself as an administrator. Use a test machine: tasks
change system settings.

```powershell
Import-Module C:\Temp\AutopilotBranding\AutopilotBranding.psd1 -Force
Add-ABDesktopShortcuts -ShortcutFolder C:\Temp\Shortcuts -Target AllUsers -Verbose
```

Outside a run, the default user hive isn't loaded, so `Set-ABRegistryValue -Hive DefaultUser` fails. To test the way
the package runs, copy the whole output folder to the test machine and run the runner script as an administrator.
`-Force` makes it run even though OOBE is already finished:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Temp\Output\AutopilotBranding.ps1 -Force
Get-Content "$env:ProgramData\Microsoft\AutopilotBranding\AutopilotBranding.log"
```

This runs **every enabled task** in the configuration, not only yours. For a quick test, build a configuration with
only your task enabled. To test as SYSTEM, the account Intune uses, you can run the same command from a SYSTEM
prompt, for example with `psexec -s -i`.

**In the repository**, if you work in a clone or fork, `Tests\Test-AutopilotBranding.ps1` checks every task in
`Tasks`: that it has a synopsis and that every parameter has help text. It also checks that the default template's
configuration lists every task, so add your task to `Template\AutopilotBranding.json` (usually with
`"Enabled": false`) to keep the tests passing. The tests run in GitHub Actions on every push.

## Things to know

- **The task doesn't appear in the builder.** Check that:
  - the module that's loaded is your copy (`(Get-Module AutopilotBranding).ModuleBase`);
  - the file is directly in `Tasks` and ends in `.ps1`;
  - the function name matches the file name after the number. The builder writes a warning,
    `Function ... not found in ..., skipping`, when it doesn't;
  - the file has no syntax errors. The builder writes a warning, `Parse errors in ...`.
- **The task appears without a description.** Check that the comment-based help is inside the function, right
  after the opening `{`, and uses `.SYNOPSIS`.
- **The web builder doesn't have your task.** The page at `mtniehaus.github.io` is built from the module on `main`
  in this repository. To use your task there, run the web builder from your own fork. See "Running or hosting it
  yourself" in the [README](README.md#running-or-hosting-it-yourself).
- **Configurations work with both copies.** If someone opens a configuration that uses your task with a module that
  doesn't have it, the builder warns `Unknown task, it will be ignored`. The task's settings stay in the JSON file
  and are used again by a module that has the task.
- **Updating the module:** when a new version comes out, copy your task files into the new version's `Tasks`
  folder (or merge the new version into your fork). Check that your numbers don't collide with new built-in tasks.
  If two files have the same number, they're ordered by name.
- **Changing a built-in task:** you can, but your change has to be redone with every update. Copying the task to a
  new file with a different number and name usually works better. Leave the original disabled.
- **Sharing:** if your task could be useful to others, consider contributing it. See [Suggestions?](README.md#suggestions)
  in the README.

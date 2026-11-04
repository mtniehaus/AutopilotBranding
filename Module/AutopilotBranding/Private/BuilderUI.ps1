# Builder UI (WPF) used by Show-AutopilotBrandingBuilder.
#
# The window, its named controls and the UI state live in module-scope variables ($window, $ui, $State).  The
# helper functions and the event handlers (which run later, while the window is shown) read them from there.

$script:window = $null
$script:ui = $null
$script:State = $null

# When set, Show-ABUIMessage throws instead of showing a message box (used by the automated tests, where a
# message box would block forever).
$script:ABUISuppressDialogs = $false


function Show-ABUIMessage {
	# Shows a message box owned by the builder window and returns the result (e.g. 'Yes').
	param (
		[Parameter(Mandatory = $true)] [string] $Text,
		[string] $Caption = 'Autopilot Branding Builder',
		[ValidateSet('OK', 'OKCancel', 'YesNo', 'YesNoCancel')] [string] $Buttons = 'OK',
		[ValidateSet('None', 'Information', 'Question', 'Warning', 'Error')] [string] $Icon = 'Information'
	)

	if ($script:ABUISuppressDialogs) {
		throw "Message box ($Caption): $Text"
	}
	if ($script:window) {
		return [System.Windows.MessageBox]::Show($script:window, $Text, $Caption, $Buttons, $Icon)
	}
	return [System.Windows.MessageBox]::Show($Text, $Caption, $Buttons, $Icon)
}


#region Helpers

function Invoke-Safely {
	param ([scriptblock] $ScriptBlock)
	try {
		& $ScriptBlock
	}
	catch {
		Show-ABUIMessage -Text ("$_") -Caption 'Autopilot Branding Builder' -Buttons 'OK' -Icon 'Error' | Out-Null
	}
}

function Get-BasePath {
	# Folder that relative paths in the configuration are relative to: the configuration file's folder, or the
	# module's project template for a configuration that hasn't been saved yet
	if ($State.ConfigPath) {
		return (Split-Path -Path $State.ConfigPath -Parent)
	}
	return (Get-ABTemplatePath)
}

function Get-DialogFolder {
	# Initial folder for file dialogs: the configuration's folder, or Documents (never the module's template folder)
	if ($State.ConfigPath) {
		return (Split-Path -Path $State.ConfigPath -Parent)
	}
	return [Environment]::GetFolderPath('MyDocuments')
}

function Get-TaskDefinition([string] $TaskName) {
	$State.Definitions | Where-Object { $_.Name -eq $TaskName } | Select-Object -First 1
}

function New-Brush([string] $Color) {
	(New-Object System.Windows.Media.BrushConverter).ConvertFromString($Color)
}

function Format-Value($Value) {
	if ($null -eq $Value) { return '' }
	if ($Value -is [bool]) { if ($Value) { return 'True' } else { return 'False' } }
	if ($Value -is [array]) { return ($Value -join ', ') }
	return [string]$Value
}

function Set-Dirty([bool] $Dirty = $true) {
	$State.Dirty = $Dirty
	Update-Title
}

function Update-Title {
	$name = if ($State.ConfigPath) { $State.ConfigPath } else { '(not saved yet - save to create a project folder)' }
	$marker = if ($State.Dirty) { ' *' } else { '' }
	$window.Title = "Autopilot Branding Builder - $name$marker"
}

function Update-Status {
	$enabled = @($State.Definitions | Where-Object { $State.Configuration.Tasks[$_.Name].Enabled }).Count
	$relativeTo = if ($State.ConfigPath) { Get-BasePath } else { 'the default template' }
	$ui.StatusText.Text = "$enabled of $($State.Definitions.Count) tasks enabled.  Paths are relative to $relativeTo"
}

function Set-TaskEnabled([string] $TaskName, [bool] $Enabled) {
	$entry = $State.Configuration.Tasks[$TaskName]
	if ([bool]$entry.Enabled -eq $Enabled) {
		return
	}
	$entry.Enabled = $Enabled
	$wasLoading = $State.Loading
	$State.Loading = $true
	try {
		if ($State.ListCheckBoxes.ContainsKey($TaskName)) {
			$State.ListCheckBoxes[$TaskName].IsChecked = $Enabled
		}
		if ($State.SelectedTask -eq $TaskName -and $State.DetailEnabledCheckBox) {
			$State.DetailEnabledCheckBox.IsChecked = $Enabled
		}
	}
	finally {
		$State.Loading = $wasLoading
	}
	Set-Dirty
	Update-Status
}

function Set-ParameterValue([string] $TaskName, $Definition, $Value) {
	try {
		$converted = ConvertTo-ABParameterValue -Definition $Definition -Value $Value
	}
	catch {
		# Not a valid value for the parameter type (e.g. while typing a number); keep the previous value
		return
	}
	$State.Configuration.Tasks[$TaskName].Parameters[$Definition.Name] = $converted
	Set-Dirty
}

function Confirm-Discard {
	if (-not $State.Dirty) {
		return $true
	}
	$answer = Show-ABUIMessage -Text ('Save changes to the current configuration?') -Caption 'Autopilot Branding Builder' -Buttons 'YesNoCancel' -Icon 'Question'
	switch ($answer) {
		'Yes' { return (Save-Configuration) }
		'No' { return $true }
		default { return $false }
	}
}

#endregion


#region Configuration load/save

function Set-Configuration($Configuration, [string] $Path) {
	$State.Configuration = $Configuration
	$State.ConfigPath = $Path
	# Generate into the configuration's (project's) Output folder by default
	$ui.OutputPathBox.Text = if ($Path) { Join-Path (Split-Path -Path $Path -Parent) 'Output' } else { '' }
	$State.Dirty = $false
	Show-TaskList
	Update-Title
	Update-Status
}

function Save-Configuration([switch] $SaveAs, [string] $Path) {
	# Saves to -Path if specified (e.g. by the tests), otherwise to the current file or a file chosen in a dialog.
	# When the configuration moves to another folder, template files it uses are copied there (so saving the default
	# template creates a project) and other file and folder parameters are rebased.
	if (-not $Path) {
		$Path = $State.ConfigPath
	} else {
		$SaveAs = $false
	}
	if ($SaveAs -or -not $path) {
		$dialog = New-Object Microsoft.Win32.SaveFileDialog
		$dialog.Filter = 'JSON configuration (*.json)|*.json|All files (*.*)|*.*'
		$dialog.DefaultExt = '.json'
		$dialog.FileName = if ($path) { Split-Path $path -Leaf } else { 'AutopilotBranding.json' }
		$dialog.InitialDirectory = Get-DialogFolder
		$dialog.Title = if ($State.ConfigPath) { 'Save the configuration' } else { 'Save the configuration in a project folder (the files it uses are copied there)' }
		if (-not $dialog.ShowDialog($window)) {
			return $false
		}
		$path = $dialog.FileName
	}

	$path = ConvertTo-ABFullPath $path
	$oldBase = Get-BasePath
	$newBase = Split-Path -Path $path -Parent
	if (Test-ABPathUnder -Path $newBase -Folder (Get-ABTemplatePath)) {
		throw "Don't save into the module's template folder; choose a project folder instead."
	}
	$oldOutput = $ui.OutputPathBox.Text
	if ($oldBase -ne $newBase) {
		Update-ABAssetBase -Configuration $State.Configuration -TaskDefinitions $State.Definitions -OldBase $oldBase -NewBase $newBase
	}
	Save-ABConfiguration -Configuration $State.Configuration -Path $path
	$State.ConfigPath = $path
	if (-not $oldOutput -or $oldOutput -eq (Join-Path $oldBase 'Output')) {
		$ui.OutputPathBox.Text = Join-Path $newBase 'Output'
	}
	Set-Dirty $false
	Update-Status
	if ($State.SelectedTask) {
		Show-TaskDetail $State.SelectedTask
	}
	$ui.StatusText.Text = "Saved $path"
	return $true
}

#endregion


#region Task list and details

function Show-TaskList {
	$wasLoading = $State.Loading
	$State.Loading = $true
	try {
		$selected = $State.SelectedTask
		$ui.TaskList.Items.Clear()
		$State.ListCheckBoxes = @{}
		foreach ($definition in $State.Definitions) {
			$checkBox = New-Object System.Windows.Controls.CheckBox
			$checkBox.IsChecked = [bool]$State.Configuration.Tasks[$definition.Name].Enabled
			$checkBox.VerticalAlignment = 'Top'
			$checkBox.Margin = '0,2,8,0'
			$checkBox.Tag = $definition.Name
			$checkBox.ToolTip = 'Run this task'
			$checkBox.Add_Click({
					param($sender, $e)
					if (-not $State.Loading) {
						Set-TaskEnabled -TaskName $sender.Tag -Enabled ([bool]$sender.IsChecked)
					}
				})
			$State.ListCheckBoxes[$definition.Name] = $checkBox

			$name = New-Object System.Windows.Controls.TextBlock
			$name.Text = $definition.Name
			$name.FontWeight = 'SemiBold'
			$synopsis = New-Object System.Windows.Controls.TextBlock
			$synopsis.Text = $definition.Synopsis
			$synopsis.TextWrapping = 'Wrap'
			$synopsis.FontSize = 11
			$synopsis.Foreground = New-Brush '#666666'
			$text = New-Object System.Windows.Controls.StackPanel
			$text.Children.Add($name) | Out-Null
			$text.Children.Add($synopsis) | Out-Null

			$panel = New-Object System.Windows.Controls.DockPanel
			[System.Windows.Controls.DockPanel]::SetDock($checkBox, 'Left')
			$panel.Children.Add($checkBox) | Out-Null
			$panel.Children.Add($text) | Out-Null

			$item = New-Object System.Windows.Controls.ListBoxItem
			$item.Content = $panel
			$item.Tag = $definition.Name
			$item.Padding = '4'
			$ui.TaskList.Items.Add($item) | Out-Null
			if ($definition.Name -eq $selected) {
				$ui.TaskList.SelectedItem = $item
			}
		}
	}
	finally {
		$State.Loading = $wasLoading
	}
	if (-not $ui.TaskList.SelectedItem -and $ui.TaskList.Items.Count -gt 0) {
		$ui.TaskList.SelectedIndex = 0
	} elseif ($ui.TaskList.SelectedItem) {
		Show-TaskDetail $ui.TaskList.SelectedItem.Tag
	}
}

function Add-DetailText([string] $Text, [double] $Size = 13, [string] $Weight = 'Normal', [string] $Color = '#000000', [string] $Margin = '0,0,0,6') {
	$block = New-Object System.Windows.Controls.TextBlock
	$block.Text = $Text
	$block.TextWrapping = 'Wrap'
	$block.FontSize = $Size
	$block.FontWeight = $Weight
	$block.Foreground = New-Brush $Color
	$block.Margin = $Margin
	$ui.DetailPanel.Children.Add($block) | Out-Null
	$block
}

function New-ParameterEditor([string] $TaskName, $Definition, $Value) {
	$tag = @{ Task = $TaskName; Parameter = $Definition }

	if ($Definition.Kind -in 'Boolean', 'Switch') {
		$checkBox = New-Object System.Windows.Controls.CheckBox
		$checkBox.Content = 'Enabled'
		$checkBox.IsChecked = [bool]$Value
		$checkBox.Tag = $tag
		$checkBox.Add_Click({
				param($sender, $e)
				if (-not $State.Loading) {
					Set-ParameterValue -TaskName $sender.Tag.Task -Definition $sender.Tag.Parameter -Value ([bool]$sender.IsChecked)
				}
			})
		return $checkBox
	}

	if ($Definition.ValidateSet) {
		$combo = New-Object System.Windows.Controls.ComboBox
		$combo.MinWidth = 200
		$combo.HorizontalAlignment = 'Left'
		foreach ($option in $Definition.ValidateSet) {
			$combo.Items.Add($option) | Out-Null
		}
		$combo.SelectedItem = [string]$Value
		$combo.Tag = $tag
		$combo.Add_SelectionChanged({
				param($sender, $e)
				if (-not $State.Loading) {
					Set-ParameterValue -TaskName $sender.Tag.Task -Definition $sender.Tag.Parameter -Value ([string]$sender.SelectedItem)
				}
			})
		return $combo
	}

	$textBox = New-Object System.Windows.Controls.TextBox
	$textBox.Tag = $tag
	if ($Definition.Kind -eq 'StringArray') {
		$textBox.AcceptsReturn = $true
		$textBox.TextWrapping = 'NoWrap'
		$textBox.MinHeight = 90
		$textBox.MaxHeight = 260
		$textBox.VerticalScrollBarVisibility = 'Auto'
		$textBox.HorizontalScrollBarVisibility = 'Auto'
		$textBox.FontFamily = 'Consolas'
		$textBox.Text = (@($Value) -join "`r`n")
	} else {
		$textBox.Text = [string]$Value
		$textBox.Padding = '2'
	}
	$textBox.Add_TextChanged({
			param($sender, $e)
			if (-not $State.Loading) {
				Set-ParameterValue -TaskName $sender.Tag.Task -Definition $sender.Tag.Parameter -Value $sender.Text
			}
		})

	if (-not $Definition.AssetKind) {
		return $textBox
	}

	# File or folder: text box plus a Browse button
	$browse = New-Object System.Windows.Controls.Button
	$browse.Content = 'Browse...'
	$browse.Padding = '8,2'
	$browse.Margin = '4,0,0,0'
	$browse.Tag = @{ Parameter = $Definition; TextBox = $textBox }
	$browse.Add_Click({
			param($sender, $e)
			Invoke-Safely {
				$definition = $sender.Tag.Parameter
				$box = $sender.Tag.TextBox
				$base = Get-BasePath
				$current = $null
				if ($box.Text) {
					$current = Resolve-ABAssetPath -Path $box.Text -BasePath $base
				}
				$selectedPath = $null
				if ($definition.AssetKind -eq 'Folder') {
					$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
					$dialog.Description = "Select the folder for $($definition.Name)"
					if ($current -and (Test-Path $current)) { $dialog.SelectedPath = $current }
					if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
						$selectedPath = $dialog.SelectedPath
					}
				} else {
					$dialog = New-Object Microsoft.Win32.OpenFileDialog
					$dialog.Filter = 'All files (*.*)|*.*'
					$dialog.Title = "Select the file for $($definition.Name)"
					if ($current -and (Test-Path $current)) {
						$dialog.InitialDirectory = Split-Path $current -Parent
						$dialog.FileName = Split-Path $current -Leaf
					} else {
						$dialog.InitialDirectory = $base
					}
					if ($dialog.ShowDialog($window)) {
						$selectedPath = $dialog.FileName
					}
				}
				if ($selectedPath) {
					# Store paths inside the configuration's folder as relative paths
					$box.Text = Get-ABRelativePath -Path $selectedPath -BasePath $base
				}
			}
		})

	$panel = New-Object System.Windows.Controls.DockPanel
	[System.Windows.Controls.DockPanel]::SetDock($browse, 'Right')
	$panel.Children.Add($browse) | Out-Null
	$panel.Children.Add($textBox) | Out-Null
	return $panel
}

function Show-TaskDetail([string] $TaskName) {
	$State.SelectedTask = $TaskName
	$State.DetailEnabledCheckBox = $null
	$ui.DetailPanel.Children.Clear()
	$definition = Get-TaskDefinition $TaskName
	if (-not $definition) {
		return
	}
	$entry = $State.Configuration.Tasks[$TaskName]

	$wasLoading = $State.Loading
	$State.Loading = $true
	try {
		Add-DetailText -Text $definition.Name -Size 22 -Weight 'SemiBold' -Margin '0,0,0,4' | Out-Null
		Add-DetailText -Text $definition.Synopsis -Size 14 | Out-Null
		if ($definition.Description) {
			Add-DetailText -Text $definition.Description -Color '#555555' | Out-Null
		}

		$enabled = New-Object System.Windows.Controls.CheckBox
		$enabled.Content = 'Run this task'
		$enabled.FontWeight = 'SemiBold'
		$enabled.Margin = '0,6,0,12'
		$enabled.IsChecked = [bool]$entry.Enabled
		$enabled.Tag = $TaskName
		$enabled.Add_Click({
				param($sender, $e)
				if (-not $State.Loading) {
					Set-TaskEnabled -TaskName $sender.Tag -Enabled ([bool]$sender.IsChecked)
				}
			})
		$ui.DetailPanel.Children.Add($enabled) | Out-Null
		$State.DetailEnabledCheckBox = $enabled

		Add-DetailText -Text 'Parameters' -Size 16 -Weight 'SemiBold' -Margin '0,4,0,8' | Out-Null
		if ($definition.Parameters.Count -eq 0) {
			Add-DetailText -Text 'This task has no parameters.' -Color '#666666' | Out-Null
		}

		foreach ($p in $definition.Parameters) {
			$value = if ($entry.Parameters.Contains($p.Name)) { $entry.Parameters[$p.Name] } else { $p.DefaultValue }

			$stack = New-Object System.Windows.Controls.StackPanel

			$header = New-Object System.Windows.Controls.TextBlock
			$header.TextWrapping = 'Wrap'
			$nameRun = New-Object System.Windows.Documents.Run ("-$($p.Name)")
			$nameRun.FontWeight = 'SemiBold'
			$header.Inlines.Add($nameRun)
			$typeText = "  [$($p.TypeName)]"
			if ($p.AssetKind) { $typeText += " ($($p.AssetKind.ToLower()))" }
			$typeRun = New-Object System.Windows.Documents.Run ($typeText)
			$typeRun.Foreground = New-Brush '#777777'
			$header.Inlines.Add($typeRun)
			if ($p.Mandatory) {
				$requiredRun = New-Object System.Windows.Documents.Run ('  required')
				$requiredRun.Foreground = New-Brush '#B00020'
				$header.Inlines.Add($requiredRun)
			}
			$stack.Children.Add($header) | Out-Null

			if ($p.HelpText) {
				$help = New-Object System.Windows.Controls.TextBlock
				$help.Text = $p.HelpText
				$help.TextWrapping = 'Wrap'
				$help.Foreground = New-Brush '#555555'
				$help.Margin = '0,2,0,4'
				$stack.Children.Add($help) | Out-Null
			}

			$editor = New-ParameterEditor -TaskName $TaskName -Definition $p -Value $value
			$stack.Children.Add($editor) | Out-Null

			$defaultText = Format-Value $p.DefaultValue
			if ($defaultText -and $p.Kind -ne 'Switch') {
				$default = New-Object System.Windows.Controls.TextBlock
				$default.Text = "Default: $defaultText"
				$default.TextWrapping = 'Wrap'
				$default.FontSize = 11
				$default.Foreground = New-Brush '#888888'
				$default.Margin = '0,2,0,0'
				$stack.Children.Add($default) | Out-Null
			}

			$border = New-Object System.Windows.Controls.Border
			$border.BorderBrush = New-Brush '#DDDDDD'
			$border.BorderThickness = '1'
			$border.CornerRadius = '4'
			$border.Padding = '10'
			$border.Margin = '0,0,0,10'
			$border.Child = $stack
			$ui.DetailPanel.Children.Add($border) | Out-Null
		}
	}
	finally {
		$State.Loading = $wasLoading
	}
}

#endregion


function Initialize-ABBuilderWindow {
	<#
	.SYNOPSIS
	Creates the builder window, wires up its event handlers, and loads the initial configuration.
	.DESCRIPTION
	The window, its controls and the UI state are kept in module-scope variables ($script:window, $script:ui,
	$script:State) so that the event handlers and helper functions can reach them.  Show-AutopilotBrandingBuilder
	calls this and then shows the window.
	#>
	[CmdletBinding()]
	param (
		[string] $ConfigPath,
		[string] $OutputPath
	)

	Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

	$script:State = @{
		Definitions    = @(Get-ABTaskDefinition)
		Configuration  = $null
		ConfigPath     = $null
		Dirty          = $false
		Loading        = $false
		SelectedTask   = $null
		ListCheckBoxes = @{}
	}

	#region XAML

	[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Autopilot Branding Builder" Height="780" Width="1180" MinHeight="500" MinWidth="800"
        WindowStartupLocation="CenterScreen" FontSize="13">
  <DockPanel>
    <ToolBarTray DockPanel.Dock="Top">
      <ToolBar>
        <Button x:Name="NewProjectButton" Content="New project..." Padding="8,2" ToolTip="Create a project folder from the default template (configuration and sample files) and open it"/>
        <Button x:Name="NewButton" Content="New" Padding="8,2" ToolTip="Start a new configuration with all tasks disabled"/>
        <Button x:Name="OpenButton" Content="Open..." Padding="8,2" ToolTip="Open a JSON configuration file"/>
        <Button x:Name="SaveButton" Content="Save" Padding="8,2" ToolTip="Save the configuration"/>
        <Button x:Name="SaveAsButton" Content="Save As..." Padding="8,2" ToolTip="Save the configuration to a new JSON file"/>
        <Separator/>
        <Button x:Name="ImportButton" Content="Import Config.xml..." Padding="8,2" ToolTip="Convert a v3 Config.xml file"/>
        <Separator/>
        <Button x:Name="ValidateButton" Content="Validate" Padding="8,2" ToolTip="Check the configuration for problems"/>
      </ToolBar>
    </ToolBarTray>
    <StatusBar DockPanel.Dock="Bottom">
      <StatusBarItem>
        <TextBlock x:Name="StatusText"/>
      </StatusBarItem>
    </StatusBar>
    <Border DockPanel.Dock="Bottom" Padding="8" BorderThickness="0,1,0,0" BorderBrush="#DDDDDD">
      <DockPanel>
        <Button x:Name="GenerateButton" DockPanel.Dock="Right" Content="Generate output and .intunewin" Padding="14,4" Margin="8,0,0,0" FontWeight="SemiBold"
                ToolTip="Generate the output folder and package it as AutopilotBranding.intunewin in the output folder's parent folder"/>
        <Button x:Name="BrowseOutputButton" DockPanel.Dock="Right" Content="Browse..." Padding="8,2" Margin="4,0,0,0"/>
        <TextBlock DockPanel.Dock="Left" Text="Output folder:" VerticalAlignment="Center" Margin="0,0,8,0"/>
        <TextBox x:Name="OutputPathBox" VerticalContentAlignment="Center"/>
      </DockPanel>
    </Border>
    <Grid>
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="340" MinWidth="200"/>
        <ColumnDefinition Width="5"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <DockPanel Grid.Column="0">
        <DockPanel DockPanel.Dock="Top" Margin="8,8,8,4">
          <Button x:Name="NoneButton" DockPanel.Dock="Right" Content="None" Padding="6,0" Margin="4,0,0,0"/>
          <Button x:Name="AllButton" DockPanel.Dock="Right" Content="All" Padding="6,0"/>
          <TextBlock Text="Configuration tasks" FontWeight="SemiBold" VerticalAlignment="Center"/>
        </DockPanel>
        <ListBox x:Name="TaskList" Margin="8,0,0,8" ScrollViewer.HorizontalScrollBarVisibility="Disabled"/>
      </DockPanel>
      <GridSplitter Grid.Column="1" HorizontalAlignment="Stretch" Background="#EEEEEE"/>
      <ScrollViewer Grid.Column="2" VerticalScrollBarVisibility="Auto" Margin="0,8,0,8">
        <StackPanel x:Name="DetailPanel" Margin="16,0,16,16"/>
      </ScrollViewer>
    </Grid>
  </DockPanel>
</Window>
'@

	$script:window = [System.Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
	$script:ui = @{}
	foreach ($name in 'NewProjectButton', 'NewButton', 'OpenButton', 'SaveButton', 'SaveAsButton', 'ImportButton', 'ValidateButton', 'StatusText',
		'GenerateButton', 'BrowseOutputButton', 'OutputPathBox', 'NoneButton', 'AllButton', 'TaskList', 'DetailPanel') {
		$ui[$name] = $window.FindName($name)
	}
	$ui.OutputPathBox.Text = $OutputPath

	#endregion

	#region Event handlers

	$ui.TaskList.Add_SelectionChanged({
			param($sender, $e)
			if ($sender.SelectedItem) {
				Invoke-Safely { Show-TaskDetail $sender.SelectedItem.Tag }
			}
		})

	$ui.AllButton.Add_Click({
			foreach ($definition in $State.Definitions) { Set-TaskEnabled -TaskName $definition.Name -Enabled $true }
		})

	$ui.NoneButton.Add_Click({
			foreach ($definition in $State.Definitions) { Set-TaskEnabled -TaskName $definition.Name -Enabled $false }
		})

	$ui.NewProjectButton.Add_Click({
			Invoke-Safely {
				if (-not (Confirm-Discard)) { return }
				$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
				$dialog.Description = 'Select or create the project folder (the default configuration and sample files are copied there)'
				$dialog.SelectedPath = Get-DialogFolder
				if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
				$project = $dialog.SelectedPath
				$configPath = Join-Path $project 'AutopilotBranding.json'
				if (Test-Path -LiteralPath $configPath) {
					Show-ABUIMessage -Text "$project already contains a project; opening it." -Caption 'New project' | Out-Null
				} else {
					New-AutopilotBrandingProject -Path $project | Out-Null
				}
				Set-Configuration -Configuration (Read-ABConfiguration -Path $configPath -TaskDefinitions $State.Definitions) -Path $configPath
				$ui.StatusText.Text = "Opened project $project"
			}
		})

	$ui.NewButton.Add_Click({
			Invoke-Safely {
				if (-not (Confirm-Discard)) { return }
				$configuration = New-ABConfiguration -TaskDefinitions $State.Definitions
				foreach ($key in @($configuration.Tasks.Keys)) { $configuration.Tasks[$key].Enabled = $false }
				Set-Configuration -Configuration $configuration -Path $null
			}
		})

	$ui.OpenButton.Add_Click({
			Invoke-Safely {
				if (-not (Confirm-Discard)) { return }
				$dialog = New-Object Microsoft.Win32.OpenFileDialog
				$dialog.Filter = 'JSON configuration (*.json)|*.json|All files (*.*)|*.*'
				$dialog.InitialDirectory = Get-DialogFolder
				if ($dialog.ShowDialog($window)) {
					$configuration = Read-ABConfiguration -Path $dialog.FileName -TaskDefinitions $State.Definitions
					Set-Configuration -Configuration $configuration -Path $dialog.FileName
				}
			}
		})

	$ui.SaveButton.Add_Click({ Invoke-Safely { Save-Configuration | Out-Null } })

	$ui.SaveAsButton.Add_Click({ Invoke-Safely { Save-Configuration -SaveAs | Out-Null } })

	$ui.ImportButton.Add_Click({
			Invoke-Safely {
				if (-not (Confirm-Discard)) { return }
				$dialog = New-Object Microsoft.Win32.OpenFileDialog
				$dialog.Filter = 'Config.xml (*.xml)|*.xml|All files (*.*)|*.*'
				$dialog.Title = 'Select a v3 AutopilotBranding Config.xml file'
				if ($dialog.ShowDialog($window)) {
					$configuration = ConvertFrom-ABLegacyConfig -Path $dialog.FileName -TaskDefinitions $State.Definitions
					Set-Configuration -Configuration $configuration -Path $null
					Set-Dirty
					Show-ABUIMessage -Text ("Imported $($dialog.FileName).`r`n`r`nFile and folder parameters point at the files next to Config.xml.  Review the tasks, then save the configuration.") -Caption 'Autopilot Branding Builder' -Buttons 'OK' -Icon 'Information' | Out-Null
				}
			}
		})

	$ui.ValidateButton.Add_Click({
			Invoke-Safely {
				$problems = @(Test-ABConfiguration -Configuration $State.Configuration -BasePath (Get-BasePath) -TaskDefinitions $State.Definitions)
				if ($problems.Count -eq 0) {
					Show-ABUIMessage -Text ('No problems found.') -Caption 'Validate' -Buttons 'OK' -Icon 'Information' | Out-Null
				} else {
					$text = ($problems | ForEach-Object { "[$($_.Severity)] $($_.Task) -$($_.Parameter): $($_.Message)" }) -join "`r`n"
					Show-ABUIMessage -Text ($text) -Caption 'Validate' -Buttons 'OK' -Icon 'Warning' | Out-Null
				}
			}
		})

	$ui.BrowseOutputButton.Add_Click({
			$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
			$dialog.Description = 'Select the output folder'
			if ($ui.OutputPathBox.Text -and (Test-Path $ui.OutputPathBox.Text)) { $dialog.SelectedPath = $ui.OutputPathBox.Text }
			if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
				$ui.OutputPathBox.Text = $dialog.SelectedPath
			}
		})

	$ui.GenerateButton.Add_Click({
			Invoke-Safely {
				if (-not $State.ConfigPath) {
					Show-ABUIMessage -Text 'Save the configuration first: saving it in a folder creates a project there (with the files the configuration uses), and the output is generated from that project.' -Caption 'Generate output' | Out-Null
					return
				}
				$output = $ui.OutputPathBox.Text.Trim()
				if (-not $output) {
					throw 'Specify an output folder.'
				}
				if (-not [System.IO.Path]::IsPathRooted($output)) {
					$output = Join-Path (Get-BasePath) $output
				}

				$problems = @(Test-ABConfiguration -Configuration $State.Configuration -BasePath (Get-BasePath) -TaskDefinitions $State.Definitions)
				$errors = @($problems | Where-Object { $_.Severity -eq 'Error' })
				if ($errors.Count -gt 0) {
					$text = ($errors | ForEach-Object { "$($_.Task) -$($_.Parameter): $($_.Message)" }) -join "`r`n"
					Show-ABUIMessage -Text ("Fix these problems before generating the output:`r`n`r`n$text") -Caption 'Generate output' -Buttons 'OK' -Icon 'Warning' | Out-Null
					return
				}

				if ((Test-Path $output) -and @(Get-ChildItem -Path $output -Force).Count -gt 0) {
					$answer = Show-ABUIMessage -Text ("The folder $output is not empty.  Replace its contents?") -Caption 'Generate output' -Buttons 'YesNo' -Icon 'Question'
					if ($answer -ne 'Yes') { return }
				}

				if (Test-ABPathUnder -Path (ConvertTo-ABFullPath $output) -Folder (Get-ABTemplatePath)) {
					throw "Don't generate into the module's template folder; choose another output folder."
				}
				$packageFolder = Split-Path -Path (ConvertTo-ABFullPath $output) -Parent
				if (-not $packageFolder) {
					throw 'The output folder must not be the root of a drive (the .intunewin file is created in its parent folder).'
				}

				$window.Cursor = [System.Windows.Input.Cursors]::Wait
				try {
					$ui.StatusText.Text = 'Generating output...'
					$result = New-ABOutput -Configuration $State.Configuration -BasePath (Get-BasePath) -OutputPath $output -Force
					$ui.StatusText.Text = 'Creating .intunewin package...'
					$intunewin = New-ABIntuneWinPackage -SourcePath $result.OutputPath -DestinationPath $packageFolder -SetupFile (Split-Path $result.RunnerScript -Leaf)
				}
				finally {
					$window.Cursor = $null
				}

				$ui.StatusText.Text = "Output generated in $($result.OutputPath); package created: $intunewin"
				$message = "Output generated in $($result.OutputPath) ($($result.EnabledTasks.Count) tasks).`r`n`r`nIntune package created: $intunewin"
				$answer = Show-ABUIMessage -Text ("$message`r`n`r`nOpen the folder?") -Caption 'Generate output' -Buttons 'YesNo' -Icon 'Information'
				if ($answer -eq 'Yes') {
					Start-Process explorer.exe -ArgumentList "/select,`"$intunewin`""
				}
			}
		})

	$window.Add_Closing({
			param($sender, $e)
			if (-not (Confirm-Discard)) {
				$e.Cancel = $true
			}
		})

	#endregion


	# Load the initial configuration
	try {
		if ($ConfigPath -and (Test-Path $ConfigPath)) {
			$fullPath = (Resolve-Path $ConfigPath).Path
			Set-Configuration -Configuration (Read-ABConfiguration -Path $fullPath -TaskDefinitions $State.Definitions) -Path $fullPath
		} else {
			# No configuration: start from the module's default template (unsaved; saving it creates a project)
			if ($ConfigPath) { throw "Configuration file not found: $ConfigPath" }
			$templateConfig = Join-Path (Get-ABTemplatePath) 'AutopilotBranding.json'
			Set-Configuration -Configuration (Read-ABConfiguration -Path $templateConfig -TaskDefinitions $State.Definitions) -Path $null
		}
		if ($OutputPath) {
			$ui.OutputPathBox.Text = $OutputPath
		}
	}
	catch {
		Show-ABUIMessage -Text ("Unable to load $($ConfigPath): $_") -Caption 'Autopilot Branding Builder' -Buttons 'OK' -Icon 'Error' | Out-Null
		Set-Configuration -Configuration (New-ABConfiguration -TaskDefinitions $State.Definitions) -Path $null
	}
}

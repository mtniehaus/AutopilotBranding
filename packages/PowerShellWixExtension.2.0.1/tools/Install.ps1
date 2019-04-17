# Created by Alexander Köplinger, 2013

param($installPath, $toolsPath, $package, $project)

# ensure that we are installing into a WiX project
if ($project.Kind -ne '{930c7802-8a8c-48f9-8165-68863bccd9dd}')
{
    throw "'$($project.Name)' is not a WiX project! This package will only work on WiX projects."
}

# remove dummy file from project
$dummy = $project.ProjectItems.Item("PowerShellWixExtension.DummyFile.txt").Delete()

$msBuildProj = @([Microsoft.Build.Evaluation.ProjectCollection]::GlobalProjectCollection.GetLoadedProjects($project.FullName))[0]

# remove previous changes (for cases where Uninstall.ps1 wasn't executed properly)
Import-Module (Join-Path $toolsPath "Remove.psm1")
Remove-Changes $msBuildProj

# add the property group directly before the WixTargetsPath-Import, according to http://wixtoolset.org/documentation/manual/v3/msbuild/daily_builds.html
$itemGroup = $msBuildProj.Xml.CreateItemGroupElement()

$wixImport = $msBuildProj.Xml.Children | Where-Object { $_.Project -eq '$(WixTargetsPath)' }
$msBuildProj.Xml.InsertBeforeChild($itemGroup, $wixImport)

# Calculate relative path to package from project
$projectDir = [System.IO.Path]::GetDirectoryName($project.FullName)

Push-Location $projectDir 

$hintPath = Resolve-Path ($toolsPath + '\lib\PowerShellWixExtension.dll') -Relative

Pop-Location 

#    <WixExtension Include="PowerShellWixExtension">
#      <HintPath>..\..\Libs\PowerShellWixExtension\PowerShellWixExtension.dll</HintPath>
#      <Name>PowerShellWixExtension</Name>
#    </WixExtension>

$metadata = New-Object 'System.Collections.Generic.Dictionary[String, String]'
$metadata.Add("HintPath", $hintPath)
$metadata.Add("Name", "PowerShellWixExtension")
$itemGroup.AddItem('WixExtension', 'PowerShellWixExtension', $metadata)

# save changes
$project.Save($null)
$msBuildProj.ReevaluateIfNecessary()
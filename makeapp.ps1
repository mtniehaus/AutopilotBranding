[CmdletBinding()]
param(
    [Parameter(Mandatory = $True)] [string] $SourceFolder,
    [Parameter(Mandatory = $True)] [string] $SetupFile,
    [Parameter(Mandatory = $False)] [string] $OutputFolder = ""
)

Install-Module IntuneWin32App
Import-Module IntuneWin32App

if ($OutputFolder -eq "") {
    $OutputFolder = $PSScriptRoot
}
New-IntuneWin32AppPackage -SourceFolder $SourceFolder -SetupFile $SetupFile -OutputFolder $OutputFolder -Force

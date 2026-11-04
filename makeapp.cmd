@echo off
setlocal
rem Builds the Intune app: loads the AutopilotBranding module from this folder and runs Build-AutopilotBranding
rem (alias for New-AutopilotBrandingPackage) on a project folder, which generates <project>\Output (module, assets,
rem runner script) and packages it as <project>\AutopilotBranding.intunewin.
rem   makeapp.cmd [project folder]
rem The project folder defaults to .\Project next to this script; if it doesn't contain a project yet, one is created
rem from the module's default template (configuration and sample files).
rem Uses PowerShell 7 (pwsh.exe) if it is installed, otherwise Windows PowerShell 5.1 (powershell.exe).
rem Set AB_POWERSHELL to the PowerShell executable to use a specific one.
set "AB_ROOT=%~dp0"
set "AB_PROJECT=%~1"
if not defined AB_PROJECT set "AB_PROJECT=%~dp0Project"
set "PS=%AB_POWERSHELL%"
if not defined PS where pwsh.exe >nul 2>&1 && set "PS=pwsh.exe"
if not defined PS set "PS=powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -Command "& { $ErrorActionPreference = 'Stop'; Import-Module (Join-Path $env:AB_ROOT 'Module\AutopilotBranding\AutopilotBranding.psd1') -Force; if (-not (Test-Path -LiteralPath (Join-Path $env:AB_PROJECT 'AutopilotBranding.json'))) { New-AutopilotBrandingProject -Path $env:AB_PROJECT | Out-Null }; Build-AutopilotBranding -ProjectPath $env:AB_PROJECT }"
exit /b %ERRORLEVEL%

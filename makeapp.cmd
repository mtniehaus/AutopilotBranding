@echo off
setlocal
rem Builds the Intune app: loads the AutopilotBranding module from this folder and runs Build-AutopilotBranding
rem (alias for New-AutopilotBrandingPackage),
rem which generates the Output folder (module, assets, runner script) from AutopilotBranding.json and packages it
rem as AutopilotBranding.intunewin in this folder.
rem Uses PowerShell 7 (pwsh.exe) if it is installed, otherwise Windows PowerShell 5.1 (powershell.exe).
rem Set AB_POWERSHELL to the PowerShell executable to use a specific one.
set "AB_ROOT=%~dp0"
set "PS=%AB_POWERSHELL%"
if not defined PS where pwsh.exe >nul 2>&1 && set "PS=pwsh.exe"
if not defined PS set "PS=powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -Command "& { $ErrorActionPreference = 'Stop'; Import-Module (Join-Path $env:AB_ROOT 'Module\AutopilotBranding\AutopilotBranding.psd1') -Force; Build-AutopilotBranding -ConfigPath (Join-Path $env:AB_ROOT 'AutopilotBranding.json') -OutputPath (Join-Path $env:AB_ROOT 'Output') }"
exit /b %ERRORLEVEL%

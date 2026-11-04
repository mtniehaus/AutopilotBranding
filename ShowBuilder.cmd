@echo off
setlocal
rem Starts the Autopilot Branding builder UI: loads the AutopilotBranding module from this folder and runs
rem Show-AutopilotBrandingBuilder with AutopilotBranding.json.
rem Uses PowerShell 7 (pwsh.exe) if it is installed, otherwise Windows PowerShell 5.1 (powershell.exe).
rem Set AB_POWERSHELL to the PowerShell executable to use a specific one.
set "AB_ROOT=%~dp0"
set "PS=%AB_POWERSHELL%"
if not defined PS where pwsh.exe >nul 2>&1 && set "PS=pwsh.exe"
if not defined PS set "PS=powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -Command "& { $ErrorActionPreference = 'Stop'; Import-Module (Join-Path $env:AB_ROOT 'Module\AutopilotBranding\AutopilotBranding.psd1') -Force; Show-AutopilotBrandingBuilder -ConfigPath (Join-Path $env:AB_ROOT 'AutopilotBranding.json') }"
exit /b %ERRORLEVEL%

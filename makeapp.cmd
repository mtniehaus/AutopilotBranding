@echo off
pushd %~dp0
rem Generate the Output folder (module, assets, runner script) from AutopilotBranding.json
rem and package it as AutopilotBranding.intunewin in this folder.
pwsh.exe -noprofile -executionpolicy bypass -file Build-AutopilotBranding.ps1 -ConfigPath .\AutopilotBranding.json -OutputPath .\Output -Package -PackagePath .
set RESULT=%ERRORLEVEL%
popd
exit /b %RESULT%

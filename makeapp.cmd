@echo off
pushd %~dp0
powershell.exe -noprofile -executionpolicy bypass -file makeapp.ps1 -SourceFolder .\AutopilotBranding -SetupFile AutopilotBranding.ps1
popd

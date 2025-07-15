@echo off
pushd %~dp0
pwsh.exe -noprofile -executionpolicy bypass -file makeapp.ps1 -SourceFolder .\AutopilotBranding -SetupFile AutopilotBranding.ps1
popd

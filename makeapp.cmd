@echo off
pushd %~dp0
rem Generate the Output folder (module, assets, runner script) from AutopilotBranding.json
pwsh.exe -noprofile -executionpolicy bypass -file Build-AutopilotBranding.ps1 -ConfigPath .\AutopilotBranding.json -OutputPath .\Output
if errorlevel 1 (
    popd
    exit /b 1
)
rem Package the Output folder as AutopilotBranding.intunewin
pwsh.exe -noprofile -executionpolicy bypass -file makeapp.ps1 -SourceFolder .\Output -SetupFile AutopilotBranding.ps1
popd

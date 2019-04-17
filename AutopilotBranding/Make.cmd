:: Clean output directories
rmdir obj\Debug /s /q
rmdir bin\Debug /s /q

:: Compile and link
"%Wix%\bin\heat.exe" dir .\LPs -cg LPs -ag -srd -dr LPFOLDER -out LPs.wxs
"%Wix%\bin\candle.exe" -out obj\Debug\ -arch x64 -ext ..\packages\PowerShellWixExtension.2.0.1\tools\lib\PowerShellWixExtension.dll Product.wxs LPs.wxs
"%Wix%\bin\light.exe" -out bin\Debug\AutopilotBranding.msi -ext ..\packages\PowerShellWixExtension.2.0.1\tools\lib\PowerShellWixExtension.dll obj\Debug\Product.wixobj obj\debug\LPs.wixobj -b LPs

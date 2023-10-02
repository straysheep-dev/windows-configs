REM Open tools folder
explorer.exe C:\Users\WDAGUtilityAccount\Documents\Tools

REM Enable script execution
cmd.exe /C powershell.exe -c Set-ExecutionPolicy Bypass -Force
REM Execute scripts
cmd.exe /C powershell.exe C:\Users\WDAGUtilityAccount\Documents\Tools\generic-sandbox-setup.ps1

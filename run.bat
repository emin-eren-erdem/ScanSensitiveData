@echo off
:: Check for administrator privileges
openfiles >nul 2>&1
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd.exe -ArgumentList '/c \"%~0\"' -Verb RunAs"
    exit /b
)

:: Define the path to the PowerShell script
set "psScriptPath=ScanSensitiveData.ps1"

:: Run the PowerShell script
powershell -NoProfile -ExecutionPolicy Bypass -File "%psScriptPath%"

@echo off
rem ==============================================================================
rem Windows CMD Launcher for AI Security Architect Pull & Deploy Pipeline
rem ==============================================================================
setlocal EnableDelayedExpansion

set SCRIPT_DIR=%~dp0
set PS_SCRIPT=%SCRIPT_DIR%pull-and-deploy.ps1

if not exist "%PS_SCRIPT%" (
    echo [ERROR] PowerShell deployment script not found: %PS_SCRIPT%
    exit /b 1
)

echo [LAUNCHER] Invoking AI Security Architect Pull and Deploy Pipeline...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
set EXIT_CODE=%ERRORLEVEL%

if %EXIT_CODE% neq 0 (
    echo [ERROR] Pull and Deploy Pipeline exited with error code %EXIT_CODE%
    exit /b %EXIT_CODE%
)

exit /b 0

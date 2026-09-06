@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "TOMAX_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "TOMAX_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%TOMAX_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Ressources\Install-Tomax.ps1" -Uninstall
exit /b %errorlevel%

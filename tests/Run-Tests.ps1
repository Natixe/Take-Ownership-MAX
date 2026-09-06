#Requires -Version 5.1
[CmdletBinding()] param([switch]$Stress)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $repo '.test-output\bin'
[void][IO.Directory]::CreateDirectory($bin)
$exe = Join-Path $bin 'TomaxTests.exe'
$sources = @('Ressources\Native\TomaxNative.cs', 'Ressources\Native\TomaxEngine.cs', 'Ressources\Native\TomaxLocks.cs', 'tests\TomaxTests.cs') | ForEach-Object { Join-Path $repo $_ }
$compiler = @(
    "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe"
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $compiler) { throw 'Compilateur C# .NET Framework 4.x introuvable.' }
& $compiler /nologo /target:exe /warnaserror+ "/out:$exe" /r:System.Runtime.Serialization.dll @sources
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$taskAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$taskLog = Join-Path $repo ('.test-output\progress-' + $(if ($taskAdmin) { 'admin' } else { 'standard' }) + '.txt')
Set-Content -LiteralPath $taskLog -Value "Stress requested: $([bool]$Stress)" -Encoding UTF8
$windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$environmentInfo = "Windows build=$($windows.CurrentBuild).$($windows.UBR); Edition=$($windows.EditionID); PowerShell=$($PSVersionTable.PSVersion)"
Add-Content -LiteralPath $taskLog -Value $environmentInfo -Encoding UTF8
Write-Output $environmentInfo
if ($Stress) {
    & $exe --stress | ForEach-Object { Add-Content -LiteralPath $taskLog -Value $_ -Encoding UTF8; Write-Output $_ }
} else {
    & $exe | ForEach-Object { Add-Content -LiteralPath $taskLog -Value $_ -Encoding UTF8; Write-Output $_ }
}
exit $LASTEXITCODE

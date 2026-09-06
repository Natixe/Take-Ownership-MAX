#Requires -Version 5.1
# Integration tests of the distributed DLL path, command-line transport and exits.
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$testOutput = Join-Path $repo '.test-output'
$run = Join-Path $testOutput ('cli-' + [guid]::NewGuid().ToString('N'))
$package = Join-Path $run "package & [test] 'quote'"
$data = Join-Path $run "data & [test] 'quote'"
[void][IO.Directory]::CreateDirectory($package)
[void][IO.Directory]::CreateDirectory($data)
$file = Join-Path $data 'document.txt'
Set-Content -LiteralPath $file -Value 'original content' -Encoding UTF8
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$results = [Collections.Generic.List[string]]::new()
trap { $results.Add('FAIL ' + ($_ | Out-String)); Set-Content -LiteralPath (Join-Path $testOutput 'latest-cli.txt') -Value $results -Encoding UTF8; exit 1 }
function Check-Exit([int]$Expected, [string]$Name) {
    if ($LASTEXITCODE -ne $Expected) { throw "$Name : code $LASTEXITCODE, attendu $Expected" }
    $results.Add("PASS $Name")
}
$sources = @('TomaxNative.cs','TomaxEngine.cs','TomaxLocks.cs') | ForEach-Object { Join-Path (Join-Path $repo 'Ressources\Native') $_ }
$compiler = @(
    "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe"
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $compiler) { throw 'Compilateur C# .NET Framework 4.x introuvable.' }
& $compiler /nologo /target:library /warnaserror+ "/out:$(Join-Path $package 'Tomax.Native.dll')" /r:System.Runtime.Serialization.dll @sources
Check-Exit 0 'Compilation DLL distribuee'
Copy-Item -LiteralPath (Join-Path $repo 'Ressources\TakeOwnershipMAX.ps1') -Destination $package
$script = Join-Path $package 'TakeOwnershipMAX.ps1'
$backup = Join-Path $run 'backups'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try { $admin = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
finally { $identity.Dispose() }
& $ps -NoProfile -ExecutionPolicy Bypass -File $script -TargetPath $file -BackupDirectory $backup -WhatIf -NoPause
Check-Exit 0 'WhatIf sans elevation ni mutation'
if (Test-Path -LiteralPath $backup) { throw 'WhatIf a cree une sauvegarde.' }
& $ps -NoProfile -ExecutionPolicy Bypass -File $script -Action Resume -NoPause
Check-Exit 1 'Code erreur de parametres'
if ($admin) {
    & $ps -NoProfile -ExecutionPolicy Bypass -File $script -TargetPath $file -Mode Repair -BackupDirectory $backup -Force -NoPause
    Check-Exit 0 'Reparation par DLL, apostrophes, espaces et crochets'
    $operation = (Get-ChildItem -LiteralPath $backup -Directory | Select-Object -First 1).FullName
    $report = Get-Content -LiteralPath (Join-Path $operation 'report.json') -Raw | ConvertFrom-Json
    if (-not $report.Complete -or $report.Succeeded -ne 1) { throw 'Rapport CLI non verifie.' }
    & $ps -NoProfile -ExecutionPolicy Bypass -File $script -Action Restore -OperationDirectory $operation -Force -NoPause
    Check-Exit 0 'Restauration CLI'
    & $ps -NoProfile -ExecutionPolicy Bypass -File $script -ShellTarget ($data + '\|') -Mode Ultimate -BackupDirectory $backup -Force -NoPause
    Check-Exit 0 'Transport Explorer avec antislash final'
    $operation2 = (Get-ChildItem -LiteralPath $backup -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
    & $ps -NoProfile -ExecutionPolicy Bypass -File $script -Action Restore -OperationDirectory $operation2 -Force -NoPause
    Check-Exit 0 'Restauration arborescence via CLI'
}
else { $results.Add('SKIP Reparations et restaurations CLI : administrateur requis') }
$installer = Join-Path $repo 'Ressources\Install-Tomax.ps1'
& $ps -NoProfile -ExecutionPolicy Bypass -File $installer -WhatIf -NoPause
Check-Exit 0 'Installateur en simulation'
& $ps -NoProfile -ExecutionPolicy Bypass -File $installer -Uninstall -WhatIf -NoPause
Check-Exit 0 'Desinstallateur en simulation'
Set-Content -LiteralPath (Join-Path $testOutput 'latest-cli.txt') -Value $results -Encoding UTF8
exit 0

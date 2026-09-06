#Requires -Version 5.1
[CmdletBinding()] param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$dist = Join-Path $PSScriptRoot 'dist'
[void][IO.Directory]::CreateDirectory($dist)
$stage = Join-Path $dist ('package-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)
try {
    foreach ($file in @('Installer_Take_Ownership_MAX.cmd', 'Desinstaller_Take_Ownership_MAX.cmd', 'README.md', 'LICENSE')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $stage
    }
    $resources = Join-Path $stage 'Ressources'
    [void][IO.Directory]::CreateDirectory($resources)
    foreach ($file in @('TakeOwnershipMAX.ps1', 'Install-Tomax.ps1')) {
        Copy-Item -LiteralPath (Join-Path (Join-Path $PSScriptRoot 'Ressources') $file) -Destination $resources
    }
    [void][IO.Directory]::CreateDirectory((Join-Path $resources 'Native'))
    $sources = @('TomaxNative.cs', 'TomaxEngine.cs', 'TomaxLocks.cs') | ForEach-Object {
        $source = Join-Path (Join-Path $PSScriptRoot 'Ressources\Native') $_
        Copy-Item -LiteralPath $source -Destination (Join-Path $resources 'Native')
        $source
    }
    $compiler = @(
        "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $compiler) { throw 'Compilateur C# .NET Framework 4.x introuvable.' }
    $dll = Join-Path $resources 'Tomax.Native.dll'
    & $compiler /nologo /target:library /optimize+ /warnaserror+ "/out:$dll" /r:System.Runtime.Serialization.dll @sources
    if ($LASTEXITCODE -ne 0) { throw 'Compilation echouee.' }
    $zipName = 'TakeOwnershipMAX-ULTIMATE-v3.zip'
    $zip = Join-Path $dist $zipName
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    "$hash  $zipName" | Set-Content -LiteralPath ($zip + '.sha256') -Encoding ASCII
    Write-Output $zip
}
finally {
    $resolved = [IO.Path]::GetFullPath($stage)
    if (-not $resolved.StartsWith([IO.Path]::GetFullPath($dist).TrimEnd('\') + '\package-', [StringComparison]::OrdinalIgnoreCase)) { throw 'Dossier temporaire inattendu.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}

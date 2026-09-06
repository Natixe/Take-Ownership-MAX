#Requires -Version 5.1
[CmdletBinding()] param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$testOutput = Join-Path $repo '.test-output'
$extract = Join-Path $testOutput ('package-' + [guid]::NewGuid().ToString('N'))
$zipName = 'TakeOwnershipMAX-ULTIMATE-v3.zip'
$zip = Join-Path (Join-Path $repo 'dist') $zipName

try {
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'Build.ps1')
    if ($LASTEXITCODE -ne 0) { throw "Build.ps1 a retourne le code $LASTEXITCODE." }
    if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { throw 'Archive absente.' }

    $checksum = Get-Content -LiteralPath ($zip + '.sha256') -Raw
    if ($checksum.Trim() -notmatch '^([A-Fa-f0-9]{64})  TakeOwnershipMAX-ULTIMATE-v3\.zip$') { throw 'Format du fichier SHA-256 invalide.' }
    $actualHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    if ($actualHash -cne $Matches[1].ToUpperInvariant()) { throw 'Empreinte SHA-256 incorrecte.' }

    [void][IO.Directory]::CreateDirectory($extract)
    Expand-Archive -LiteralPath $zip -DestinationPath $extract
    $expected = @(
        'Desinstaller_Take_Ownership_MAX.cmd',
        'Installer_Take_Ownership_MAX.cmd',
        'LICENSE',
        'README.md',
        'Ressources\Install-Tomax.ps1',
        'Ressources\TakeOwnershipMAX.ps1',
        'Ressources\Tomax.Native.dll',
        'Ressources\Native\TomaxEngine.cs',
        'Ressources\Native\TomaxLocks.cs',
        'Ressources\Native\TomaxNative.cs'
    )
    $actual = @(Get-ChildItem -LiteralPath $extract -Recurse -File | ForEach-Object { $_.FullName.Substring($extract.Length + 1) } | Sort-Object)
    $difference = @(Compare-Object ($expected | Sort-Object) $actual)
    if ($difference.Count -ne 0) { throw 'Le contenu de l archive ne correspond pas au manifeste attendu.' }

    [void][Reflection.AssemblyName]::GetAssemblyName((Join-Path $extract 'Ressources\Tomax.Native.dll'))
    Write-Output "PASS Archive, empreinte et manifeste verifies : $zip"
}
finally {
    $resolved = [IO.Path]::GetFullPath($extract)
    $prefix = [IO.Path]::GetFullPath($testOutput).TrimEnd('\') + '\package-'
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Dossier de test inattendu.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}

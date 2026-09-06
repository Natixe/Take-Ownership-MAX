#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param([switch]$Uninstall, [switch]$Elevated, [switch]$NoPause)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$result = 1
$installRoot = Join-Path $env:ProgramFiles 'TakeOwnershipMAX'
$registryPaths = @('*', 'Directory', 'Directory\Background', 'Drive')

function New-InstallDirectory([string]$Path) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl.SetOwner($adminSid)
    foreach ($sid in @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-32-545')) {
        $rights = if ($sid -eq 'S-1-5-32-545') { 'ReadAndExecute' } else { 'FullControl' }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), $rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    [void][IO.Directory]::CreateDirectory($Path, $acl)
}
function Assert-InstallRoot {
    if (-not (Test-Path -LiteralPath $installRoot)) { return }
    $item = Get-Item -LiteralPath $installRoot -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Le dossier d installation est redirige.' }
    $acl = Get-Acl -LiteralPath $installRoot
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-32-544', 'S-1-5-18')) { throw 'Le proprietaire du dossier d installation est inattendu.' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544', 'S-1-5-18') -and
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership')) {
            throw 'Le dossier d installation est modifiable par un utilisateur non administrateur.'
        }
    }
}
function Set-Menu([string]$EnginePath) {
    foreach ($kind in $registryPaths) {
        $relative = "Software\Classes\$kind\shell\TakeOwnershipMAX"
        # Only our own key is replaced. Never remove generic runas or third-party verbs.
        [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($relative, $false)
        $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($relative)
        try {
            $key.SetValue('MUIVerb', 'Take Ownership MAX ULTIMATE')
            $key.SetValue('SubCommands', ''); $key.SetValue('Icon', 'imageres.dll,-78')
            $key.SetValue('HasLUAShield', ''); $key.SetValue('MultiSelectModel', 'Single')
        } finally { $key.Dispose() }
        $verbs = @(
            @{ Key = '01repair'; Title = 'Reparer les acces (avec sauvegarde)'; Arguments = '-Mode Repair' },
            @{ Key = '02ultimate'; Title = 'ULTIMATE : reparer et isoler les permissions'; Arguments = '-Mode Ultimate' }
        )
        if ($kind -eq '*') { $verbs += @{ Key = '03diagnose'; Title = 'Identifier les applications qui utilisent ce fichier'; Arguments = '-Action Diagnose' } }
        $placeholder = if ($kind -eq 'Directory\Background') { '%V' } else { '%1' }
        foreach ($verb in $verbs) {
            $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("$relative\shell\$($verb.Key)")
            try { $key.SetValue('', $verb.Title); $key.SetValue('HasLUAShield', '') } finally { $key.Dispose() }
            $command = '"' + "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" + '" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $EnginePath + '" -FromShell -ShellTarget "' + $placeholder + '|" ' + $verb.Arguments
            $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("$relative\shell\$($verb.Key)\command")
            try { $key.SetValue('', $command) } finally { $key.Dispose() }
        }
    }
}
try {
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'Installation incompatible avec le mode PowerShell contraint de ce PC.' }
    if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Lancez avec Windows PowerShell 5.1 (powershell.exe).' }
    $operation = if ($Uninstall) { 'Desinstaller Take Ownership MAX (sauvegardes conservees)' } else { 'Installer Take Ownership MAX ULTIMATE v3 et son menu contextuel' }
    if (-not $PSCmdlet.ShouldProcess($installRoot, $operation)) { $result = 0; return }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $identity.Dispose()
    if (-not $admin) {
        $scriptPath = $PSCommandPath.Replace("'", "''")
        $command = "& '$scriptPath' -Elevated"
        if ($Uninstall) { $command += ' -Uninstall' }
        if ($NoPause) { $command += ' -NoPause' }
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded" -Verb RunAs -WindowStyle Normal -Wait -PassThru
        $result = $process.ExitCode; $NoPause = $true; return
    }
    Assert-InstallRoot
    if ($Uninstall) {
        foreach ($kind in $registryPaths) { [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree("Software\Classes\$kind\shell\TakeOwnershipMAX", $false) }
        if (Test-Path -LiteralPath $installRoot) {
            $resolved = [IO.Path]::GetFullPath((Get-Item -LiteralPath $installRoot).FullName).TrimEnd('\')
            $expected = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'TakeOwnershipMAX')).TrimEnd('\')
            if ($resolved -cne $expected -or -not (Test-Path -LiteralPath (Join-Path $resolved 'install.json'))) { throw 'Suppression refusee : dossier non reconnu.' }
            $links = @(Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
            if ($links.Count -gt 0) { throw 'Suppression refusee : le dossier contient des liens ou jonctions.' }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
        Write-Host 'Menu et moteur v3 supprimes. Les sauvegardes restent dans ProgramData\TakeOwnershipMAX-Backups.' -ForegroundColor Green
        Write-Host 'Conservez le ZIP pour pouvoir executer une restauration plus tard.'
    }
    else {
        foreach ($file in @('TakeOwnershipMAX.ps1', 'Native\TomaxNative.cs', 'Native\TomaxEngine.cs', 'Native\TomaxLocks.cs')) {
            if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $file) -PathType Leaf)) { throw "Fichier requis absent : $file" }
        }
        if (-not (Test-Path -LiteralPath $installRoot)) { New-InstallDirectory $installRoot }
        $versionDirectory = Join-Path $installRoot ('v3-' + [guid]::NewGuid().ToString('N'))
        New-InstallDirectory $versionDirectory
        $nativeDirectory = Join-Path $versionDirectory 'Native'
        New-InstallDirectory $nativeDirectory
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'TakeOwnershipMAX.ps1') -Destination $versionDirectory
        $sources = @('TomaxNative.cs', 'TomaxEngine.cs', 'TomaxLocks.cs') | ForEach-Object {
            $destination = Join-Path $nativeDirectory $_
            Copy-Item -LiteralPath (Join-Path (Join-Path $PSScriptRoot 'Native') $_) -Destination $destination
            $destination
        }
        $compiler = @(
            "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
            "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\csc.exe"
        ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $compiler) { throw 'Compilateur C# .NET Framework 4.x introuvable.' }
        $dll = Join-Path $versionDirectory 'Tomax.Native.dll'
        & $compiler /nologo /target:library /optimize+ /warnaserror+ "/out:$dll" /r:System.Runtime.Serialization.dll @sources
        if ($LASTEXITCODE -ne 0) { throw 'Compilation du moteur echouee. Le menu existant reste en place.' }
        $enginePath = Join-Path $versionDirectory 'TakeOwnershipMAX.ps1'
        Set-Menu $enginePath
        @{ Version = 3; Engine = $enginePath; InstalledUtc = [DateTime]::UtcNow.ToString('o'); SHA256 = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $installRoot 'install.json') -Encoding UTF8
        Write-Host 'Take Ownership MAX ULTIMATE v3 installe.' -ForegroundColor Green
        Write-Host 'Clic droit > Afficher plus d options > Take Ownership MAX ULTIMATE.'
        Write-Host 'Sauvegardes : ProgramData\TakeOwnershipMAX-Backups (conservees apres desinstallation).'
        foreach ($scope in @('MachinePolicy', 'UserPolicy')) {
            $policy = Get-ExecutionPolicy -Scope $scope
            if ($policy -ne 'Undefined' -and $policy -ne 'Bypass' -and $policy -ne 'Unrestricted') { Write-Host "Strategie $scope = $policy : elle peut empecher le lancement des scripts non signes." -ForegroundColor Yellow }
        }
    }
    $result = 0
}
catch { Write-Host "ERREUR : $($_.Exception.Message)" -ForegroundColor Red }
finally { if (-not $NoPause) { try { [void](Read-Host 'Entree pour fermer') } catch { } }; exit $result }

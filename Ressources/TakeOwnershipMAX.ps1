#Requires -Version 5.1
<# Take Ownership MAX ULTIMATE v3. Native engine; durable backup before writes. #>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Position = 0)][string]$TargetPath,
    [ValidateSet('TakeOwnership', 'Resume', 'Restore', 'Diagnose')][string]$Action = 'TakeOwnership',
    [ValidateSet('Repair', 'Ultimate')][string]$Mode = 'Repair',
    [string]$OperationDirectory,
    [string]$BackupDirectory = "$env:ProgramData\TakeOwnershipMAX-Backups",
    [switch]$IncludeHardLinks, [switch]$OverwriteChanged, [switch]$CloseApplications,
    [switch]$Force, [switch]$NoPause,
    # Internal Explorer/UAC transport. No command text or temporary SID file.
    [string]$ShellTarget, [string]$InternalRequest, [switch]$FromShell, [switch]$Elevated
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$exitCode = 1
$privileges = $null
$requester = $null

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { return [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { $identity.Dispose() }
}
function Compress-Request([string]$Json) {
    $memory = [IO.MemoryStream]::new()
    $zip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionMode]::Compress, $true)
    try { $bytes = [Text.Encoding]::UTF8.GetBytes($Json); $zip.Write($bytes, 0, $bytes.Length) } finally { $zip.Dispose() }
    try { return [Convert]::ToBase64String($memory.ToArray()) } finally { $memory.Dispose() }
}
function Expand-Request([string]$Data) {
    if ($Data.Length -gt 30000) { throw 'Requete interne trop longue.' }
    $memory = [IO.MemoryStream]::new([Convert]::FromBase64String($Data))
    $zip = [IO.Compression.GZipStream]::new($memory, [IO.Compression.CompressionMode]::Decompress)
    $output = [IO.MemoryStream]::new()
    try {
        $buffer = New-Object byte[] 4096
        while (($count = $zip.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($output.Length + $count -gt 1048576) { throw 'Requete interne trop volumineuse.' }
            $output.Write($buffer, 0, $count)
        }
        return [Text.Encoding]::UTF8.GetString($output.ToArray())
    } finally { $output.Dispose(); $zip.Dispose(); $memory.Dispose() }
}
function Confirm-Target([string]$Path) {
    if ($Force) { return }
    $display = [Tomax.Native]::Display($Path)
    $root = [IO.Path]::GetPathRoot($display)
    $critical = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, "$env:SystemDrive\Users", $env:USERPROFILE)
    $sensitive = $display.TrimEnd('\') -eq $root.TrimEnd('\')
    foreach ($entry in $critical) {
        if (-not [string]::IsNullOrWhiteSpace($entry) -and [Tomax.Native]::Within($Path, [Tomax.Native]::Normalize($entry))) { $sensitive = $true }
    }
    if ($sensitive) {
        Write-Host "Emplacement sensible : $display" -ForegroundColor Yellow
        Write-Host 'Les permissions des objets inventories seront modifiees. Une sauvegarde sera conservee.'
        if ((Read-Host 'Tapez JE CONFIRME pour continuer') -cne 'JE CONFIRME') { throw [OperationCanceledException]::new('Operation annulee.') }
    }
}
try {
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw 'WDAC/AppLocker impose un mode PowerShell contraint. Le moteur natif ne peut pas etre charge.' }
    if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Utilisez Windows PowerShell 5.1 (powershell.exe), fourni avec Windows. Ce moteur cible .NET Framework.' }
    if (-not ('Tomax.Engine' -as [type])) {
        $assembly = Join-Path $PSScriptRoot 'Tomax.Native.dll'
        if (Test-Path -LiteralPath $assembly) { Add-Type -LiteralPath $assembly }
        else {
            $sources = @('TomaxNative.cs', 'TomaxEngine.cs', 'TomaxLocks.cs') | ForEach-Object { Join-Path (Join-Path $PSScriptRoot 'Native') $_ }
            Add-Type -Path $sources -ReferencedAssemblies @('System.dll', 'System.Core.dll', 'System.Xml.dll', 'System.Runtime.Serialization.dll')
        }
    }
    if ($InternalRequest) {
        $payload = Expand-Request $InternalRequest | ConvertFrom-Json
        $TargetPath = [string]$payload.TargetPath; $OperationDirectory = [string]$payload.OperationDirectory
        $BackupDirectory = [string]$payload.BackupDirectory; $Action = [string]$payload.Action; $Mode = [string]$payload.Mode
        $Force = [bool]$payload.Force; $NoPause = [bool]$payload.NoPause; $FromShell = [bool]$payload.FromShell
        $IncludeHardLinks = [bool]$payload.IncludeHardLinks; $OverwriteChanged = [bool]$payload.OverwriteChanged
        $CloseApplications = [bool]$payload.CloseApplications
        $requester = [Tomax.Requester]::FromJson([string]$payload.Requester)
        if ($Action -notin @('TakeOwnership', 'Resume', 'Restore', 'Diagnose') -or $Mode -notin @('Repair', 'Ultimate')) { throw 'Parametres internes invalides.' }
    }
    elseif ($ShellTarget) {
        if (-not $ShellTarget.EndsWith('|')) { throw 'Argument Explorer invalide.' }
        $TargetPath = $ShellTarget.Substring(0, $ShellTarget.Length - 1)
    }
    if ($null -eq $requester) { $requester = [Tomax.Requester]::Capture() }
    if ($Action -in @('Resume', 'Restore')) {
        if (-not $OperationDirectory -or $TargetPath) { throw 'Resume/Restore exigent -OperationDirectory et aucune autre cible.' }
        $OperationDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OperationDirectory)
    }
    else {
        if (-not $TargetPath -or $OperationDirectory) { throw 'Indiquez -TargetPath pour TakeOwnership/Diagnose.' }
        $TargetPath = [Tomax.Native]::Normalize($TargetPath)
    }
    if ($CloseApplications -and $Action -notin @('TakeOwnership', 'Diagnose')) { throw '-CloseApplications exige un fichier cible : utilisez Diagnose, puis Resume.' }
    if ($Action -ne 'Diagnose' -or $CloseApplications) {
        $description = if ($Action -in @('Resume', 'Restore')) { $OperationDirectory } else { [Tomax.Native]::Display($TargetPath) }
        if (-not $PSCmdlet.ShouldProcess($description, $Action)) { $exitCode = 0; return }
    }
    $admin = Test-Administrator
    if (($Action -ne 'Diagnose' -and -not $admin) -or ($FromShell -and -not $Elevated)) {
        $transport = @{
            TargetPath = $TargetPath; OperationDirectory = $OperationDirectory; BackupDirectory = $BackupDirectory
            Action = $Action; Mode = $Mode; Force = [bool]$Force; NoPause = [bool]$NoPause; FromShell = [bool]$FromShell
            IncludeHardLinks = [bool]$IncludeHardLinks; OverwriteChanged = [bool]$OverwriteChanged
            CloseApplications = [bool]$CloseApplications; Requester = $requester.ToJson()
        } | ConvertTo-Json -Compress -Depth 8
        $encodedRequest = Compress-Request $transport
        $escapedScript = $PSCommandPath.Replace("'", "''")
        $command = "& '$escapedScript' -InternalRequest '$encodedRequest' -Elevated"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        if ($encodedCommand.Length -gt 30000) { throw 'Arguments trop volumineux pour UAC. Lancez directement depuis Windows PowerShell administrateur.' }
        $start = @{
            FilePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
            ArgumentList = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"
            Wait = $true; PassThru = $true; WindowStyle = 'Normal'
        }
        if (-not $admin) { $start.Verb = 'RunAs' }
        try { $child = Start-Process @start; $exitCode = $child.ExitCode }
        catch { throw [OperationCanceledException]::new('Elevation refusee ou impossible. Aucune operation lancee.', $_.Exception) }
        $FromShell = $false
        return
    }
    Write-Host "`n=== TAKE OWNERSHIP MAX ULTIMATE v3 ===" -ForegroundColor Cyan
    if ($admin) {
        $privileges = [Tomax.PrivilegeScope]::new()
        foreach ($entry in $privileges.Results.GetEnumerator()) {
            $status = if ($entry.Value -eq 0) { 'actif' } else { "indisponible (Windows $($entry.Value))" }
            Write-Host "  $($entry.Key) : $status" -ForegroundColor DarkGray
        }
    }
    if ($CloseApplications -or $Action -eq 'Diagnose') {
        $item = [Tomax.Native]::Open($TargetPath, $false, $false)
        try { if ($item.IsDirectory -or $item.IsReparsePoint) { throw 'Le diagnostic des verrous exige un fichier ordinaire.' } } finally { $item.Dispose() }
        $lockers = [Tomax.LockManager]::List($TargetPath)
        if ($lockers.Count -eq 0) { Write-Host 'Aucune application signalee par Restart Manager.' }
        else {
            $lockers | Format-Table ProcessId, Name, Service, Restartable -AutoSize | Out-Host
            if ($CloseApplications) {
                if ((Read-Host 'Enregistrez votre travail. Tapez FERMER pour demander la fermeture propre de ces applications') -cne 'FERMER') { throw [OperationCanceledException]::new('Fermeture annulee.') }
                [Tomax.LockManager]::CloseApproved($TargetPath, $lockers)
                Write-Host 'Demande de fermeture envoyee. Nouvelle verification :'
                [Tomax.LockManager]::List($TargetPath) | Format-Table ProcessId, Name -AutoSize | Out-Host
            }
        }
        if ($Action -eq 'Diagnose') { $exitCode = 0; return }
    }
    if ($Action -eq 'TakeOwnership') {
        Confirm-Target $TargetPath
        $BackupDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupDirectory)
        $OperationDirectory = [Tomax.Engine]::CreateOperation($BackupDirectory, $TargetPath, $Mode, $requester, $IncludeHardLinks)
    }
    else { $saved = [Tomax.Engine]::ReadState($OperationDirectory); Confirm-Target $saved.Root }
    Write-Host "Operation et sauvegarde : $OperationDirectory" -ForegroundColor Cyan
    Write-Host 'Ctrl+C interrompt le traitement ; Resume reprend avec la sauvegarde existante.'
    $engine = [Tomax.Engine]::new()
    $script:progressWatch = [Diagnostics.Stopwatch]::StartNew()
    $engine.Progress = [Action[Tomax.ProgressInfo]] {
        param($info)
        if ($script:progressWatch.ElapsedMilliseconds -lt 200) { return }
        $script:progressWatch.Restart()
        $percent = if ($info.Phase -eq 'Scanning' -or $info.Total -eq 0) { -1 } else { [int][Math]::Min(100, 100.0 * $info.Processed / $info.Total) }
        Write-Progress -Activity "Take Ownership MAX : $($info.Phase)" -Status "$($info.Processed) objets ; $($info.Failed) echecs | $($info.Path)" -PercentComplete $percent
    }
    $report = $engine.Run($OperationDirectory, ($Action -eq 'Restore'), $OverwriteChanged)
    Write-Progress -Activity 'Take Ownership MAX' -Completed
    Write-Host "`nEtat : $($report.Phase)" -ForegroundColor Cyan
    Write-Host "Verifies/restaures : $($report.Succeeded) ; echecs : $($report.Failed) ; erreurs d'inventaire : $($report.ScanFailed)"
    Write-Host "Exclusions (liens) : $($report.Skipped) ; en attente : $($report.Pending)"
    Write-Host "Rapport : $(Join-Path $OperationDirectory 'rapport.txt')"
    $quotedOperation = $OperationDirectory.Replace("'", "''")
    Write-Host "Reprendre : .\TakeOwnershipMAX.ps1 -Action Resume -OperationDirectory '$quotedOperation'" -ForegroundColor DarkGray
    Write-Host "Restaurer : .\TakeOwnershipMAX.ps1 -Action Restore -OperationDirectory '$quotedOperation'" -ForegroundColor DarkGray
    Write-Host 'La verification confirme les ACL ; chiffrement, verrous et strategies Windows restent distincts.' -ForegroundColor DarkGray
    $exitCode = if ($report.Complete -and $report.Skipped -eq 0 -and $report.ScanFailed -eq 0) { 0 } else { 2 }
}
catch [OperationCanceledException] { Write-Host $_.Exception.Message -ForegroundColor Yellow; $exitCode = 3 }
catch { Write-Host "ERREUR : $($_.Exception.Message)" -ForegroundColor Red; $exitCode = 1 }
finally {
    if ($null -ne $privileges) { $privileges.Dispose() }
    if ($FromShell -and -not $NoPause) { try { [void](Read-Host 'Entree pour fermer') } catch { } }
    exit $exitCode
}

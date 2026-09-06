# Reads only the most recent test run; exports bounded diagnostics for review.
$ErrorActionPreference = 'Stop'
$testOutput = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) '.test-output'))
trap { ($_ | Out-String) + $_.ScriptStackTrace | Set-Content -LiteralPath (Join-Path $testOutput 'diagnostics-error.txt'); exit 1 }
$run = [IO.Path]::GetFullPath((Get-Content -LiteralPath (Join-Path $testOutput 'latest-admin.txt') -TotalCount 1))
if (-not $run.StartsWith($testOutput + '\run-', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected fixture directory.' }
$lines = [Collections.Generic.List[string]]::new()
[void][Reflection.Assembly]::LoadFrom((Join-Path $testOutput 'bin\TomaxTests.exe'))
$privileges = [Tomax.PrivilegeScope]::new()
foreach ($operation in Get-ChildItem -LiteralPath (Join-Path $run 'journals') -Directory) {
    $state = Get-Content -LiteralPath (Join-Path $operation.FullName 'state.json') -Raw | ConvertFrom-Json
    $lines.Add("$($state.Root) | $($state.Phase) | succeeded=$($state.Succeeded) failed=$($state.Failed)")
    $events = Get-Content -LiteralPath (Join-Path $operation.FullName 'events.jsonl') | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object { $_.Status -in @('Failure', 'Conflict', 'ScanFailure') } | Select-Object -First 3
    foreach ($event in $events) { $lines.Add(($event | ConvertTo-Json -Compress -Depth 5)) }
    if ($state.Root -match '\\(denied|resume)$') {
        $stream = [IO.File]::OpenRead((Join-Path $operation.FullName 'backup.tomax'))
        $reader = [IO.BinaryReader]::new($stream)
        try {
            $number = 0
            while ($stream.Position -lt $stream.Length -and $number -lt 3) {
                $size = $reader.ReadInt32(); $entry = [Text.Encoding]::UTF8.GetString($reader.ReadBytes($size)) | ConvertFrom-Json
                if ($state.BackupFormat -eq 1) { [void]$reader.ReadInt32() }
                $who = [Tomax.Requester]::FromJson(($state.Requester | ConvertTo-Json -Compress -Depth 8))
                $lines.Add('PATH ' + $entry.Path)
                $lines.Add('OLD ' + $entry.Original)
                $lines.Add('EXPECTED ' + [Tomax.Native]::RepairDescriptor($entry.Original, $entry.Directory, $who, ($state.Mode -eq 'Ultimate')))
                $item = [Tomax.Native]::Open($entry.Path, $false, $false)
                try { $lines.Add('ACTUAL ' + [Tomax.Native]::ReadSecurity($item)) } finally { $item.Dispose() }
                $number++
            }
        } finally { $reader.Dispose(); $stream.Dispose() }
    }
}
$privileges.Dispose()
Set-Content -LiteralPath (Join-Path $testOutput 'diagnostics-admin.txt') -Value $lines -Encoding UTF8

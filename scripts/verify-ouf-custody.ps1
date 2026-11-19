# Windows PowerShell 5.1. Verify the historical archive without extracting files.
param(
    [Parameter(Mandatory=$true)][string]$IdentityFile,
    [Parameter(Mandatory=$true)][string]$DestinationDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-Exact($stream, [byte[]]$buffer, [int]$count) {
    $offset = 0
    while ($offset -lt $count) {
        $n = $stream.Read($buffer, $offset, $count - $offset)
        if ($n -eq 0) { throw 'Flusso tar interrotto' }
        $offset += $n
    }
}

function Get-Hex([byte[]]$bytes) {
    [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
}

$identity = Get-Item -LiteralPath $IdentityFile
$archive = Get-Item -LiteralPath (Join-Path $DestinationDirectory 'retained-historical.tar.age')
$age = Get-Item -LiteralPath (Join-Path $DestinationDirectory 'age.exe')
if ($identity.PSIsContainer -or $archive.PSIsContainer -or $archive.Length -ne 6544578724) {
    throw 'Chiave o archivio Windows diverso dalla ricevuta'
}
$agePin = '2821a4ed191da07372acd302e5f6feae7a7985e285e1417765ebe74025af45f0'
if ((Get-FileHash -LiteralPath $age.FullName -Algorithm SHA256).Hash -ne $agePin) {
    throw 'SHA-256 di age.exe diverso dalla prova di custodia'
}
$manifestPin = '58484aea53aefeb1fff390578ba6562efabffd914caf64944eee7c9d9a2e0d79'
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $age.FullName
$start.Arguments = '-d -i "' + $identity.FullName + '" "' + $archive.FullName + '"'
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$process = [Diagnostics.Process]::Start($start)
try {
    $stream = $process.StandardOutput.BaseStream
    $header = [byte[]]::new(512)
    $buffer = [byte[]]::new(1048576)
    $members = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $manifest = $null
    $entries = 0
    while ($true) {
        Read-Exact $stream $header 512
        if ($header[0] -eq 0) { break }
        $entries += 1
        $name = [Text.Encoding]::ASCII.GetString($header, 0, 100).TrimEnd([char]0)
        if ($entries -gt 57 -or $header[156] -ne 48 -or $header[345] -ne 0 -or
            $name -cnotmatch '^(payload|evidence)/[a-z0-9][a-z0-9.-]{0,79}$' -or
            $members.ContainsKey($name)) {
            throw 'Voce tar inattesa o duplicata'
        }
        $octal = [Text.Encoding]::ASCII.GetString($header, 124, 12).Trim([char[]]@(0, 32))
        $length = [Convert]::ToInt64($octal, 8)
        if ($length -lt 1 -or $length -gt $archive.Length) { throw 'Dimensione membro tar inattesa' }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            if ($name -ceq 'evidence/custody-manifest.private.json') {
                if ($null -ne $manifest -or $length -gt 65536) { throw 'Manifest tar inatteso' }
                $raw = [byte[]]::new([int]$length)
                Read-Exact $stream $raw $raw.Length
                if ((Get-Hex ($sha.ComputeHash($raw))) -cne $manifestPin) { throw 'SHA-256 del manifest diverso' }
                $manifest = [Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
            } else {
                $remaining = $length
                while ($remaining -gt 0) {
                    $count = [int][Math]::Min([long]$buffer.Length, $remaining)
                    Read-Exact $stream $buffer $count
                    [void]$sha.TransformBlock($buffer, 0, $count, $buffer, 0)
                    $remaining -= $count
                }
                [void]$sha.TransformFinalBlock($buffer, 0, 0)
                $members.Add($name, @{bytes=$length; sha256=(Get-Hex $sha.Hash)})
            }
        } finally { $sha.Dispose() }
        $pad = [int]((512 - ($length % 512)) % 512)
        if ($pad -gt 0) { Read-Exact $stream $buffer $pad }
    }
    foreach ($byte in $header) { if ($byte -ne 0) { throw 'Chiusura tar non valida' } }
    Read-Exact $stream $header 512
    foreach ($byte in $header) { if ($byte -ne 0) { throw 'Chiusura tar non valida' } }
    $tail = 0
    while (($count = $stream.Read($buffer, 0, 10240)) -gt 0) {
        $tail += $count
        if ($tail -gt 10240) { throw 'Coda tar inattesa' }
        for ($i = 0; $i -lt $count; $i++) {
            if ($buffer[$i] -ne 0) { throw 'Coda tar non nulla' }
        }
    }
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw 'Decifratura age fallita' }
    if ($entries -ne 57 -or $null -eq $manifest -or $members.Count -ne 56 -or
        $manifest.schema -cne 'ouf.storage-retained-capture-custody.v1') {
        throw 'Manifest o numero di membri inatteso'
    }
    $payload = @($manifest.members.PSObject.Properties)
    $evidence = @($manifest.evidenceSha256.PSObject.Properties)
    if ($payload.Count -ne 53 -or $evidence.Count -ne 3) { throw 'Cardinalita del manifest inattesa' }
    foreach ($entry in $payload) {
        $key = 'payload/' + $entry.Name
        if (-not $members.ContainsKey($key) -or $members[$key].bytes -ne $entry.Value.bytes -or
            $members[$key].sha256 -cne $entry.Value.sha256) { throw 'Membro del payload diverso dal manifest' }
    }
    foreach ($entry in $evidence) {
        $key = 'evidence/' + $entry.Name
        if (-not $members.ContainsKey($key) -or $members[$key].sha256 -cne $entry.Value) {
            throw 'Ricevuta interna diversa dal manifest'
        }
    }
    [ordered]@{
        schema = 'ouf.storage-retained-custody-windows-verified.v1'
        status = 'HISTORICAL_CUSTODY_DECRYPTED_AND_MANIFEST_VERIFIED'
        archiveBytes = $archive.Length
        privateManifestSha256 = $manifestPin
        payloadMembersVerified = $payload.Count
        evidenceMembersVerified = $evidence.Count
        plaintextFilesWritten = 0
        restorePerformed = $false
        acceptanceCreditAdded = 0
    } | ConvertTo-Json
} finally {
    if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    $process.Dispose()
}

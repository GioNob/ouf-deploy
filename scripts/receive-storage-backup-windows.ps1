# Requires Windows PowerShell 5.1 and the already configured OpenSSH client.
# Transfer only: this does not produce, decrypt, restore or qualify a backup.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SshTarget,
    [Parameter(Mandatory=$true)][string]$IdentityFile,
    [Parameter(Mandatory=$true)][string]$RemoteArchive,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][long]$ExpectedBytes,
    [string]$DestinationDirectory = (Join-Path $env:USERPROFILE 'OUF-backup')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ExpectedBytes -le 0) { throw 'ExpectedBytes must come from the final archive receipt.' }
# Keep remote-shell metacharacters out, including with older SCP implementations.
if ($SshTarget -notmatch '^[a-zA-Z0-9_][a-zA-Z0-9_.-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*$') {
    throw 'Use user@hostname or user@IPv4.'
}
if ($RemoteArchive -notmatch '^/[a-zA-Z0-9_./-]+$' -or
    $RemoteArchive -match '(^|/)\.\.(/|$)' -or $RemoteArchive.EndsWith('/')) {
    throw 'Use an absolute remote archive path without shell metacharacters or parent traversal.'
}
$identity = Get-Item -LiteralPath $IdentityFile
if ($identity.PSIsContainer -or $identity.PSProvider.Name -ne 'FileSystem') {
    throw 'IdentityFile must be an existing local file.'
}
$scp = (Get-Command scp.exe -CommandType Application -ErrorAction Stop).Source
$destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationDirectory)
if ($destination -notmatch '^[a-zA-Z]:\\') { throw 'Use a local Windows drive for the independent copy.' }
$drive = New-Object System.IO.DriveInfo ([IO.Path]::GetPathRoot($destination))
if ($drive.AvailableFreeSpace -lt $ExpectedBytes) { throw 'Insufficient destination space.' }
[void][IO.Directory]::CreateDirectory($destination)
$basename = [IO.Path]::GetFileName($RemoteArchive)
$final = Join-Path $destination $basename
if (Test-Path -LiteralPath $final) { throw 'Final destination exists; no overwrite performed.' }
# A fresh subdirectory separates this single attempt from any earlier partial copy.
$attempt = Join-Path $destination ('transfer-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($attempt)
$partial = Join-Path $attempt ($basename + '.partial')
$remote = $SshTarget + ':' + $RemoteArchive
# Host-key verification stays enabled. No retry, resume, remote chmod or deletion.
& $scp -i $identity.FullName -o 'StrictHostKeyChecking=yes' -o 'ConnectionAttempts=1' $remote $partial
if ($LASTEXITCODE -ne 0) {
    throw ('SCP failed. Partial copy retained at: ' + $partial)
}
$received = Get-Item -LiteralPath $partial
if ($received.Length -ne $ExpectedBytes) { throw ('Size mismatch. Partial copy retained at: ' + $partial) }
$actual = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $ExpectedSha256.ToLowerInvariant()) { throw ('SHA256 mismatch. Partial copy retained at: ' + $partial) }
# File.Move refuses an existing destination, including one created during transfer.
[IO.File]::Move($partial, $final)
[pscustomobject]@{
    schema = 'ouf.storage-backup-windows-transfer.v1'
    status = 'TRANSFER_SIZE_AND_SHA256_VERIFIED'
    bytes = $received.Length
    sha256 = $actual
    localFile = $final
    attempts = 1
    remoteFilesModified = $false
    decryptionVerified = $false
    restoreVerified = $false
    g3Complete = $false
    acceptanceCreditAdded = 0
} | ConvertTo-Json

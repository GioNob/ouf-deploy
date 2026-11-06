# Windows PowerShell 5.1. Local custody check only; no VPS connection or private-key copy.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$IdentityFile,
    [string]$WorkspaceDirectory = (Join-Path $env:USERPROFILE 'OUF-backup-custody-20261106')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$architecture = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $architecture = $env:PROCESSOR_ARCHITEW6432 }
if ($architecture -ne 'AMD64') { throw 'This pinned package requires Windows AMD64.' }
$identity = Get-Item -LiteralPath $IdentityFile
if ($identity.PSIsContainer -or ($identity.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Use an existing regular SSH private-key file on this PC.'
}
$sshKeygen = (Get-Command ssh-keygen.exe -CommandType Application -ErrorAction Stop).Source
$keyLines = @(& $sshKeygen -y -f $identity.FullName)
if ($LASTEXITCODE -ne 0) { throw 'SSH public-key derivation failed; private key was not copied.' }
$public = ($keyLines -join "`n").Trim()
if ($public -notmatch '^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/=]+(?: [^\r\n]*)?$') {
    throw 'The current age producer needs an RSA or Ed25519 SSH key. No files created.'
}
$parts = $public.Split(' ')
$public = $parts[0] + ' ' + $parts[1]
$directory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkspaceDirectory)
if ($directory -notmatch '^[a-zA-Z]:\\') { throw 'Use a local Windows drive.' }
if (Test-Path -LiteralPath $directory) { throw 'Custody workspace exists; preserve it, do not replay.' }
$drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($directory))
if ($drive.AvailableFreeSpace -lt 134217728) { throw '128 MiB free is required for this tool/probe only.' }
$parent = Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($directory))
while ($null -ne $parent) {
    if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse ancestry requires review.' }
    $parent = $parent.Parent
}
[void](New-Item -ItemType Directory -Path $directory -ErrorAction Stop)
# Only the current Windows principal receives access to this new workspace.
# Existing SSH key ACLs and all previous folders remain unchanged.
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $directory -AclObject $acl

$zipPath = Join-Path $directory 'age-v1.3.2-windows-amd64.zip'
$agePath = Join-Path $directory 'age.exe'
$zipSha = 'f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -TimeoutSec 120 -Uri 'https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-windows-amd64.zip' -OutFile $zipPath
if ((Get-Item -LiteralPath $zipPath).Length -ne 20250704 -or
    (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $zipSha) {
    throw 'Pinned age ZIP size/SHA256 mismatch. Partial workspace preserved.'
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $entries = @($archive.Entries | Where-Object { $_.Name -eq 'age.exe' })
    if ($entries.Count -ne 1 -or $entries[0].Length -le 0 -or $entries[0].Length -gt 67108864) {
        throw 'Expected one bounded age.exe in the verified ZIP.'
    }
    $inputStream = $entries[0].Open()
    try {
        $outputStream = [IO.File]::Open($agePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $inputStream.CopyTo($outputStream); $outputStream.Flush($true) }
        finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
} finally { $archive.Dispose() }
$version = (& $agePath --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $version -ne 'v1.3.2') { throw 'Unexpected age executable version.' }
$recipientPath = Join-Path $directory 'recipient.pub'
[IO.File]::WriteAllText($recipientPath, $public + "`n", (New-Object Text.UTF8Encoding($false)))
$probe = Join-Path $directory 'probe.bin'
$cipher = Join-Path $directory 'probe.bin.age'
$decoded = Join-Path $directory 'probe.decoded.bin'
$bytes = New-Object byte[] 4096
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
[IO.File]::WriteAllBytes($probe, $bytes)
& $agePath -r $public -o $cipher $probe
if ($LASTEXITCODE -ne 0) { throw 'Local probe encryption failed.' }
& $agePath -d -i $identity.FullName -o $decoded $cipher
if ($LASTEXITCODE -ne 0) { throw 'Local probe decryption failed.' }
$before = (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash.ToLowerInvariant()
$after = (Get-FileHash -LiteralPath $decoded -Algorithm SHA256).Hash.ToLowerInvariant()
if ($before -ne $after -or (Get-Item -LiteralPath $decoded).Length -ne 4096) { throw 'Probe round-trip mismatch.' }
$result = [ordered]@{
    schema = 'ouf.storage-backup-windows-custody.v1'
    status = 'LOCAL_ENCRYPTION_AND_DECRYPTION_VERIFIED'
    recipient = $public
    recipientFileSha256 = (Get-FileHash -LiteralPath $recipientPath -Algorithm SHA256).Hash.ToLowerInvariant()
    ageVersion = $version
    ageArchiveSha256 = $zipSha
    ageExeSha256 = (Get-FileHash -LiteralPath $agePath -Algorithm SHA256).Hash.ToLowerInvariant()
    probeBytes = 4096
    probeSha256 = $before
    availableBytes = $drive.AvailableFreeSpace
    workspaceAclRestrictedToCurrentUser = $true
    privateKeyCopied = $false
    remoteConnections = 0
    externalDownloads = 1
    targetCapturePerformed = $false
    crossPlatformDecryptProven = $false
    targetBackupCapacityAccepted = $false
    targetRestoreVerified = $false
    automaticReplayAllowed = $false
    runtimeAuthorityIssued = $false
    acceptanceCreditAdded = 0
}
$json = $result | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText((Join-Path $directory 'result.json'), $json + "`n", (New-Object Text.UTF8Encoding($false)))
$json

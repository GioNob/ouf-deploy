Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Disposable GitHub Actions fixture only.' }
$root = Join-Path $env:RUNNER_TEMP ('ouf-custody-fixture-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $root)
$identity = Join-Path $root 'fixture-key'
$keygen = (Get-Command ssh-keygen.exe -CommandType Application).Source
$generation = Start-Process -FilePath $keygen -ArgumentList @('-q', '-t', 'ed25519', '-N', '""', '-f', ('"' + $identity + '"')) -Wait -PassThru -NoNewWindow
if ($generation.ExitCode -ne 0) { throw 'Synthetic SSH key generation failed.' }
$originalKeyHash = (Get-FileHash -LiteralPath $identity -Algorithm SHA256).Hash
$workspace = Join-Path $root 'custody'
$script = Join-Path $PSScriptRoot '../scripts/prepare-storage-backup-custody-windows.ps1'
$result = (& $script -IdentityFile $identity -WorkspaceDirectory $workspace | Out-String) | ConvertFrom-Json
if ($result.status -ne 'LOCAL_ENCRYPTION_AND_DECRYPTION_VERIFIED' -or $result.probeBytes -ne 4096 -or
    $result.ageVersion -ne 'v1.3.2' -or $result.privateKeyCopied -or $result.remoteConnections -ne 0) {
    throw 'Custody proof mismatch.'
}
if ((Get-FileHash -LiteralPath $identity -Algorithm SHA256).Hash -ne $originalKeyHash) { throw 'Original key changed.' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $workspace
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if (-not $acl.AreAccessRulesProtected -or $rules.Count -ne 1 -or $rules[0].IdentityReference -ne $sid) {
    throw 'Workspace ACL not exclusive to fixture principal.'
}
$replayDenied = $false
try { & $script -IdentityFile $identity -WorkspaceDirectory $workspace | Out-Null }
catch { if ($_.Exception.Message -like 'Custody workspace exists*') { $replayDenied = $true } else { throw } }
if (-not $replayDenied) { throw 'Existing workspace replay accepted.' }
$report = [ordered]@{
    schema = 'ouf.storage-backup-windows-native.v1'
    status = 'PASS'
    powershell = $PSVersionTable.PSVersion.ToString()
    ageVersion = $result.ageVersion
    ageArchiveSha256 = $result.ageArchiveSha256
    ageExeSha256 = $result.ageExeSha256
    probeBytes = 4096
    localRoundTripVerified = $true
    privateKeyUnchanged = $true
    workspaceAclVerified = $true
    existingWorkspaceReplayDenied = $true
    userPcQualified = $false
    crossPlatformDecryptProven = $false
    targetOperations = 0
    acceptanceCreditAdded = 0
}
$output = Join-Path $env:RUNNER_TEMP 'ouf-custody-public-result'
[void](New-Item -ItemType Directory -Path $output)
[IO.File]::WriteAllText((Join-Path $output 'native-result.json'), (($report | ConvertTo-Json) + "`n"), (New-Object Text.UTF8Encoding($false)))
$report | ConvertTo-Json

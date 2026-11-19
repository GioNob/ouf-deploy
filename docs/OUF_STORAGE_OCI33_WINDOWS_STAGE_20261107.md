## Esito dello staging VPS

Il download diretto ha restituito HTTP 200 e SHA-256 conforme. [Ricevuta](../evidence/storage-oci33-zip-staged-operator-20261107.json). [Proposta per caricamento e rehearsal in una singola esecuzione](OUF_STORAGE_RETAINED_OCI33_REHEARSAL_20261107.md).

# Trasferire l’artefatto SeaweedFS OCI33 sul VPS

L'[immagine esatta manca sul VPS](../evidence/storage-oci33-image-absent-operator-20261107.json). Scaricare lo [ZIP OCI33 da GitHub Actions](https://github.com/GioNob/ouf-deploy/actions/runs/41782068047/artifacts/13299559178) con la sessione GitHub già in uso. Il file è `seaweedfs-452-generation33-candidate-image-41782068047.zip`. Il comando verifica dimensione e SHA-256 sul PC, crea una directory privata nuova nella home di `oufadmin` e copia lo ZIP con SCP e host key obbligatoria. Nessun container viene avviato.

## Comando PowerShell

Incollare tutto il blocco in una volta sola. Indicare soltanto host o IP quando richiesto. I percorsi locali restano sul PC.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    if ([string]::IsNullOrWhiteSpace($identity)) { $identity = (Read-Host 'Percorso della chiave SSH gia usata').Trim().Trim('"') }
    if (-not (Test-Path -LiteralPath $identity -PathType Leaf)) { throw 'File chiave SSH assente' }
    $zip = Join-Path $env:USERPROFILE 'Downloads\seaweedfs-452-generation33-candidate-image-41782068047.zip'
    if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) { $zip = (Read-Host 'Percorso dello ZIP OCI33 scaricato').Trim().Trim('"') }
    $pin = '4175ae9f0f5e4f6e71729084e0bfc2d9e8a2d39d3c5908dc51e5c4c695bd6121'
    if ((Get-Item -LiteralPath $zip).Length -ne 174223468) { throw 'Dimensione ZIP diversa' }
    if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $pin) { throw 'SHA-256 ZIP diverso' }
    $server = (Read-Host 'Solo host o IP del VPS').Trim()
    if ($server -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]*$') { throw 'Indicare solo host o IPv4' }
    $target = "oufadmin@$server"
    $folder = 'ouf-oci33-' + [guid]::NewGuid().ToString('N')
    $opts = @('-i',$identity,'-o','StrictHostKeyChecking=yes','-o','ConnectionAttempts=1')
    & ssh.exe @opts $target "umask 077 && mkdir -- $folder"
    if ($LASTEXITCODE -ne 0) { throw 'Creazione directory privata fallita' }
    & scp.exe @opts $zip "${target}:$folder/candidate.zip"
    if ($LASTEXITCODE -ne 0) { throw "SCP fallito, conservare $folder" }
    [ordered]@{status='OCI33_ZIP_STAGED'; remoteRelativePath="$folder/candidate.zip"; bytes=174223468; sha256=$pin} | ConvertTo-Json
}
```

La ricevuta Windows attesta lo ZIP locale verificato e la riuscita del trasporto. Il prossimo comando confronterà gli hash sul VPS e userà l'immagine esatta per l'ambiente di rehearsal. Nessun credito MiniPET, nessun dato applicativo copiato.

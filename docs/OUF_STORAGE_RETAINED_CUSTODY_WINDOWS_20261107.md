# Trasferimento della copia storica OUF su Windows

**Staging VPS concluso.** La [ricevuta `SCP_SOURCE_STAGED`](../evidence/storage-retained-custody-scp-staged-operator-20261107.json) coincide con dimensione e SHA-256 dell'archivio sigillato. Eseguire [solo il passaggio Windows](#2-windows--copiare-e-confrontare-il-digest).

La [ricevuta VPS](../evidence/storage-retained-custody-sealed-operator-20261107.json) fissa **6.544.578.724 byte** e SHA-256 `c3b0de7ab9fceb9c566431a4ed5ebf8f7720dae5eee52c1a0a5c76a5eb99a886`. La copia resta cifrata. Lo staging locale del VPS è stato qualificato su fixture Linux con cambio di proprietà reale, diniego del replay, mismatch di digest, rifiuto di symlink e conservazione dell'originale. Il trasferimento effettivo su Windows è ancora da eseguire. [Qualifica](https://github.com/GioNob/ouf-deploy/actions/runs/42352859496)

## 1. VPS — preparare il sorgente SCP privato

Eseguire dalla sessione esistente `oufadmin`. Lo script apre l'archivio e la ricevuta come root, verifica i byte durante la copia e rende leggibile la copia separata al solo account `oufadmin`. I permessi dell'archivio sigillato restano intatti. Su `SCP_SOURCE_STAGED` passare a Windows. In caso di `HELD` conservare il risultato e fermarsi.

```bash
sudo /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import urllib.request

url = (
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/"
    "1f501c46a93e9ee9b112795ac8b51c4eea052507/"
    "scripts/stage-retained-custody-windows-20261107.py"
)
with urllib.request.urlopen(url, timeout=30) as response:
    raw = response.read(5672)
if len(raw) != 5671 or hashlib.sha256(raw).hexdigest() != "3283f2846d9fc3831955f25884c9ef37785bb511a6dbc86d858c13b8c20ed37f":
    raise SystemExit("HELD: download o SHA256 non corrispondente")
exec(compile(raw, "verified-custody-scp-stage", "exec"), {"__name__": "__main__"})
PY
```

## 2. Windows — copiare e confrontare il digest

In PowerShell usare lo stesso target SSH e il percorso locale della chiave già usati per il VPS. I valori digitati restano sul PC. Se la directory privata di custodia è stata personalizzata, indicarla al prompt. Il ricevitore usa SCP con controllo della chiave host attivo, conserva un parziale in caso di errore e promuove il file soltanto dopo il confronto di dimensione e SHA-256.

### 2A. Inserire i parametri SSH

Eseguire ciascuna riga da sola e rispondere al relativo prompt prima di incollare la riga successiva. Nel secondo prompt indicare il percorso del file della chiave privata già in uso, senza incollare il contenuto della chiave.

```powershell
$sshTarget = (Read-Host 'Target SSH gia usato (utente@host)').Trim()
```

```powershell
$identity = [Environment]::ExpandEnvironmentVariables((Read-Host 'Percorso locale della chiave SSH gia usata').Trim().Trim('"').Trim("'"))
```

### 2B. Eseguire la copia

Se PowerShell mostra `>>`, premere Ctrl+C per tornare a `PS>`. Eseguire le righe qui sotto una alla volta. Ogni riga è un comando completo.

```powershell
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($sshTarget)) { throw 'Impostare il target SSH nel passaggio 2A' }
if ([string]::IsNullOrWhiteSpace($identity)) { throw 'Impostare il percorso della chiave nel passaggio 2A' }
if (-not (Test-Path -LiteralPath $identity -PathType Leaf)) { throw 'File della chiave assente' }
if ($identity.EndsWith('.pub', [StringComparison]::OrdinalIgnoreCase)) { throw 'Indicare il file della chiave privata' }
$dest = Join-Path $env:USERPROFILE 'OUF-backup-custody-20261106'
if (-not (Test-Path -LiteralPath $dest -PathType Container)) { $dest = Read-Host 'Directory privata di custodia gia preparata' }
if (-not (Test-Path -LiteralPath $dest -PathType Container)) { throw 'Directory privata di custodia assente' }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$uri = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/b866758dfaea4df22e057ed926aa5b01b762fd5b/scripts/receive-storage-backup-windows.ps1'
$client = [Net.WebClient]::new()
try { $bytes = $client.DownloadData($uri) } finally { $client.Dispose() }
$stream = [IO.MemoryStream]::new([byte[]]$bytes)
try { $pin = (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash } finally { $stream.Dispose() }
if ($bytes.Length -ne 3523 -or $pin -ne '48d1aae4854257c414d14a7fb62b660613ba52e2d5a619776babc598016cfce6') { throw 'Ricevitore con dimensione o SHA-256 diverso' }
$receive = [ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($bytes))
$transfer = @{}
$transfer.SshTarget = $sshTarget
$transfer.IdentityFile = $identity
$transfer.DestinationDirectory = $dest
$transfer.RemoteArchive = '/var/tmp/ouf-historical-transfer-20261107-v1/retained-historical.tar.age'
$transfer.ExpectedBytes = 6544578724
$transfer.ExpectedSha256 = 'c3b0de7ab9fceb9c566431a4ed5ebf8f7720dae5eee52c1a0a5c76a5eb99a886'
$json = & $receive @transfer
$json | ConvertFrom-Json | Select-Object * -ExcludeProperty localFile | ConvertTo-Json
```

La ricevuta redatta attesa è `TRANSFER_SIZE_AND_SHA256_VERIFIED`. Conservare la copia cifrata. Decifratura e prova di restore isolato sono passi distinti. MiniPET **39,78%**, nessun nuovo credito.

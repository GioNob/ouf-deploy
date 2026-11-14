# P: lettura del runtime v4 e v5 — 13 novembre 2026

Task sprint-01/task-17, decisioni D-008, D-011, D-014 punto 3 e D-019.

## Contratto di lettura

`runtime(reader, info, docs)` del controller P
`scripts/prepare-semantic-provider-installation.py` verifica che adapter e
southbound dichiarino lo stesso runtime in `HostConfig.Runtime`. Legge il wrapper
indicato da `info["Runtimes"][name]["path"]`, root:root 0755, e richiede la forma
esatta `#!/bin/sh\nexec <python> -I -B <source> --configuration <config> "$@"\n`.
La configurazione passa da `Reader.document`, con custodia predefinita root:root
0600. Schemi diversi da v4 e v5 producono `RUNTIME_CONFIGURATION_UNPROVEN`.

Per `ouf.semantic-docker-runtime-adapter.v4` restano gli stessi controlli:
Python uguale a quello del wrapper, sorgente con modo 0600, 0644 oppure 0755 e
hash `sourceHash`, Python e runtime verificati con `Reader.binary` e i rispettivi
hash. Restano invariati i codici di errore e il risultato del ramo v4.

Per `ouf.semantic-docker-runtime-adapter.v5`, P verifica localmente l'insieme
esatto di `CONFIG_FIELDS`, hash SHA256 minuscoli, path assoluti canonici senza
`..`, binding di file chiusi, versione OpenSSL e sintassi dell'issuer secondo
`load_configuration` della v5. Richiede inoltre che `pythonPath` coincida con
il Python del wrapper. Gli errori producono `RUNTIME_V5_CONFIGURATION_UNPROVEN`.
Il controller non importa il modulo runtime: un test lo importa per path,
senza chiamarne `main`, e confronta schema e insieme dei campi per impedire deriva.

I candidati devono essere esattamente i due `Id` di adapter e southbound,
CID SHA256 sintatticamente validi, ciascuno con le sole chiavi `phase` e
`bundleParents`, fase `INACTIVE` e da uno a quattro parent assoluti.
Gli errori producono `RUNTIME_V5_CANDIDATES_MISMATCH`.

Sorgente, driver, broker di ammissione, verificatore di armatura, manifest
`acceptance`, `b1b2TrustPolicy` e `b1b2AuthorityModule` sono letti da `Reader.read`
con hash atteso e custodia root:root 0600. Il limite di lettura è 131072 byte,
come nella v5. Python, runtime e `opensslBinding.path` passano da `Reader.binary`
con hash atteso e limite di 64000000 byte; i modi ammessi restano 0555 e 0755.
Gli errori di hash o custodia conservano i codici di `Reader`, fra cui
`BOUND_INPUT_HASH_CHANGED`, `FILE_CUSTODY_UNPROVEN` ed
`EXECUTABLE_CUSTODY_UNPROVEN`.

## Profilo e piano (D-008)

Entrambi i rami restituiscono soltanto `name`, `wrapper`, `runtimeStateRoot`,
`runtimeExecutable`, `pythonExecutable` e `dockerDataRoot`. A parità di questi
valori il risultato, e quindi il contributo runtime al profilo serializzato,
è identico. Non entrano nel profilo versione dello schema o hash.

Le letture di configurazione e file vincolati vengono registrate in
`reader.inputs`. `observe()` pubblica la mappa restituita da `reader.verify()`
negli `inputHashes` del piano. Dopo lo switch del contenuto del wrapper da parte
del futuro controller B1, mantenendo gli stessi valori del profilo e gli altri
input stabili, la revisione di P deve quindi produrre zero delta del profilo.
La differenza del piano è negli `inputHashes`, inclusi wrapper, configurazione,
sorgente e file vincolati della v5; il suo digest cambia di conseguenza.

## Confine dell'armatura

P valida solo la sintassi del path `armingRoot` presente nella configurazione:
non ne controlla esistenza, custodia o contenuto. Non apre payload, envelope
firmati né marker `.consumed`. Sono stato di B2; la loro comparsa o il consumo
non devono modificare profilo o piano di P. I file statici del verificatore,
della policy e del modulo di autorità restano invece input vincolati della v5.
Nessuna lettura esegue runtime, verificatore, driver o broker.

## Verifica

I test aggiunti in `tests/test_semantic_provider_installation.py` comprendono
confronto v4/v5, mappa completa degli hash, schema e candidati non validi,
hash alterati, custodia dei file e assenza di accessi all'armatura. Le fixture
native usano `/run` e `OUF_P_NATIVE=1`, con `Reader` reale e custodia root.
Il test anti-deriva usa il modulo v5 del checkout completo già disponibile
nel workflow `semantic-provider-installation-profile.yml`.

Comando di verifica previsto dal workflow:

```sh
sudo -n env OUF_P_NATIVE=1 /usr/bin/python3 -I -B -m unittest discover -s tests -p test_semantic_provider_installation.py -v
```

Nell'ambiente locale Windows di implementazione Python non è disponibile nel
PATH e WSL restituisce accesso negato. La suite nativa non è stata eseguita
localmente; l'esito CI resta da acquisire. Questo task non installa la v5,
non cambia il wrapper sul VPS e non attesta effetti runtime.

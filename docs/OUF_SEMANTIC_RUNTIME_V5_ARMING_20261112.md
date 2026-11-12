# Runtime v5 inattivo e armatura B1/B2 — 12 novembre 2026

Task sprint-01/task-16, D-011 punto 1, D-014, D-015, D-016,
con separazione dei sorgenti imposta da D-019 e chiarimento r3.

## Sorgenti e confini

`tools/semantic_runtime_v5/semantic_provider_docker_runtime_v5.py` è un runtime
autonomo, di sola libreria standard, derivato dal runtime storico. Accetta solo
`ouf.semantic-docker-runtime-adapter.v5`; v1–v4 continuano a usare il sorgente
storico. Runtime, broker, hash fissati dalle fixture e installer di
`cohort-draft` restano intatti. Questo task non installa sorgenti, wrapper o
configurazioni e non crea container o journal `STAGED`.

Il runtime controlla custodia, sintassi e legami. La crittografia appartiene a
`tools/semantic_runtime_v5/arming_verifier.py`, processo separato eseguito
prima del broker. Il broker storico riceve soltanto i suoi argomenti originali
e conserva tutte le verifiche di intent, creazione, approvazione, driver e
consumo dell'ammissione. Non riceve nuovi argomenti di armatura.

## Configurazione v5

Oggetto JSON chiuso, senza chiavi aggiuntive:

| Campi | Contratto |
|---|---|
| `schema` | `ouf.semantic-docker-runtime-adapter.v5` |
| `sourceHash` | SHA256 dei byte del nuovo runtime v5 |
| `runtimePath`, `runtimeSha256` | Eseguibile runc e SHA256 |
| `pythonPath`, `pythonSha256` | Eseguibile Python e SHA256 |
| `driverPath`, `driverSha256` | Driver storico e SHA256 |
| `admissionPath`, `admissionSha256` | Broker storico e SHA256 |
| `registryRoot`, `runtimeStateRoot` | Root del registry e dei runtime state |
| `acceptance` | Esattamente `{path, sha256}` del manifest B1, hash dei byte |
| `b1b2TrustPolicy` | Esattamente `{path, sha256}` della policy separata del task-14 |
| `armingRoot` | Directory root:root, 0700 |
| `armingVerifierPath`, `armingVerifierSha256` | Verificatore separato e SHA256 |
| `b1b2AuthorityModule` | Esattamente `{path, sha256}` dell'originale `authority.py` del task-14 |
| `opensslBinding` | Esattamente `{path, sha256, version}` per OpenSSL |
| `armingIssuerRef` | Issuer atteso del mandato `RUNTIME_ARMING` |
| `candidates` | Esattamente due chiavi CID di 64 cifre hex minuscole |

Ogni candidato contiene esattamente `phase: "INACTIVE"` e `bundleParents`:
lista da uno a quattro parent assoluti dei bundle Docker. Il controllo del
bundle resta quello storico: parent dichiarato e nome uguale al CID.
I path devono essere assoluti, senza `..`. Hash in SHA256 hex minuscolo.
La configurazione è root:root, 0600, file regolare con nlink 1, senza symlink.
Gli antenati devono essere directory root senza scrittura di gruppo/altri.

Ogni operazione rilegge configurazione e custodia di `armingRoot` e controlla
gli hash del sorgente, runc, Python, driver, broker, verificatore, modulo di
autorità, manifest B1, policy B1/B2 e OpenSSL. Non legge chiavi private.
Le operazioni senza CID (`version`, `--version`, `features`) vengono delegate
a runc con il protocollo storico, senza selezione o consumo di armature.

## Armatura e firma

In `armingRoot` B2 pubblica due file root:root, 0600, regolari, nlink 1:

- `<generation>.json`: byte esatti del payload firmato;
- `<generation>.RUNTIME_ARMING.json`: envelope del task-14.

Il payload è un oggetto JSON chiuso con esattamente:

```text
schema: "ouf.semantic-docker-runtime-arming.v1"
installationRef, entityRef: identità B1/B2
generation: intero >= 1, uguale al nome del file (senza zeri iniziali)
runtimeConfigurationSha256: SHA256 dei byte della configurazione v5
acceptanceSha256: uguale a v5.acceptance.sha256
candidates: esattamente i due CID della v5
issuedAt: intero epoch >= 0
```

Ogni entry di `candidates` ha esattamente `intentRef` (SHA256),
`admissionConfiguration` (path assoluto della configurazione del broker) e
`admissionConfigurationHash` (SHA256 dei suoi byte). Nessuna chiave di firma
o facoltà di generare firme è contenuta nel runtime o nel verificatore.

## Selezione, verifica e consumo

Non esiste selezione «latest». Per un CID una generazione è disponibile se
manca `<generation>.<cid>.consumed`. Su `create`:

1. Zero generazioni disponibili: `RUNTIME_PHASE_INACTIVE`.
   Più di una: `ARMING_GENERATION_AMBIGUOUS`.
2. Verifica schema, custodia, insieme CID, hash della v5 e del manifest,
   journal `STAGED` di B2, binding e bundle Docker.
3. Invoca `[pythonPath, -I, -B, armingVerifierPath, --configuration, v5,
   --container-id, cid, --generation, n]`: ambiente minimo, stderr soppresso,
   timeout di 20 secondi. Serve exit 0 e stdout esatto
   `RUNTIME_ARMING_VERIFIED\n`. Un fallimento non crea marker.
4. Rilegge configurazione e payload; crea il marker con `O_EXCL`, 0600,
   root:root, nlink 1, contenuto `{generation, armingPayloadSha256}`;
   esegue fsync del marker e della directory.
5. Chiama `authorize-create` e il percorso v4: journal, shadow bundle,
   runc create e `record-created`.

Qualunque errore dopo il marker lascia la generazione consumata. Nessun
rollback del marker, nuovo tentativo implicito o cancellazione di parziali.
La disponibilità è per CID: consumare un candidato non consuma l'altro.
Firme orfane rendono visibile una generazione e fanno fallire la selezione
se manca il payload; file estranei o custodia errata provocano diniego.

Il verificatore carica il modulo B1/B2 dal path esplicito della v5 soltanto
dopo aver verificato SHA256 e custodia. Compila esattamente i byte verificati,
senza import da `sys.path` e senza riaprire il modulo per eseguirlo.
`B1B2Authenticator` verifica ruolo `RUNTIME_ARMING`, dominio separato,
`issuerRef = armingIssuerRef`, scope installation/entity uguale a payload e
policy, hash e versione di OpenSSL e mandato attivo durante l'intera verifica.
Il verificatore controlla inoltre l'hash della configurazione del broker e
`intentRef == admissionConfiguration.intentBinding.sha256`, leggendo lo
schema `ouf.semantic-deployment-broker.v1` senza importare il broker.
Rilegge gli input al termine per intercettare modifiche concorrenti.

Il verificatore imposta umask 077. Non scrive file persistenti. I temporanei
privati di `B1B2Authenticator.verify()` sono ammessi da r3 e vengono rimossi
automaticamente anche in caso di errore. Non crea marker o journal.

## Fase inattiva e operazioni successive

Senza journal, o con journal ancora `STAGED`, `start` e `kill` sono negati con
`RUNTIME_PHASE_INACTIVE`. `create` richiede l'armatura unica e il journal
`STAGED` già preparato da B2: il runtime non lo alloca.

Per `state`/`delete` inattivi il runtime interroga runc `state` prima di
delegare. Un esito positivo indica un container inatteso:
`RUNTIME_PHASE_INACTIVE_UNEXPECTED_CONTAINER`. L'assenza deve essere esplicita:
exit 1 e messaggio runc `container does not exist` (testo semplice o riga
logrus `time="..." level=error|fatal msg="container does not exist"`).
Quindi delega l'operazione richiesta e restituisce il codice runc.
Un errore diverso, timeout o output eccessivo non prova assenza e viene negato.

Dopo il consumo, `start`, `state`, `kill` e `delete` caricano esclusivamente
`armingGeneration` del journal e verificano il marker con lo stesso hash del
payload. Nessuna nuova selezione e nessun passaggio a generazioni successive.
Per `start` restano `cohort-ready`, scheduling comune, preparazione, driver,
controlli dell'intent firmato e del journal durevole v4. Il verificatore
dell'armatura non viene rieseguito su `start`; il broker mantiene i propri
controlli correnti di autorità.

## API di binding e responsabilità di B2

Funzione pubblica del nuovo runtime:

```python
binding_v5(config, cid, arming)
```

`config` è l'oggetto v5; `arming` sono i **byte esatti del payload firmato**,
non un dizionario o una sua ricodifica. Il risultato è SHA256 del JSON canonico
(`sort_keys=True`, separatori `,` e `:`, ASCII escape) dell'oggetto composto da:

- tutti i campi v5 eccetto `candidates`;
- `candidate`: entry inattiva v5 unita all'entry corrispondente dell'armatura;
- `armingGeneration`: intero della generazione;
- `armingPayloadSha256`: SHA256 dei byte esatti di `arming`.

`binding` v1–v4 non cambia. B2 scrive payload e firma con il ruolo
`RUNTIME_ARMING`, senza cambiare CID, bundleParents, manifest o altri campi
fissati nella v5 da B1. B2 prepara anche directory per CID 0700 e
`operation.lock` 0600 del registry, e il journal con chiavi esatte:

```python
{
    "schema": "ouf.semantic-docker-runtime-journal.v1",
    "containerId": cid,
    "configurationHash": binding_v5(config, cid, arming_bytes),
    "armingGeneration": generation,
    "state": "STAGED",
    "runtimeRoot": None,
    "bundleHash": None,
    "driverHash": None,
}
```

B2 riusa gli owner esistenti per i journal di ammissione del broker e i suoi
profili. Questo modulo non sostituisce quegli owner e non inizializza journal.
Ogni controllo runtime di `configurationHash` usa `binding_v5` con i byte
della generazione selezionata e registrata, preservata nei successivi update.

## Prova di annullamento

Il futuro controller B1 può chiamare in sola lettura:

```python
arming_absence(config_path)
# {"armingGenerations": [], "consumedMarkers": []}
```

Le generazioni sono interi ordinati, deduplicati tra payload e firma:
anche una firma orfana impedisce di dichiarare assenza. I marker sono nomi
completi ordinati, anche quando il payload è assente. La funzione controlla
configurazione e custodia, non avvia processi, non verifica firme e non scrive.
Solo entrambi gli elenchi vuoti provano assenza all'istante della lettura.
File estranei o custodia errata generano un errore, mai una falsa lista vuota.
Il controller deve garantire la quiescenza degli scrittori B2 durante la prova;
non è un lock distribuito o un'autorizzazione alla rimozione dei marker.

## Verifica e limiti

Workflow nuovo `semantic-runtime-v5-arming.yml`: Ubuntu 24.04, checkout
vincolato, test nativi root con fixture private sotto `/run`, nessun Docker
daemon, VPS o dato reale. runc/broker/driver simulati; firme Ed25519 reali con
chiavi esclusivamente effimere di test. Esegue i nuovi test e tutti i test del
task-14, con le variabili native che impediscono skip silenziosi in CI.

```sh
sudo -n env OUF_RUNTIME_V5_NATIVE=1 /usr/bin/python3 -I -B -m unittest discover -s tests -p test_runtime_v5_arming.py -v
sudo -n env OUF_B1B2_NATIVE=1 /usr/bin/python3 -I -B -m unittest discover -s tests -p test_semantic_b1b2_authority.py -v
```

In questa sessione Windows Python non è disponibile e WSL restituisce accesso
negato: i test non sono stati eseguiti localmente. Nessun risultato CI è
attestato da questa modifica. I workflow storici non vengono modificati.

**D-018 punto 3:** la validità durevole della firma dopo scadenza del mandato
resta da definire. La verifica di una nuova `create` richiede il mandato
`RUNTIME_ARMING` ACTIVE e valido fino al completamento; un payload emesso prima
di `expiresAt` non permette verifica storica dopo la scadenza. `issuedAt` non
scavalca revoca o scadenza. Il consumo già registrato mantiene la generazione
per le operazioni successive secondo D-014; non stabilisce una regola generale
di validità storica delle firme. La verifica del broker rimane indipendente.

Non vengono qualificati installazione, E2E reale, TLS, grant, readiness o
avvio dei due nuovi CID. Il lettore v4 dell'installer e il registro runtime
saranno adeguati da task successivi.

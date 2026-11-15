# Supervisore del lease Semantic v2 — R3

Il servizio attende la testa durevole `OPERATE` e due epoche `STARTED`, vive
sul boot corrente e legate all'hash della testa. Fissa CID, epoche e generazioni
per ogni scope; ogni variazione revoca il lease prima della nuova attesa.
Non firma, non legge chiavi private e non usa Docker. Tutte le scritture nft
passano dal coordinatore e dalla recovery R12 esistente, senza modifiche.

Avvio previsto su Linux root:root:

```sh
/usr/bin/python3 -I -B /opt/ouf/scripts/semantic-provider-lease-supervisor-v2.py \
  --configuration /etc/ouf/lease-v2/configuration.json \
  --configuration-sha256 <sha256-dei-byte-canonici>
```

L'installazione systemd appartiene al task-41: `BindsTo=docker.service`,
`Restart=always`, abilitazione al boot e directory di stato persistente.
Questo task prepara il processo, senza installare o avviare servizi.
`SIGTERM` segnala al ciclo di quiescere, pubblicare `STOPPED` e uscire con 0;
gli errori di quiescenza danno `FAILED` e uscita 1.

La configurazione canonica ha schema chiuso
`ouf.semantic-provider-lease-supervisor.v1`: `installationRef`, `entityRef`,
`issuerRef`, `authorizationRoot`, `anchorBinding`, `mandateRoot`,
`opensslBinding`, `mandatesModule`, `registryRoot`, `coordinator`,
`recoveryJournalRoot`, `statusPath`, `limits`, oltre a `schema`.
I binding sono `{path, sha256}`; OpenSSL aggiunge `version`.
Tutti i percorsi sono assoluti, senza traversal. `limits` contiene esattamente
`maxActivationsPerHour: 6`, `heartbeatSeconds: 1..30`, `pollSeconds: 1..300`.

`coordinator` contiene esattamente:

| Campo | Contenuto |
| --- | --- |
| `ownerConfiguration` | Binding della configurazione coordinata del proprietario R12 |
| `journalPath` | Journal di coordinamento esistente |
| `commonLockPath` | Lock comune esistente, mai ricreato dal servizio |
| `dnsProfile` | Binding del JSON canonico uguale al campo `dns` del proprietario |
| `nftBinding` | Binding del comando nft, coerente con il proprietario |

Il proprietario mantiene la struttura esistente R12 (`kernel`, `dns`, `binding`,
`expectedStructureHash`, `readBudgetSeconds`, `journalFile`, `commonLockFile`,
`nftPath`, `nftSha256`, `sourceHashes`). La sua closure è in `source/` accanto
alla configurazione. Viene caricata da byte verificati con `load_installed`,
senza eseguire i vecchi avviatori. Anche `mandates.py` viene compilato solo dai
byte verificati. Le librerie recovery hanno i pin LF R12 nel nuovo modulo:
la consegna deve preservare esattamente quei byte, senza conversione CRLF.

Configurazione, profili, moduli consegnati e journal sono file root:root 0600,
regolari e senza link; gli antenati devono essere root e non scrivibili da altri.
Il binario nft è root:root, eseguibile e non scrivibile da altri. I genitori
dello stato e della recovery sono directory preesistenti root:root 0700.
Il modulo non crea tabelle, lock comuni o journal di coordinamento.

Prima di consultare lo scope il processo esegue la quiescenza del coordinatore:
non adotta mai un lease preesistente. La recovery usa `RenewingLeaseAdapter`,
`LeaseRecovery(Policy())`, `Journal` e `Supervisor.serve` invariati. L'osservatore
termina lo scope sui checkpoint terminali; il ciclo verifica poi journal
`QUIESCED`, autorizzazioni false e set vuoti sotto il lock comune.
I tentativi transitori restano nella stessa recovery con il budget originale.

Ogni apertura riserva prima uno slot in `<statusPath>.activations.json`.
La finestra è `(adesso - 3600, adesso]`; oltre sei aperture il servizio resta
`PARKED_RATE_LIMITED`, quiescente, e ricontrolla a ogni heartbeat.
Il lock esclusivo `<statusPath>.lock` protegge l'intera invocazione.
Il registro non si azzera al riavvio: corruzione, cronologia mancante a fronte
di uno stato esistente o regressione dell'orologio negano nuove aperture.
Una directory casuale nuova sotto `recoveryJournalRoot` conserva ciascuna
recovery; quelle precedenti non vengono riaperte né cancellate.

Le guardie usano solo le categorie `Permanent` ammesse: `GENERATION_CHANGED`,
`AUTHORITY_REVOKED`, `CONFIGURATION_DRIFT`, `INTEGRITY_UNPROVEN`. Il motivo
dettagliato resta nel supervisore: per esempio `EPOCH_SCOPE_CHANGED` nello stato,
con `GENERATION_CHANGED` verso la recovery. Le eccezioni sconosciute diventano
`LOCAL_STATE_UNPROVEN`. Il binding nft è ricontrollato anche prima/dopo ogni
comando del backend, compresa la revoca. Se la custodia non permette una
revoca sicura, il servizio fallisce senza dichiarare quiescenza provata.

Lo stato `ouf.semantic-provider-lease-supervisor-status.v1` contiene soltanto
`state`, `reason`, `activationsLastHour`, `renewals`, `authorizationSequence`,
`epochs: {adapter, southbound}`, `updatedAt` e `schema`. `updatedAt` è Unix time
in secondi; `renewals` conta i rinnovi nell'invocazione corrente.
La scrittura usa temporaneo 0600, fsync, rename e fsync della directory.
Non include percorsi, indirizzi, messaggi di eccezione o segreti.

I test non nativi eseguono il ciclo reale con confini nativi finti.
Il gate `OUF_PROVIDER_LEASE_SUPERVISOR_NATIVE=1` richiede Linux root:root e usa
la fixture di `test_semantic_provider_operation.py` sotto `/run`: testa firmata,
OpenSSL, registro e processi reali. È cablato nel workflow dedicato; non richiede
DNS, nft, Docker o servizi esterni. Su Windows questi test restano saltati.

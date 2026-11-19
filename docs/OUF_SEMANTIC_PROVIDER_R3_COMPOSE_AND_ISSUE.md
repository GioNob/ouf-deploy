# R3: composizione deterministica ed emissione dell'autorizzazione

Task sprint-01/40b. Il compositore produce i byte che il task-41 dovrà
ricomporre e pubblicare. L'emittente pubblica esclusivamente la prima coppia
della catena di autorizzazione e la ricevuta di emissione. Nessuna azione su
Docker, nft, DNS, systemd, reti, servizi o dati applicativi.

## API pura

`tools.semantic_provider_r3.compose.compose(inputs)` riceve:

```python
inputs = {
    "files": {nome_logico: byte_del_file},
    "sources": {percorso_relativo_repository: byte_del_blob},
}
```

Le chiavi sono chiuse: `DATA_INPUTS` e `SOURCE_INPUTS` nel modulo.
Il risultato contiene `documents: {percorso_relativo_installazione: bytes}`,
`authorization: bytes`, `hashes: {percorso: sha256}`, `inputHashes`, `audit`
e `layout`. Non legge filesystem, orologi, chiavi o processi. Non modifica
gli input. Nessun valore del VPS è incorporato nel codice di composizione.

I nomi logici di `files` sono:

| Nome | Origine |
| --- | --- |
| `settings` | Parametri pubblici espliciti, schema chiuso descritto sotto |
| `coordinator` | `coordinated-configuration.json` del successore |
| `coordinationJournal` | Journal del medesimo coordinatore, `QUIESCED`, autorizzazioni false |
| `a2Manifest` | File `manifest.json` di A2, involucro `{manifest, planSha256}` |
| `successors`, `semanticPeer` | File `successors.json` e `semantic-peer.json` di A2 |
| `rootfs` | Ricevuta rootfs con `roles.<role>.effectiveSeal` e `aSuccessors` |
| `acceptance` | Payload dell'accettazione v5.1, generazione almeno 3 |
| `<role>/historicalTemplate` | `preparer-template.json` storico del ruolo |
| `<role>/template`, `/launch`, `/context`, `/policy` | I quattro file delle ricette v2 del ruolo |

`role` è esattamente `adapter` oppure `southbound`. Il manifest A2 deve
contenere gli stessi successori e peer, con gli hash dei file originali.
L'accettazione deve legare gli stessi file A2, piano, CID, immagini, transazioni,
ricette e sigilli, nello scope dell'ancora selezionata. Si verifica il payload
con il validatore reale dell'accettazione; il compositore non autentica la sua
firma. L'accettazione autenticata resta un requisito dell'installazione 41.

`settings` contiene esattamente:

```text
installRoot, issuedAt, installationRef, entityRef, issuerRef,
anchorBinding, mandateRoot, opensslBinding, coordinatorBinding,
tableNames, runtimeBinding, runtimeRootParent, rootfsLimits, supervisorLimits
```

I binding hanno `{path, sha256}`; `opensslBinding` aggiunge `version`.
`runtimeBinding` lega runc. `runtimeRootParent` è il parent dello stato runc,
usato come `runtimeStateRoot` nel v5.2 e `runtimeRootParent` nei broker.
`tableNames` contiene i due ruoli, nomi distinti conformi ad authorization,
diversi da `ouf_v2_adapter`, `ouf_v2_southbound` e dalla tabella del lease.
`rootfsLimits` e `supervisorLimits` seguono esattamente i validatori dei
componenti; il massimo delle attivazioni è 6, senza coefficienti aggiuntivi.

## Byte e tracciabilità

Tutti i nuovi JSON sono `authorization.canonical(value)`, ASCII, chiavi
ordinate, separatori compatti, nessun newline. Duplicati e numeri non finiti
sono rifiutati. Un input JSON è accettato solo se già canonico oppure canonico
più esattamente un LF; non si correggono spazi, CRLF o newline multipli.
Per `policy.json` delle ricette è obbligatorio **esattamente** canonico più LF;
ogni altra forma dà `RECIPE_POLICY_NOT_CANONICAL_PLUS_LF`.

La copia `documents/<role>/frame-policy.json` perde solo quel LF.
`framePolicySha256` e `artifactHash` sono l'hash della copia canonica;
`audit.<role>.recipePolicySha256` conserva l'hash originale con LF.
Le ricette vengono ricompilate con `compile_policy` e confrontate interamente.
`applicationHash` è lo sha256 del JSON canonico di `expectedOci`.
Il binding `creationFrameObserverBinding.configuration` punta alla copia
canonica, con lo stesso hash del campo nell'autorizzazione.

Trasporto e template sono derivati dal template storico; il sigillo è un
frammento della ricevuta rootfs. Non esistono file originali separati da cui
inventare hash: si conservano gli hash dei file contenitori originali in
`inputHashes` e `audit.historicalTemplateSha256` / `rootfsResultSha256`.
`originalTransportFragmentSha256` e `originalSealFragmentSha256` identificano
i frammenti canonici estratti, esplicitamente distinti dagli hash dei file.
La stessa regola canonico/solo-LF vale per quei contenitori. I byte sorgenti
sono conservati esatti; nessuna normalizzazione CRLF avviene nel compositore.

## Trasporto: percorso alternativo

Non viene chiamato `compile_successor_pair`: richiede ricevute storiche ulteriori,
ricompila un contesto nuovo e conserva i vecchi `tableName`. Qui le ricette v2
sono già quelle dei CID A2 e il requisito impone tabelle nuove.

Si conservano comandi, relativi hash, Python, budget, namespace host e campi
dei flussi storici. Le NIC mantengono interfaccia, bridge, IP, MAC e riferimenti;
si aggiorna solo `leaseGuard.configurationHash` al binding del successore.
Il template usa `kernel`, `dns`, binding, journal e lock del successore.
Il candidato riceve il CID A2, la tabella da CLI e il binding runc esplicito.
Il `transactionId` nel template è una correlazione deterministica di ruolo,
CID e binding del coordinatore; il preparer v2 lo sostituisce con la propria
correlazione dell'epoca, come previsto dal componente.

I peer reciproci ricevono il CID A2, l'hash applicativo della ricetta v2 e le
stesse NIC con guard aggiornato. Il resto dei flussi resta uguale.
L'ingresso Semantic usa **BRIDGE_PORT** e `proposedIngress` di `semantic-peer.json`
A2, verificando indirizzi, protocollo, porta e corrispondenza con
`binding.hostIfindex`. A2 non contiene un `applicationHash` Semantic indipendente:
non si inventa una dichiarazione `CREATED_CANDIDATE`. Il collegamento verrà
nuovamente osservato dal percorso nativo di ammissione; questa composizione
non attesta la sua validità attuale.

## Layout e validatori

Sotto `installRoot`:

```text
source/<percorsi del repository e alias v1 richiesti dai bootstrap>
runtime-configuration.json
broker/{adapter,southbound}.json
documents/<role>/{frame-policy,rootfs-seal,transport,preparer-template}.json
supervisor/{configuration,dns-profile}.json
supervisor/state/recovery/
registry/<cid>/epochs/
registry/<cid>/operation.lock
authorization/{1.json,1.signature.json}
```

`layout.directories0700` elenca tutti i parent, incluse le directory per CID;
`files0600` elenca file e coppia firmata. I lock sono byte vuoti, con hash
dell'input vuoto; nessun journal, puntatore `current` o epoca viene precreato.

La chiusura contiene runtime v5.2, tre entrypoint v2, pacchetto admission v2,
authorization, epochs, supervisore ed entrypoint, 11 librerie recovery,
`mandates.py` e l'osservatore del frame autosufficiente. I moduli v1 provengono
da `tools/semantic_cohort_admission/cohort-draft/tools/`: sono conservati con
quel percorso e duplicati come `source/tools/<nome>.py`, perché i bootstrap
v2 richiedono questi alias. `SOURCE_MAP` descrive la corrispondenza completa.
Ogni copia ha l'hash del blob fornito. Nessuno script v1 storico viene usato.

Broker e supervisore hanno ciascuno il proprio insieme chiuso `sourceHashes`.
Il runtime usa invece `sourceHash` e binding puntuali, come richiede il suo
schema. Il proprietario del lease rimane nella posizione originale, con la sua
closure `source/` già installata accanto: copiarlo sotto il nuovo root senza
quella closure romperebbe `load_installed`. La configurazione del supervisore
lega i byte **originali** del proprietario; solo il profilo DNS è una nuova
copia canonica, identica a `canonical(owner['dns'])`.

Il compositore esegue `broker_v2.validate`, `evidence_v2.documents`,
`authorization.validate`, `lease_supervisor.validate` e il reale
`load_configuration` v5.2. Per questi ultimi due carica i blob completi in
moduli privati: gli import nativi non usati dal validatore sono inerti,
`Path` è lessicale POSIX e la lettura del runtime usa i byte in memoria.
Non viene modificato `sys.modules`. La custodia nativa rimane responsabilità
dell'emittente/installer. I test verificano anche un grant futuro con
`driver_v7.validate` e il metodo reale `CreatedFrameObserver.observe`,
simulando solo custodia e subprocess dell'osservatore; non dichiarano frame
vivi osservati. La suite nativa carica inoltre la configurazione v5.2 senza
adattatori di portabilità.

## CLI plan/apply

L'indice pubblico passato con `--inputs` è un JSON canonico (eventuale solo LF):

```json
{"schema":"ouf.semantic-provider-r3-inputs.v1","files":{"settings":{"path":"/percorso/settings.json","sha256":"<64 hex>"}},"sources":{}}
```

L'esempio è abbreviato: `files` deve contenere tutti i `DATA_INPUTS`, `sources`
tutti i `SOURCE_INPUTS`, ciascuno con un binding indipendente `{path,sha256}`.
I sorgenti sono esportazioni esatte dei blob del repository, inclusi i pin LF
delle librerie recovery. Il programma non interroga Git o servizi esterni.

Argomenti obbligatori comuni:

```text
--inputs PATH --inputs-sha256 SHA
--authority-profile PATH --authority-profile-sha256 SHA
--private-key-path PATH  [ripetuto per ogni chiave del profilo]
--install-root PATH --issued-at UNIX_SECONDS
--table-name adapter=NUOVO_NOME southbound=NUOVO_NOME
--output-directory PATH_NUOVO
```

`installRoot`, `issuedAt`, `tableNames` di settings vengono sostituiti dai
valori CLI prima della composizione; gli altri parametri restano espliciti
nell'indice. Per esempio si può scegliere
`/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1`: è un parametro,
non un percorso incorporato nel codice. Tutti i parent devono già esistere
con custodia root; `installRoot` può essere assente oppure root:root 0700.
La directory di output deve essere nuova e separata dall'albero di installazione.

Invocare con Python `-I -B`, root:root. `--plan` non crea file né legge chiavi:
i percorsi di **tutte** le chiavi sono esclusi prima della prima lettura,
compresa quella del profilo delle autorità. Il profilo deve confermare
esattamente l'insieme escluso. Symlink, hardlink, antenati scrivibili e drift
di contenuto/custodia sono rifiutati. I file pubblici devono essere regolari,
root:root, non scrivibili da gruppo/altri e vincolati per hash.

Il plan verifica il profilo con l'ancora, il mandato installer RUNTIME_ARMING
attivo ora e a `issuedAt`, la non revoca e OpenSSL fissato per hash/versione.
Restituisce payload, hash di tutti i documenti, layout, audit, snapshot del
registro e `planSha256 = sha256(canonical(plan))`. Nessun tempo osservato o
percorso temporaneo generato entra nel digest. I path espliciti degli input
e dell'output ne fanno parte: vanno conservati tra plan e apply.

`--apply --plan-sha256 SHA` ripete letture e composizione, confronta il digest,
poi crea esclusivamente la directory di output come **claim duraturo**.
Da questo punto `doNotRerunApply=true`, anche se manca ancora una firma.
Se necessario crea `installRoot` e `authorization/` con mkdir esclusivo 0700;
una directory authorization esistente deve essere vuota, root:root 0700.
Un lock esclusivo sul suo inode serializza l'emissione.

L'apply ricontrolla input e mandato, verifica l'hash della chiave installer
0600 prima e dopo la firma e confronta la chiave pubblica con il registro.
OpenSSL usa il percorso di custodia originale per derivare il pubblico e
firmare. Sotto il claim 0700 viene creato il solo frame temporaneo di firma,
rimosso al termine del contesto. `privateKeysRead=1` conta un utilizzo logico
della chiave installer.

Il frame è `authorization.signing_bytes`, dominio separato
`OUF-SEMANTIC-PROVIDER-OPERATION\0V1\0`, ruolo `RUNTIME_ARMING`.
L'envelope è `authorization.SIGNATURE_SCHEMA`, canonico **senza LF**.
Si verifica la firma prima di pubblicarla. `1.json` e `1.signature.json`
sono scritti O_EXCL 0600, con fsync; `authorization.head` deve rileggere
sequenza 1, `OPERATE` e hash esatto. `result.json` nella directory di output
nuova riporta `privateKeysRead=1`, `signaturesIssued=1`,
`installationDocumentsPublished=0`, `runtimeActions=0`, `doNotRerunApply=true`.

In caso di errore vengono stampati solo codici pubblici e contatori/fase.
Una firma tentata dall'esito incerto lascia `signaturesIssued=null`.
Non si cancellano catene o claim parziali e non si ripete automaticamente
l'apply. La rimozione riguarda solo il materiale temporaneo di firma.

`imageManifestDigest` nel payload contiene l'ID immagine Docker A2 `.Image`,
come impone la nota §14 del design, senza reinterpretarlo come digest del
manifest di distribuzione.

## Emissioni successive con `--supersede`

1. Con la testa ancora allineata alla configurazione installata, fermare il
   provider con `operate stop` plan/apply se i candidati sono accesi.
2. Verificare i due CID fermi, il lease in quiescenza e il cleanup prima di
   cambiare la testa. Ogni `FAILED` preparato (`driverHash` presente) deve
   avere la sua ricevuta `runtime-cleanup.json`, anche nello storico.
3. Eseguire issue plan/apply con `--supersede` e il nuovo `planSha256`.
4. Eseguire upgrade plan/apply, quindi `operate start` con il nuovo wrapper.

L’issuer autentica la testa `OPERATE` precedente e la confronta con la
configurazione selezionata da `/usr/local/sbin/ouf-semantic-admitted-v2`.
Legge da quella configurazione i due CID e vincola lo storico dei journal e
le ricevute nel campo `supersession` del plan. `ISSUE_SUPERSEDE_PROVIDER_NOT_STOPPED`
indica un’epoca aperta. `ISSUE_SUPERSEDE_PREPARED_CLEANUP_PENDING` indica una
ricevuta assente o non valida per un `FAILED` preparato. Un puntatore, un
binding o una configurazione indimostrabili bloccano la supersessione.

In apply l’issuer acquisisce i due `operation.lock` in ordine di CID, poi il
lock della catena. Ripete il controllo sotto lock prima del claim. I dinieghi
del gate lasciano `privateKeysRead=0` e `signaturesIssued=0`. I lock restano
acquisiti durante la pubblicazione e fino alla rilettura autenticata di
N+1. La prima emissione usa la procedura descritta sopra.

## Verifiche e limiti

Le fixture sono sintetiche, con struttura e valori d'esempio del §14:
coordinatore successore, due/tre NIC, guard, peer reciproci, ingresso A2,
ricette indipendenti e sigilli. Non provengono da nuove letture VPS.

Il workflow `semantic-provider-r3-issuance.yml` esegue compositore, emissione
con `OUF_OPERATION_ISSUANCE_NATIVE=1` e tutte le regressioni richieste con i
rispettivi gate nativi. La chiave Ed25519 è effimera, il registro è di fixture,
la CLI è invocata realmente. Copre digest/input cambiati, mandato non attivo
ora o all'emissione, root occupata/custodia errata, dominio B1/B2 rifiutato,
claim dopo errore, root assente/vuota e rilettura della testa.

Sul Windows locale sono eseguibili compositore, test portabili e py_compile.
WSL nega l'accesso (`E_ACCESSDENIED`): i test Linux/root rimangono da eseguire
in CI. Questo task non attesta installazione 41, primo start, lease attivo,
TLS, discovery o prova E2E.

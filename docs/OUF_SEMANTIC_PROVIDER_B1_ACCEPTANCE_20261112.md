# Manifest di accettazione artefatti B1

Task `sprint-01/task-15`, 12 novembre 2026. Decisioni di riferimento:
D-011 punti 2 e 4, D-014, D-016, D-017, D-018 punto 3.
Questo task consegna schema, costruttore e verificatore; non emette accettazioni,
non legge chiavi private e non installa la configurazione runtime v5.
I riferimenti reali sotto provengono dal mandato, senza osservazioni VPS.
La [nota B1](OUF_SEMANTIC_PROVIDER_B1_DESIGN.md), §§3, 4 e 11, conserva il
contesto delle ricette e delle evidenze ancora da produrre.

## Contratto e schema

Modulo: `tools/semantic_b1_acceptance/acceptance.py`.
`validate_acceptance(value)` restituisce una copia indipendente del manifest.
Ogni oggetto ha esattamente le chiavi indicate; mancanze, chiavi aggiunte e tipi
diversi sono rifiutati. `bool` non vale come intero. Hash esadecimali minuscoli.

Un **binding** è sempre `{"path": <assoluto POSIX>, "sha256": <64 hex>}`.
La validazione è lessicale e portabile anche su Windows: niente apertura,
risoluzione di symlink, stat o lettura degli artefatti. Percorsi normalizzati,
senza `..`, componenti `.`, slash doppi, slash finale, backslash o caratteri di
controllo; `/` da solo non identifica un input. I path relativi della closure
seguono le stesse regole, con almeno una componente e senza `:`.

| Campo | Forma esatta e origine |
| --- | --- |
| `schema` | Letterale `ouf.semantic-provider-b1-artifact-acceptance.v1`. |
| `installationRef`, `entityRef` | Identità del perimetro approvato P/autorità, con sintassi task-14 `[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`. L'entity reale va acquisita dagli input approvati, non indovinata. |
| `generation` | Intero ≥1, assegnato dall'emittente. Ogni nuova accettazione degli stessi CID lo incrementa; il controller conserva il limite minimo indipendente. Il modulo non ha uno storico persistente e non può incrementarlo automaticamente. |
| `profile` | Binding ai byte esatti di P, senza riformattare il JSON per calcolarne l'hash. |
| `preparationA` | Esattamente `root`, `planSha256`, `files`: root assoluta POSIX della preparazione già conclusa, digest del piano A e quattro binding. Il digest del piano non viene ricostruito dai soli quattro file. |
| `preparationA.files` | Esattamente `manifest`, `result`, `semanticPeer`, `successors`, ciascuno un binding rispettivamente a `manifest.json`, `result.json`, `semantic-peer.json`, `successors.json`. Gli hash raw vengono dalle evidenze A verificate dal controller. |
| `creation` | Esattamente `transactionRef`, `evidence`, `declaredGaps`. Transazione della creazione conservata da A; stessa sintassi delle identità per il riferimento. `evidence` è solo `PREPARATION_A_ONLY`. |
| `creation.declaredGaps` | Lista di codici stabili unici con sintassi `[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*`. Nessuna descrizione libera o conversione delle lacune in prove. Lo schema ammette una lista vuota e codici ulteriori; l'emittente deve dichiarare tutte le lacune effettive. |
| `roles` | Esattamente `adapter` e `southbound`; nessun terzo ruolo. |
| `roles.<role>` | Esattamente `containerId`, `imageId`, `recipe`, `rootfs`. CID di 64 hex, distinti fra ruoli; immagini `sha256:` seguito da 64 hex. Dati della creazione vincolati ad A e alle aspettative indipendenti. |
| `roles.<role>.recipe` | Esattamente `template`, `launch`, `context`, `policy`, tutti binding alle nuove ricette revisionate. I due insiemi di binding `(path, sha256)` devono essere diversi, anche se si cambia l'associazione alle quattro parti. Non è richiesta disgiunzione: una parte comune non rende identiche due ricette altrimenti distinte. |
| `roles.<role>.rootfs` | Esattamente `offlineImageReceipt`, `offlineDockerReceipt`, `comparison` (binding), `effectiveSeal` (oggetto). Evidenze future per i nuovi CID, senza fallback a evidenze storiche. |
| `roles.<role>.rootfs.effectiveSeal` | Esattamente `schema`, `sha256`, `entries`, `bytes`: schema `ouf.semantic-rootfs-seal.v1`, digest 64 hex, entries intero ≥1, bytes intero ≥0. È il seal effettivo della comparison, distinto da offline e atteso. Il modulo ne valida la struttura senza ricostruirlo. |
| `softwareClosure` | Esattamente `sourceCommit` (40 hex) e `files` (dizionario di 1–256 path relativi → SHA-256). Commit e byte revisionati di sorgenti e dipendenze della futura consegna B1. Nessuna enumerazione automatica del checkout, nessun uso implicito di HEAD. |
| `trustPolicy` | Binding alla policy separata B1/B2; deve coincidere anche con `authenticator.policy_binding` e con l'aspettativa del controller. |
| `startAuthorized`, `leaseAuthorized` | Entrambi il booleano letterale `false`, non `0`. Questa accettazione non concede start o lease. |
| `issuedAt` | Intero epoch ≥0 fornito dall'emittente. Informativo: non sostituisce i controlli temporali sul mandato della chiave. |

Il controllo sintattico non interpreta il contenuto dei file referenziati e non
dimostra custodia, uguaglianza delle rootfs o correttezza della closure. Queste
prove e i loro hash indipendenti spettano al futuro controller B1 e alla review
prima dell'emissione. La firma lega tutti i campi, comprese ricette, seal,
transazione, closure e lacune.

## Riferimenti acquisiti e valori ancora mancanti

| Input | Valore del mandato |
| --- | --- |
| P | `/etc/ouf/installations/ouf-lab-netcup-01/semantic-provider.json` |
| P SHA-256 | `5d8500161bfc5f57d7ed94a93868e3fba5e26bfcde781ee1d38354b04dbee76d` |
| A root | `/var/lib/ouf-storage-migration/semantic-provider-preparation-a-20261111` |
| A piano | `17de05e7d9b9610e58919a5b22697f28865ea0b076327d0b477fbae03d22daa8` |
| Transazione | `7ff12b95c3f70c5eaebb1d0a12ab931d` |
| Adapter CID | `85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef` |
| Adapter imageId | `sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc` |
| Southbound CID | `34adce783cba238c1954eb33e39c37a641ea4f0db212531951a2fd2b86290c52` |
| Southbound imageId | `sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366` |
| Trust policy | `/etc/ouf/deploy-snapshots/semantic-provider-b1b2-trust-policy-20261112/trust-policy.json` |
| Trust policy SHA-256 | `6ef247ee727484777557cdb5adb05428e6d020da1e2e49773a84eedc56be4f95` |

Il riferimento P corrente del mandato prevale sul digest storico nella nota B1.
Non sono forniti qui gli hash raw dei quattro file A, le nuove ricette,
le ricevute e i seal rootfs, la closure completa e le identità di emissione.
Questi valori non vengono inventati. `fixture()` nei test mostra la struttura
completa con i riferimenti reali sopra e hash **sintetici espliciti** per i dati
mancanti; non è un manifest da emettere. Nei test nativi il binding della policy
reale è sostituito da quello della policy pubblica temporanea di test.

D-011 punto 4: A è l'unica evidenza di creazione utilizzata. Per il caso corrente
la review deve mantenere visibili almeno le lacune
`PRE_CREATE_REQUEST_NOT_RETAINED` e `CREATION_RECEIPT_NOT_RETAINED`.
La transazione e il frame conservati in A non ricostruiscono una richiesta
pre-CREATE o una ricevuta di creazione non conservate. Il modulo non produce
attestazioni sostitutive.

## Costruzione, firma separata e verifica

`build_acceptance(**fields) -> bytes` richiede tutti i campi, incluso `schema`,
riapplica lo schema e usa `authority.canonical`: chiavi ordinate, separatori
compatti `,` e `:`, `ensure_ascii=True`, nessun NaN, **un solo LF finale**.
Nessun valore o timestamp viene aggiunto. Gli stessi input producono gli stessi
byte. Limite del payload 131072 byte, uguale al limite del task-14.

`payloadSha256` è SHA-256 di tutti i byte, incluso LF. Il file separato di firma
ha nome `<payloadSha256>.ARTIFACT_ACCEPTANCE.json`, envelope
`ouf.semantic-provider-b1b2-detached-signature.v1`, algoritmo Ed25519,
ruolo `ARTIFACT_ACCEPTANCE`, issuer atteso e installation/entity del manifest.
Dominio e frame sono quelli del task-14: nessuna nuova implementazione o
funzione di firma. Il chiamante caricherà il file di firma dal nome convenuto;
questa API riceve byte e quindi non verifica un nome file che non le è passato.

```python
result = verify_acceptance(manifest_raw, signature_raw,
                           expected=expected, authenticator=authenticator)
# {"payloadSha256": <sha256 dei byte ricevuti>, "manifest": <copia validata>}
```

`authenticator` è un `authority.B1B2Authenticator` configurato dal controller
con binding della policy pubblica, OpenSSL e clock/budget del task-14.
Solo quel verificatore legge la policy pubblica e verifica il binario OpenSSL;
il modulo di accettazione non segue i path degli artefatti. Firma e hash si
verificano sui byte ricevuti, senza ricostruire o normalizzare il JSON.
Il verificatore accetta anche JSON validamente firmato con spaziatura differente;
ciò produce un digest differente. Duplicati, JSON malformato, costanti non finite
e payload fuori limite sono rifiutati prima dell'autenticazione.

`expected` è un dizionario chiuso, fornito da fonti indipendenti dal manifest:

```text
{
  installationRef, entityRef, issuerRef,
  profileSha256,
  preparationA: {
    planSha256,
    files: {manifest: SHA256, result: SHA256,
            semanticPeer: SHA256, successors: SHA256}
  },
  roles: {
    adapter: {containerId, imageId},
    southbound: {containerId, imageId}
  },
  trustPolicy: {path, sha256},
  minimumGeneration
}
```

Questa è la notazione del contratto, non JSON emettibile. Gli hash, le identità,
i digest immagine e i binding seguono la sintassi del manifest;
`minimumGeneration` è un intero ≥1. Il controller deve aggiornarlo per una nuova
accettazione degli stessi CID. Non copiarlo dal manifest da verificare.
Per P viene confrontato l'hash; per A il piano e i quattro hash raw; per i due
ruoli CID e immagine; per la trust policy entrambi path e hash. Path di P/A,
ricette, rootfs e closure sono contenuto firmato: questa API non apre tali file
né li aggiunge implicitamente alle aspettative di contenuto del controller.

La verifica procede con schema manifest/expected, uguaglianza del binding policy
fra manifest/expected/autenticatore, verifica task-14 di firma/ruolo/issuer/scope,
quindi confronto degli altri pin. Il controllo della policy precede la firma
per impedire l'uso di un autenticatore relativo a un'altra policy. Il metodo del
task-14 deve restituire esplicitamente `True`; `False` o `None` producono
`ACCEPTANCE_SIGNATURE_UNPROVEN`.

## Rifiuti pubblici

`AcceptanceDenied` contiene solo un codice stabile, senza valori degli input.
I rifiuti di autenticazione sono `authority.AuthorityDenied` del task-14,
propagati senza trasformazione, incluso il rifiuto dell'issuer sbagliato.

| Differenza dagli input attesi | Codice |
| --- | --- |
| Installation / entity | `ACCEPTANCE_INSTALLATION_MISMATCH` / `ACCEPTANCE_ENTITY_MISMATCH` |
| Issuer nella firma | `EXACT_DETACHED_SIGNATURE_REQUIRED` (task-14) |
| Hash di P | `ACCEPTANCE_PROFILE_MISMATCH` |
| Piano A | `ACCEPTANCE_A_PLAN_MISMATCH` |
| Quattro file A | `ACCEPTANCE_A_MANIFEST_MISMATCH`, `ACCEPTANCE_A_RESULT_MISMATCH`, `ACCEPTANCE_A_SEMANTIC_PEER_MISMATCH`, `ACCEPTANCE_A_SUCCESSORS_MISMATCH` |
| CID / immagine, in ciascun ruolo | `ACCEPTANCE_CID_MISMATCH` / `ACCEPTANCE_IMAGE_MISMATCH` |
| Policy, path o hash, anche nell'autenticatore | `ACCEPTANCE_TRUST_POLICY_MISMATCH` |
| Generazione sotto il minimo | `ACCEPTANCE_GENERATION_MISMATCH` |

Gli errori strutturali hanno codici per oggetto (`ACCEPTANCE_FIELDS_REQUIRED`,
`ACCEPTANCE_ROLE_FIELDS_REQUIRED`, `ACCEPTANCE_RECIPE_FIELDS_REQUIRED`, ecc.).
Le principali violazioni dei valori sono `ACCEPTANCE_SCHEMA_REQUIRED`,
`ACCEPTANCE_IDENTITY_REQUIRED`, `ACCEPTANCE_GENERATION_REQUIRED`,
`ACCEPTANCE_ABSOLUTE_PATH_REQUIRED`, `ACCEPTANCE_RELATIVE_PATH_REQUIRED`,
`ACCEPTANCE_SHA256_REQUIRED`, `ACCEPTANCE_CID_REQUIRED`,
`ACCEPTANCE_IMAGE_ID_REQUIRED`, `ACCEPTANCE_DISTINCT_CIDS_REQUIRED`,
`ACCEPTANCE_DISTINCT_RECIPES_REQUIRED`, `ACCEPTANCE_GAP_CODES_REQUIRED`,
`ACCEPTANCE_SEAL_SCHEMA_REQUIRED`, `ACCEPTANCE_SEAL_ENTRIES_REQUIRED`,
`ACCEPTANCE_SEAL_BYTES_REQUIRED`, `ACCEPTANCE_CLOSURE_FILES_REQUIRED`,
`ACCEPTANCE_START_FORBIDDEN`, `ACCEPTANCE_LEASE_FORBIDDEN`.
Gli errori di expected sono identificati dai controlli `ACCEPTANCE_EXPECTED_*`
e dagli stessi controlli binding; il codice del modulo è l'elenco completo.

## Sequenza futura e limite temporale

1. Preparare e qualificare le ricette indipendenti dei nuovi CID e le evidenze
   rootfs offline immagine/Docker e comparison; selezionare il seal effettivo.
   Riferimenti di formato: `compose_successor_cohort.py:59-76`,
   `prepare_provider_image_rootfs.py:180-229`,
   `semantic_provider_node_observation.py:24-95`,
   `compare_provider_v2_stopped_rootfs.py:108-134` nei percorsi del task.
2. Fissare i quattro hash A, P, policy e closure revisionata; dichiarare le
   lacune di A e una nuova generazione. Costruire e revisionare i byte canonici.
3. L'umano emette la firma separata con la chiave installer avente mandato
   `ARTIFACT_ACCEPTANCE`, fuori da questo modulo e dal controller B1.
4. Il futuro B1 verifica firma, input e generazione, poi lega il digest del
   manifest alla configurazione inattiva v5. Consumo e installazione della v5
   appartengono al task successivo. Start e lease restano false; B2 e il ruolo
   `RUNTIME_ARMING` seguono il proprio percorso di autorità.

**Limite noto D-018 punto 3:** non è ancora definita la validità durevole dopo
la scadenza della chiave. Per ora occorre un mandato `ACTIVE` al momento della
verifica e ancora valido al completamento, come nel task-14. Un payload emesso
durante la validità della chiave viene rifiutato dopo `expiresAt`, anche se
payload e firma non sono cambiati. `issuedAt` non abilita verifica storica né
override della revoca. Il test
`test_current_active_mandate_required_even_for_earlier_issued_payload` dimostra
questo limite con una firma Ed25519 reale e clock controllato.

## Verifica e stato delle prove

Il workflow `semantic-provider-b1-acceptance.yml` parte su pull request per i
nuovi file e `tools/semantic_b1b2_authority/**`; usa Ubuntu 24.04, checkout
vincolato e sudo nativo come il task-14. Comandi esatti:

```sh
sudo -n env OUF_B1_ACCEPTANCE_NATIVE=1 /usr/bin/python3 -I -B -m unittest discover -s tests -p test_semantic_b1_acceptance.py -v
sudo -n env OUF_B1B2_NATIVE=1 /usr/bin/python3 -I -B -m unittest discover -s tests -p test_semantic_b1b2_authority.py -v
```

Le prove native generano chiavi Ed25519 usa e getta sotto `/run` e una policy
pubblica di test; non usano segreti esistenti. L'envelope legacy e le firme con
dominio legacy vengono rifiutati anche dopo rietichettatura; ruolo, scope,
payload alterati, pin, mandato scaduto/revocato/futuro hanno prove dedicate.
Le suite senza il flag nativo eseguono solo i test portabili e segnalano gli
skip nativi; col flag richiesto una piattaforma diversa da Linux root:root è un
errore, non uno skip silenzioso.

In questa sessione Windows Python non è disponibile nel PATH; WSL restituisce
`E_ACCESSDENIED`. Non è stato possibile eseguire le suite o attestare CI verde.
Il workflow è predisposto ma non avviato: nessun push, accesso esterno o
installazione è stato effettuato. Nessuna prova funzionale su VPS è implicata.

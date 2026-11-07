# SeaweedFS 4.52 — service account e federation fixture su SDK v2

Data: 3 novembre 2026. Ambito: sviluppo e qualifica repository, zero operazioni target.

## Modifica

`4.52-iam-service-account-sdk-v2.patch` migra tre importatori del modulo annidato
`test/s3/iam`: service account lifecycle, service account security e
`GetFederationToken`. Il framework IAM condiviso resta invariato. I nove file
residui continuano a richiedere SDK v1 e non sono dichiarati qualificati.

I nuovi client S3 usano SDK v2, endpoint esplicito, path style, regione
`us-east-1`, credenziali statiche della fixture e session token quando presente.
Coppie di credenziali assenti o parziali sono rifiutate prima del trasporto.
Ogni chiamata SDK usa il contesto del test, un solo tentativo e timeout HTTP di
30 secondi. I cleanup S3 hanno un contesto indipendente limitato a 30 secondi.
Calcolo e validazione checksum rimangono abilitati per operazioni supportate
(`WhenSupported`); il test del PUT verifica CRC32 e byte originali.

Le richieste IAM/STS raw mantengono form URL-encoded, servizio e regione di
firma, endpoint e timeout; riusano il signer v2 già qualificato dalla patch21.
Il helper raw IAM conserva il ciclo di vita HTTP precedente, necessario anche
ai cleanup esistenti. Gli errori S3 vengono estratti dalla catena Smithy;
un errore di trasporto non è più scambiato per una prova valida delle credenziali.

## Prove locali e limiti

- Sequenza upstream `984eac6a790be89e2a11de175a7413e1e3e32dd3` +21 patch +questa:
  riapplicazione e confronto byte-per-byte dei sette file PASS.
- Importatori IAM 12→9; sulla sequenza isolata, totale repository 20→17.
  Eventuali patch indipendenti successive vanno conteggiate dal workflow cumulativo.
- Compilazione intero modulo e otto test deterministici top-level PASS, con due
  sotto-casi aggiuntivi; sei test sono nuovi e due verificano il signer precedente.
- Prove senza rete: PUT firmato/path/body/token/checksum; dinieghi403 e503
  con un solo tentativo; cancellazione; cleanup limitato; credenziali incomplete
  senza trasporto; firma e body IAM Query.
- Grafo del nuovo helper S3 con i pin pubblicati esatti: 272 pacchetti,
  zero AWS SDK v1.

La compilazione locale dell'intero modulo usa un **modfile temporaneo** perché
i pin storici SDK v1 `v1.44.0`, JWT `v5.3.0` e testify `v1.8.4` non sono in cache;
le sostituzioni locali sono `v1.55.8`, `v5.3.1`, `v1.12.1`. Queste sostituzioni
non appartengono alla patch. Il workflow dedicato deve compilare con
`-mod=readonly` gli esatti pin pubblicati prima della promozione hosted.
Sono aggiunti S3 v2 `v1.114.1` e i relativi pin interni già qualificati nel modulo
root; SDK v2 core `v1.47.5` e Smithy `v1.28.7` restano invariati.

Le prove non eseguono roundtrip SeaweedFS/Keycloak live e non provano la
conformità delle policy di service account/federation. Le tolleranze e gli skip
storici dei test live restano da qualificare, non vengono promossi a PASS.
La coorte OCI esatta a15 patch non cambia, nessuna release è ammessa.

## Autorità conservate

Matrix1.7, PET UDP §109.4/109.5 e policy resilienza v3 mantengono owner,
contesti e budget finiti. Restano 0/8 gate, 0/21 AT e 0/120 oggetti reali;
MinIO attivo, Scope17/52 Engine GET consumati, Teatri/M1 e Farmacie invariati.
Nessun replay/reset/grant, merge, deploy o autorità runtime.

## Verifica locale successiva con pin esatti

Il download verificato dei pin originali ha permesso la compilazione dell’intero modulo con `-mod=readonly`, senza modfile sostitutivi: otto test principali e due sottocasi PASS. `go.mod` e `go.sum` restano byte-identici. La precedente prova con sostituzioni resta storica; il suo limite è risolto per queste verifiche bounded. Nessun roundtrip live IAM/Keycloak è stato eseguito.

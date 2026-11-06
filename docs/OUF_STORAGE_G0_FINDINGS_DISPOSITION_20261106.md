## Aggiornamento corrente — sei riferimenti classificati, due payload managed residui

[Esito operatore](../evidence/storage-g0-reference-classification-operator-20261106.json) del classificatore e2983e13:le18impronte coincidono esattamente con la reconciliation conservata.4sample_ref sono PROFILE_DB_SAMPLE_JOB_LINKED_CONTENT_NOT_EXPORTED;2evidence_ref sono CONTRACT_MAPPING_DIAGNOSTIC_LABEL;2payload_ref sono MANAGED_OBJECT_REFERENCE_REQUIRES_BINDING_REVIEW. Quattro campioni logici e due etichette sono ora distinti dai due riferimenti fisici residui. Il contenuto dei campioni non era esportato: il suo mantenimento appartiene al backup/restore DB completo,non a una nuova copia S3 di URI profile://.

Tutti10campi tenant sono NULL:1riga di owner-reconciliation coerente con asset/hash/size,9senza;0righe upload coerenti,2source_ref presenti e8assenti. Subject e source-review non esportati: nessuna proprietà autenticata dedotta. Il percorso di migrazione deve preservare NULL,prove originali e dinieghi; non è autorizzato backfill,adozione o riparazione. La classificazione legacy non azzera automaticamente il rilievo o chiude G0.

Entrambi i bucket:ACL PRESENT,un grant,Owner.ID assente;policy ABSENT,publicAccessBlock UNSUPPORTED. Versioning e notification PRESENT indicano risposte disponibili,non necessariamente feature attive. CORS/encryption/lifecycle/objectLock/replication ABSENT nei riscontri. La protezione effettiva resta aperta:assenza policy o ID owner non prova né accesso anonimo né protezione equivalente.

### Controllo locale raggruppato, senza nuova raccolta

`scripts/review-storage-g0-final-local-20261106.py` completa il collegamento dei2payload verso asset esatto e corpo nel bucket Onboarding vincolato; confronta hash/dimensione già osservati,run/attempt e binding nello snapshot. Conflitti tenant esplicito/source snapshot sono riportati,mai riparati. I NULL restano proprietà non provata anche quando il collegamento fisico è coerente.

Nello stesso comando:classificazione minima del grant ACL (tipo,permesso,presenza ID,gruppi pubblici senza identificativi),valori versioning e conteggi destinazioni notification;13ruoli e container fuori roster nell'inventario host prima/dopo già conservato. Running e revision sono dati al momento della raccolta,non un nuovo probe;revision è dichiarata,non prova di membership sorgente. Env values,mount path,containerID,bucket,grantee privati e righeDB non sono emessi. Image/revision digest pubblicati servono al successivo confronto delle coorti.

Dieci file locali:reconciliation,claim,2export,collection metadata,inventory-before,host-before/after,input base e dichiarazione runtime già vincolata. I primi dati usano i digest riportati dall'operatore;input base dc0ab6d4 e claim cec357cb fissati;runtime confrontato al digest claim per evitare bucket indovinati. Host prima/dopo devono coincidere e corrispondere ai13binding del medesimo input;gli hash di host sono osservati ora,non attestati come sigillo storico indipendente.

Zero provider/credenziali/corpi/SQL/write/replay. Sintassi e smoke sintetico PASS per payload positivo,hash diverso,conflitto tenant/snapshot,gruppoACLpubblico,versioning non impostato e redazione runtime. Esito VPS pendente. Non ripetere classificatore precedente o raccolta02. Dopo questo riepilogo,la review deve separare le disposizioni documentabili dalle evidenze operative mancanti (ACCESS/CUSTODY/WINDOW/WRITERS,capacità/obiettivi),senza supporre che un altro riepilogo provi proprietà o backup indipendente.

Stato di accettazione invariato;secondo passo della coppia raccolta+riconciliazione ancora in corso,nessun credito per questo controllo preparato.

# G0 — disposizione preliminare dei rilievi reali, 6 novembre 2026

Base deploy de87b9fbaff5cdf6237bdabe16a950b5cc3660eb; Onboarding d5155899b09dda298494b68cefa7e1f281167652. Entrambe PR54 draft/open; CI deploy51/51SUCCESS,nessun run attivo al controllo. Nessuna raccolta ripetuta. [Readback operatore](../evidence/storage-g0-sealed-findings-operator-20261106.json) vincola localmente result/reconciliation/access/capacity/claim. È output utente,non osservazione diretta dell'agent o sigillo storico indipendente.

## Che cosa è acquisito

120corpi verificati,120riferimenti fisici controllati,120corpi classificati,353righe nelle proiezioni esportate. Il breakdown dei18rilievi non contiene MISSING_BODY,CONTENT_HASH_MISMATCH,CONTENT_SIZE_MISMATCH,UNCLASSIFIED_BODY o DANGLING_*. È un esito del riconciliatore sugli snapshot osservati: non prova common-cut,completezza di tutti i consumer o identità autorizzata.

| Rilievo | Conteggio | Disposizione preliminare e lavoro necessario |
|---|---:|---|
| ASSET_OWNER_UNRESOLVED | 10 | Il collector lo emette quando tenant_id non è valorizzato,senza valutare il predicato applicativo completo. V37 preserva NULL legacy; controllare relazioni e prove disponibili. Non attribuire tenant,non inventare ricevute,non richiedere automaticamente10riparazioni HUMAN |
| ADDITIONAL_REFERENCE_REQUIRES_CLASSIFICATION | 4 | Classificare sample_ref/output_ref effettivi. Il worker genera profile://managed-files/{asset}/jobs/{job}/redacted-sample; il service conserva redacted_sample in PostgreSQL. Verificare collegamento esatto asset/job/profile; un prefisso da solo non basta |
| QUARANTINE_REFERENCE_REQUIRES_CLASSIFICATION | 4 | Distinguere payload_ref da evidence_ref. Il pipeline usa un riferimento RAW quando disponibile e genera etichette contract-or-mapping:CODE o schema-surveillance:CODE. Verificare le righe effettive,run/attempt e catalogo; niente replay o riparazione |
| ACL_OWNER_OR_GRANTS_UNPROVEN | 2 | Il controllo non trova una risposta PRESENT con Owner.ID e Grants lista. Non implica bucket pubblico. Leggere forma/stati delle risposte già conservate,incluse policy/publicAccessBlock; protezione equivalente resta da dimostrare |

Capacità osservata:293049417728byte liberi (circa272,92GiB) su539792977920byte; source/destination/backup condividono il dispositivo. Lo staging locale non dimostra un backup indipendente; questo riscontro non dimostra né esclude altri backup già esistenti e non misura throughput/crescita.

## Contratti consultati, senza inferire codice installato

- Onboarding d5155899, [V37](https://github.com/GioNob/ouf-source-onboarding/blob/d5155899b09dda298494b68cefa7e1f281167652/src/main/resources/db/migration/V37__managed_file_intake_tenant.sql), [V38](https://github.com/GioNob/ouf-source-onboarding/blob/d5155899b09dda298494b68cefa7e1f281167652/src/main/resources/db/migration/V38__managed_file_legacy_owner_reconciliation.sql), [contratto tenant](https://github.com/GioNob/ouf-source-onboarding/blob/d5155899b09dda298494b68cefa7e1f281167652/docs/MANAGED_FILE_INTAKE_TENANT.md): NULL storici non backfilled; proprietà può usare ricevute tenant+subject e source-review; riconciliazione legacy esplicita resta separata.
- Onboarding retained73498c17596ae155a3ed9ab36acfd6bb69da9846, [ManagedFileService](https://github.com/GioNob/ouf-source-onboarding/blob/73498c17596ae155a3ed9ab36acfd6bb69da9846/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileService.java), [ManagedFileProfileWorker](https://github.com/GioNob/ouf-source-onboarding/blob/73498c17596ae155a3ed9ab36acfd6bb69da9846/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileProfileWorker.java): predicato owner legacy e campioni DB con riferimento logico. Consultato anche il worker d5155899,stesso formato.
- Ingestion4165b9e149be467d5d7c6bed35e4e1af4e249db1, [CanonicalRecordPipeline](https://github.com/GioNob/ouf-ingestion-runtime/blob/4165b9e149be467d5d7c6bed35e4e1af4e249db1/src/main/java/it/comune/trieste/ouf/ingestion/CanonicalRecordPipeline.java), [QuarantineService](https://github.com/GioNob/ouf-ingestion-runtime/blob/4165b9e149be467d5d7c6bed35e4e1af4e249db1/src/main/java/it/comune/trieste/ouf/ingestion/QuarantineService.java): semantica payload/evidence e legame al run. Il fallback RAW non persistito rimane possibile e non viene scambiato per oggetto S3 presente.

Le proiezioni G0 non includono subject/uploaded_by,source-review o redacted_sample. Anche una riga upload/owner-reconciliation con tenant/hash/size coerenti è soltanto un candidato a prova: non autentica identità né completa il predicato di proprietà. Conservare i NULL e i dinieghi applicabili; una migrazione non deve inventare una proprietà per rendere verde il collector.

## Prossimo riscontro locale unico

`scripts/classify-storage-g0-sealed-references-20261106.py` legge sei file già conservati: reconciliation fissato al digest5c0bc6d7,tre export vincolati ai digest/sourceSchemaCommit del rapporto,collection metadata vincolati al digest canonico e inventory-before al digest del collector. Non legge corpi o credenziali; nessun provider,write,SQL,replay o reset.

Il classificatore associa esattamente le impronte dei18rilievi ai record locali prima di emettere soli conteggi/etichette fisse. Controlla asset/job/profile per sample; run/attempt e tenant/source/tier RAW per payload di quarantena; diagnostiche secondo formati sorgente. Sconosciuti restano in review. Owner osservati tramite conteggi NULL/source/upload/receipt; nessuna assegnazione. Per ACCESS emette soltanto stati/booleane/conteggi,senza bucket,grantee o policy privata.

Sintassi e smoke sintetico riusciti:associazione18impronte,classificazione dei formati noti,redazione,tenant diverso/job errato lasciati irrisolti,impronta modificata rifiutata. Non è nuova qualifica nativa o accettazione. Restituzione VPS ancora pendente. Il rapporto originale rimane immutato e i18rilievi non vengono azzerati.

MiniPET invariato18,3/46=39,78%,0/8gate,0/21AT,0/120migrati. G0 resta aperto: disposizioni dei rilievi,accessi/custodia/finestra/writer(11percorsi),funzioni/capacità/obiettivi da riconciliare. Il lavoro resta il secondo passo della coppia raccolta+riconciliazione,non nuovi passi di download/documentazione. Nessuna stima numerica nuova prima delle disposizioni puntuali.

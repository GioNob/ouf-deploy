# SeaweedFS 4.52 — preservazione Content-Type S3

Patch candidata29: **6.156 test PASS,5 skip,21 pacchetti PASS**; nuova coorte OCI ancora da qualificare. Non è una release ammessa.

## Problema e correzione

Il cold lab del candidato OCI15 (run41691296882, commit24e96) ha conservato corpi e metadati hash ma si è fermato su `CONTENT_TYPE_MISMATCH`. L'esecuzione non registrava ancora chiave e header effettivo; non attribuiamo al log un valore che non contiene.

La sorgente esatta dimostra un difetto indipendente e riproducibile: il PUT S3 moderno chiama `putToFiler`, conserva il Content-Type in `FuseAttributes.Mime` e invia l'entry via gRPC. `FilerStoreWrapper.normalizeEntryMimeForStore` azzera poi `application/octet-stream` per qualsiasi file. GET/HEAD, non trovando MIME, possono inferirlo dall'estensione: un oggetto `.txt` può quindi restituire un tipo diverso da quello esplicitamente richiesto.

La patch esclude dalla normalizzazione le entry riconosciute dall'esistente `Entry.isS3Entry()`. Il predicato usa owner, ETag o attributi interni S3 e già distingue la semantica S3 per TTL; non introduce un marker né dipende dal percorso `/buckets`. La normalizzazione resta invariata per file nativi; le directory erano già escluse. I percorsi HTTP autoChunk del filer non vengono modificati: non partecipano al PUT S3 moderno.

Il valore MIME realmente assente resta assente nel filer. Il PUT S3 senza Content-Type conserva il rilevamento automatico sul contenuto: quando questo sceglie octet-stream, oppure il PUT applica lo stesso default per un body vuoto, anche quel valore viene ora conservato. Questa è una modifica intenzionale del precedente fallback GET/HEAD sull’estensione: un body binario o vuoto senza header e con chiave `.txt` restituisce il MIME scelto dal PUT, non text/plain inferito dal nome. Un Content-Type già perso da una precedente scrittura non può essere ricostruito con certezza e non viene riparato automaticamente.

## Qualifica

Base esatta: upstream984eac6a790be89e2a11de175a7413e1e3e32dd3 più27patch, poi patch28 `b8387b32bfcb1f8bb7f4cb30d781c5035a6a46b1a82c6a655e318cf794f2bf79`, poi questa patch29.

Le regressioni esercitano il wrapper reale con insert, insert-known-absent e update. I casi S3 attraversano i veri handler PUT/GET/HEAD, RPC locale, wrapper reale e serializzazione/deserializzazione protobuf, usando soltanto volumi e trasporto fixture locali. Controllano octet-stream esplicito su `.txt` e `.json`, oggetto vuoto, MIME personalizzato e MIME omesso/autodetect su testo, binario e body vuoto. Il test non sostituisce un roundtrip del binario OCI.

Le7 regressioni handler e12 regressioni wrapper passano. Rimuovendo soltanto la nuova condizione,11 sottocasi falliscono come atteso (5S3 e6wrapper), insieme ai2 test padre; i controlli nativi, MIME personalizzato e autodetect testuale continuano a passare. Riapplicazione esatta della patch sui3file: PASS, zero fuzz e parità byte.

La suite20 precedente estesa a `weed/filer` totalizza6.156PASS/5skip e21pacchetti PASS;6pacchetti senza test sono riportati come skip dal tool. Grafo produzione1.811 pacchetti SHA256`cb2536b10d73bc04e587c257a75a622c6b3cf855f1d232f26dba246b43b03f4a` identico28;262 moduli nel binario identici28, senza SDKv1/manager/elastic/rclone. Go.mod/sum restano identici28. La nuova enumerazione di tutti i moduli root non è disponibile offline per metadata cache incompleti: non viene dichiarata riuscita.

Patch SHA256`54982d752afc77e680cfa75b5ada1febc6680709bdb46f8d284f2090448849bc`. Binario nuovo SHA256`a0c74718e584942f58c02214f6b3abe46b71cd47d4995b8da3aa002dcdadeef7`, Go1.27.3/linux-amd64/CGO0/trimpath, revision upstream e vcs.modified=true. [Ricevuta e manifest delle prove](../evidence/seaweedfs-452-content-type-local-20261103.json).

## Nuova coorte obbligatoria

Questa patch cambia codice di produzione e quindi il binario standard. Il digest OCI15, le sue prove runtime e la sua qualifica non si trasferiscono al binario29. Servono nuovo build, SBOM, inventario licenze, producer/readback, lock e nuove prove runtime sul nuovo digest. Questo lotto non modifica alcun lock, workflow di build o target e non ammette release, deploy o merge.

MiniPET, autorità HUMAN/THS, scope17/52GET consumati, risultati Teatri/M1 e Farmacie restano invariati. Nessun gate/AT chiuso e nessuna migrazione di oggetti reali. Il difetto osservato sul vecchio candidato resta documentato anche se una prova separata con MIME personalizzato riesce.

## Consegna delle prove

Le prove pubblicabili sono isolate in `evidence/seaweedfs-452-content-type-local-20261103/`. Il log integrale della suite resta conservato nel workspace: la ricevuta ne registra hash SHA256, dimensione, conteggi e mancata inclusione nella proposta repository. `regression-terminal-events.jsonl` è dichiarato esplicitamente derivato e conserva tutti gli eventi PASS/SKIP/FAIL, con nomi test integri e dizionario dei pacchetti nella ricevuta; non è un campione. Gli altri file di prova sono copie byte-identiche degli originali. Patch, sorgente29 e binario non sono stati modificati dalla preparazione di questa consegna.

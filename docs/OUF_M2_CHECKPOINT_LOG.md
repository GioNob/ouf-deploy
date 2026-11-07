# Log dei checkpoint M2

Il log è append-only e in ordine cronologico. Aggiungere una voce datata in fondo. Se serve correggere una voce, aggiungere un riferimento a quella precedente. Per decidere la prossima azione, leggere [STATE.md](STATE.md).

Le voci fino al 2 novembre sono una sintesi dei checkpoint preesistenti. Il [documento originale integrale](https://github.com/GioNob/ouf-deploy/blob/b8d5b67c1c4d2e42b4eaed1a2c2678806e92624b/docs/OUF_M2_MINIPET_v1_0_20261026.md) conserva il testo esatto, i riferimenti e le istruzioni storiche.

## 26 ottobre 2026 — Baseline e audit

L’audit mappava 63 file, 24 criteri di accettazione e 8 criteri UX. M1 era acquisito per il caso Teatri. Il piano iniziale proponeva di riprendere il job Farmacie allora in errore e comporre i componenti esistenti. La stima da 34 a 58 ore era stata ritirata dopo l’inventario.

- [Audit](OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md)
- [Tabella di stato del 26 ottobre](https://github.com/GioNob/ouf-deploy/blob/b8d5b67c1c4d2e42b4eaed1a2c2678806e92624b/docs/OUF_M2_MINIPET_v1_0_20261026.md#2-baseline-fonti-e-stato-certo)
- [Primo tratto operativo originario](https://github.com/GioNob/ouf-deploy/blob/b8d5b67c1c4d2e42b4eaed1a2c2678806e92624b/docs/OUF_M2_MINIPET_v1_0_20261026.md#14-primo-tratto-operativo)

## 30 ottobre 2026 — Teatri e Farmacie

Teatri aveva completato M1/G4 a passi singoli. Farmacie conservava lo stesso profilo riuscito, con 61 righe e 10 colonne. Il codice ministeriale era stato confermato come stringa e le 10 colonne come OPEN. M2 restava aperto.

- [Handoff del 30 ottobre](handoffs/OUF_M2_SINGLE_MCP_NATIVE_20261030.md)

## 1 novembre 2026 — Custodia e provenienza delle immagini

1. Catturate 13 immagini, per 2.774.726.144 byte. La verifica privata dei byte era pronta. [Handoff](handoffs/OUF_M2_IMAGE_BYTE_VERIFICATION_20261101.md)
2. La prima verifica si è fermata. La correzione dei metadati opzionali è stata qualificata. [Riconciliazione OCI](handoffs/OUF_M2_IMAGE_BYTE_RECONCILIATION_20261101.md)
3. La seconda verifica si è fermata. È stata preparata la diagnosi della struttura delle immagini. [Diagnosi](handoffs/OUF_M2_IMAGE_GRAPH_DIAGNOSTIC_20261101.md)
4. Collegati 13 ruoli, 10 configurazioni pubbliche e 4 manifesti. Tre origini restavano da confrontare. Il dodicesimo scope era consumato. [Ricevuta](../evidence/m2-runtime-origin-join-target-20261101.json)
5. Collegata la provenienza di Semantic. La scansione osservò 3 HIGH, 56 MEDIUM e 38 LOW. Il gate restava sospeso. [Provenienza e scansione](handoffs/OUF_M2_RUNTIME_PROVENANCE_RECONCILIATION_20261101.md)
6. Il candidato Semantic corretto passò senza HIGH, CRITICAL o UNKNOWN. Restava da sostituire l’immagine installata. [Correzione](handoffs/OUF_M2_SEMANTIC_HIGH_REMEDIATION_20261101.md)
7. Verificato il nuovo candidato Gateway. La scansione dell’immagine MinIO recuperata rilevò 9 CRITICAL, 127 HIGH e 8 UNKNOWN. Serviva una scelta sullo storage. [Decisione storage](handoffs/OUF_M2_STORAGE_SECURITY_DECISION_20261101.md)

## 2 novembre 2026 — Filone MinIO → SeaweedFS

Aperto un MiniPET dedicato alla sostituzione S3. Il piano partiva con 8 gate e 21 criteri di accettazione aperti. M2 conservava il proprio criterio di completamento. [MiniPET SeaweedFS](OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md)

## 7 novembre 2026 — Ripartenza e blocco del selettore

1. Il VPS ha avviato lo stack originale su MinIO e SeaweedFS OCI33 sulla rete privata. Il rinnovo dei token host ha ripristinato cinque servizi e cinque timer.
2. MCP è uscito dopo la prima ripartenza. Il successivo avvio mirato ha restituito HTTP 204 su `/health/ready`.
3. La capability di upload ha restituito un handoff. Il browser ha ricevuto HTTP 403 `ONB_CAPABILITY_DENIED` per `ouf.managed-source.file.upload` prima della selezione del file. La policy `ouf-lab-authorization:59` mostra un grant diretto scaduto e un ruolo configurato con la capability per `ouf-admin`. Il permesso effettivo della sessione THS resta da accertare.

- [Procedura di avvio sul VPS](OUF_RUNTIME_RESTART_20261107.md)

## 7 novembre 2026 — Verifica della sessione THS

Il selettore ha restituito lo stesso 403 in InPrivate. Il redirect OIDC effettivo del client THS include lo scope `ouf.managed-source.file.upload`. La lettura della policy `ouf-lab-authorization:59` ha trovato un ruolo con questa capability per `ouf-admin` e nessun grant di upload per `giovanni-chatgpt`. Rimane da identificare il soggetto della sessione browser e verificare il permesso effettivo.

## 7 novembre 2026 — Account THS confermato

L’operatore ha confermato il nome utente `ouf-admin` nella finestra InPrivate. Il login THS richiede già lo scope di upload. Preparata una lettura della configurazione Keycloak sul client `ouf-authorization-ths` per l’utente esatto. Usa un login amministrativo locale e due GET. L’esecuzione sul VPS e il riscontro sui claim restano pendenti. [Comando sorgente](../scripts/read-ouf-ths-upload-scope.py)

## 7 novembre 2026 — Claim Keycloak attesi, decisione Onboarding da osservare

La lettura operatore ha restituito HTTP 200 e quattro riscontri positivi per il token di esempio del client THS. Scope di upload incluso, soggetto `ouf-admin` e tenant attesi, attore HUMAN. Il risultato riguarda la configurazione Keycloak valutata e lascia aperta la decisione presa sulla richiesta browser.

Sul ramo separato Onboarding è disponibile una modifica limitata al log dei rifiuti del selettore. Riporta codice di decisione, versione della policy e correlazione della richiesta. Il contratto HTTP 403 resta quello esistente. Modifica non distribuita sul VPS. [Commit Onboarding](https://github.com/GioNob/ouf-source-onboarding/commit/380e8dcb8f4ff259b3fea6814bb1f6981132f839)


## 7 novembre 2026 — presa in carico unica, difetto del grant upload riprodotto

Giovanni ferma il filone parallelo e affida il seguito al solo agente principale. La build diagnostica 42382365071 è failure a Trivy dopo 281 test applicativi passati; nessuna nuova immagine distribuita. Il ramo diagnostico parte da 194b5865, prima del sorgente conservato 73498c17: non consegnarlo come aggiornamento diretto.

Lettura live GRANTS/ROLES: policy ouf-lab-authorization:59. Il permesso admin di upload richiede dataAccessLabel e detailLevel; il selettore nel sorgente identificato fornisce un ResourceContext capability privo di attributi. Riproduzione locale con il valutatore originale: NO_APPLICABLE_GRANT prima, ALLOW dopo il delta mirato; 13 controlli PASS su fixture sintetica, non prova browser/VPS. Catalogo riletto identico prima della proposta: solo la voce upload cambia a resourceType=capability, allowedDataLabels=[], allowedDetailLevels=[]; altre 65 voci e 13 assegnazioni invariate. Proposta THS preparata PENDING, conferma umana necessaria, scadenza iniziale 15:26:20 UTC. Non è una pubblicazione di policy.

Prossimo passo: leggere esito della conferma e policy risultante, poi riprovare il selettore reale. Il 403 browser e il distinto 502 SeaweedFS restano aperti. [Evidenza](../evidence/ths-upload-role-diagnosis-20261107.json).


## 7 novembre 2026 — correzione upload pubblicata in policy :60

Giovanni riporta la pubblicazione nella THS. Readback MCP conferma proposta PUBLISHED, revisione 1 e finalPolicyRef ouf-lab-authorization:60; la lettura dei grant riporta la stessa versione. Il catalogo ruoli è esattamente quello proposto: sola voce upload admin modificata, 9 ruoli, 13 assegnazioni e altre 65 voci conservati. Nuovo source.file.upload emette handoff 1d3c1a27-5a57-4e81-bbbc-2f6bc606c6ce in AWAITING_FILE_SELECTION. Selettore browser e upload ancora da verificare; nessuna prova storage acquisita. [Ricevuta](../evidence/ths-upload-policy60-published-20261107.json).


## 7 novembre 2026 — selettore aperto, riuso handoff e prossimo passo storage

Dopo policy :60 Giovanni apre il selettore, riferisce primo caricamento Farmacie e secondo tentativo Teatri terminato HTTP_500. source.file.upload.status ritorna STAGED, asset 8061fad3-1a8b-4f65-9e4a-bfead7974cb7; il nome del file non è esposto. Non attribuire il primo asset a Teatri. Riprodotto sul sorgente 73498c17 il rifiuto di completare uno stesso handoff con un asset diverso, mantenendo la prima ricevuta. Il controllo nel picker è dopo la scrittura e il pulsante viene riabilitato: possibile secondo asset persistito, da riconciliare; manca l'eccezione live. Nessun nuovo upload richiesto e nessuna patch distribuita.

Il suggerimento di confrontare client esterno e Java è recepito con stesso contesto e input. Il 502 ONB_STAGING_WRITE_FAILED è generato dal catch dell'adapter MinIO Java: nessuna causa server o SDK dedotta dal solo HTTP status. Prova storica su localhost con CA importata e container rimossi; preparata lettura read-only dei binding attuali per la prova minima sul percorso scelto. Sintassi verificata, esecuzione VPS pendente. [Evidenza e limiti](../evidence/ths-upload-reuse-storage-next-20261107.json).


## 7 novembre 2026 — binding correnti riletti; confronto client pronto

Ricevuta operatore 15:29 UTC: Onboarding su MinIO HTTP, immagine 7b9d3e91…, rete ouf-backend; SeaweedFS d23a50eb… su rete privata distinta, nessuna porta pubblicata. Non è stata provata la connettività. Preparato confronto di curl e del client MinIO dell'adapter installato, in un solo container temporaneo con rete/identità/CA comuni. Una chiave nuova, contenuto sintetico 29 byte, due PUT/GET; nessun database o binding applicativo modificato. Firma SigV4 e corpi verificati su fixture HTTP locale, compilazione Java e sintassi Python PASS; classpath target/TLS/SeaweedFS ancora da verificare sul VPS. [Pacchetto](OUF_STORAGE_CLIENT_COMPARISON_20261107.md). F1/F2 restano aperti.


## 7 novembre 2026 — confronto curl/Java riuscito; file correnti da allineare

Il risultato VPS COMPARISON_COMPLETE conferma entrambi i client PASS sullo stesso endpoint/identità/payload/chiave: curl PUT/GET 200, Java 21.0.12.1 con MinIO 8.6.0 PUT acknowledged e GET con hash coincidente. Immagine Onboarding 7b9d3e91…, CA privata verificata, container temporaneo rimosso, originale ancora running con stessa immagine/avvio. Non è un test HTTP applicativo o DB; non attribuisce la vecchia causa del 502.

Scelta per F1: conservare l'immagine installata appena provata. Il prossimo comando allinea i file attuali Onboarding dopo gli upload recenti, riusando copie identiche e copiando soltanto chiavi mancanti senza sovrascrittura. Fixture HTTP locale PASS su copia/readback, riuso, diniego su differenze/tag nuovi/drift ETag; sintassi PASS. Esecuzione VPS ancora pendente. F1/F2 aperti; nessun binding applicativo cambiato. [Procedura](OUF_ONBOARDING_CURRENT_OBJECT_ALIGNMENT_20261107.md).


## 7 novembre 2026 — elenco corrente negato da MinIO; identità sorgente corretta

Ricevuta 16:05 UTC: LIST_CURRENT_SOURCE restituisce 403 AccessDenied con credenziali applicative Onboarding. Una sola richiesta MinIO; zero richieste SeaweedFS e PUT, nessuna modifica di dati, servizi o binding. Non è il 403 THS né un nuovo fallimento PUT SeaweedFS.

Corretto il comando per usare in sola lettura l'identità di manutenzione dalla configurazione MinIO esistente, mantenendo l'identità target già provata. Riutilizzata la risoluzione ambiente/file del repository, verificata sul sorgente MinIO di riferimento; nessun default o ampliamento di grant. Conservato il motivo S3_REQUEST_NOT_SUCCESSFUL correggendo il filtro dei codici. Sei casi locali di credenziali e fixture HTTP PASS, incluso 403 sorgente senza chiamate target e rifiuto locale di PUT/DELETE sorgente. Accesso effettivo VPS pendente. [Procedura](OUF_ONBOARDING_CURRENT_OBJECT_ALIGNMENT_20261107.md). F1/F2 aperti.


## 7 novembre 2026 — file correnti allineati; passaggio Onboarding pronto

Ricevuta operatore 16:15 UTC: CURRENT_ONBOARDING_OBJECTS_ALIGNED, 12 oggetti/40.709 byte, 10 già coincidenti e 2 copiati/riletti, manifest 9bcfd9b3…, snapshot invariato. Identità MinIO risolta da ambiente + file dichiarato; 16 richieste sorgente e 16 target. Zero fermate, modifiche DB, permessi o binding.

Preparato il cambio del solo Onboarding, stessa immagine, conservando rete backend/mount/risorse e aggiungendo CA, rete privata e binding SeaweedFS. Copia del delta e doppio controllo dello snapshot a writer fermo; ripristino originale soltanto prima dello start del sostituto. Avviatore aggiornato al nuovo riferimento persistito. Sei casi locali di sequenza PASS, merge reale keytool locale PASS con 125 certificati conservati, controlli sul binding dell'avviatore PASS. Nessuna esecuzione VPS del passaggio e nessun upload applicativo provato; F1/F2 aperti. [Procedura](OUF_ONBOARDING_SEAWEEDFS_SWITCH_20261107.md).


## 7 novembre 2026, 17:42 CET — Onboarding collegato a SeaweedFS

Ricevuta operatore ONBOARDING_SEAWEEDFS_READY: stesso JAR/immagine, nuovo container d4f22ff3…, endpoint HTTPS SeaweedFS, readiness UP e TLS dalla rete del container. Originale conservato spento; backend indirizzo/alias preservati. A writer fermo: 12 oggetti/40.709 byte già coincidenti, zero PUT, manifest 9bcfd9b3… invariato. JDK VPS: 118 certificati originali conservati, CA privata aggiunta. Nessun cambio di permessi o binding UDP. Non è ancora una prova di upload HTTP/registrazione asset.

MCP ha creato il nuovo handoff 2de7b988-da47-4231-8443-0e5043214c42, inizialmente AWAITING_FILE_SELECTION, per la prova applicativa dopo il cambio. Nessun nuovo file dichiarato caricato. Dopo la selezione: readback status, profilo dell'asset restituito e lettura governata; F1/F2 aperti. Il vecchio tentativo Teatri rimane separato e da riconciliare.


## 7 novembre 2026 — upload su nuovo binding registrato; correzione profilo proposta

Readback MCP del nuovo handoff `2de7b988-da47-4231-8443-0e5043214c42`: STAGED, asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94`; filename/hash non esposti. Richiesta profilo negata dall'autorizzazione, nessuna ricevuta job. Non ripetere l'upload. F1 scrittura/registrazione acquisita; lettura/profilo ancora aperta.

Riletta policy :60 e catalogo completo: 9 ruoli, 13 assegnazioni, 66 permessi; 138 grant in due pagine, 17 managed-source. Contesti profilo/creazione capability e lettura job managed-profile-job incompatibili con i vincoli di etichette admin; coperture temporanee scadute o vincolate a vecchi job. Il valutatore Java originale, con fixture redatta, riproduce il diniego e supera 16 controlli sulla correzione, compresi scope/tenant/soggetto/actor/DENY. Non è una traccia del codice decisione live né una prova del token.

Proposta THS `66ecf0fb-04e8-476b-9ce5-4fdc1dd496fa` PENDING, scadenza 18:15 CET: modificati solo tre permessi admin (profile, preview job, onboarding.create); altri 63 e tutte le assegnazioni identici. I controlli applicativi di proprietario/tenant restano presenti nel sorgente. Nessuna pubblicazione, modifica applicativa o migrazione UDP. Dopo conferma umana, rileggere policy e riprendere lo stesso asset. [Evidenza e limiti](../evidence/onboarding-seaweedfs-upload-profile-authorization-20261107.json).


## 7 novembre 2026 — policy :61 pubblicata, F1 riuscito

Giovanni conferma la pubblicazione; readback MCP: proposta 66ecf0fb-04e8-476b-9ce5-4fdc1dd496fa PUBLISHED rev.1, policy ouf-lab-authorization:61. Il catalogo coincide esattamente con la proposta: tre permessi admin corretti, altri 63 e 13 assegnazioni invariati.

Profilato lo stesso asset c51745c5-1fc0-4d36-bdcf-1e9a8a049c94, senza nuovo upload. Job f460d4d5-c6f7-4b65-b305-08091e9849cf QUEUED, poi SUCCEEDED; preview del profilo da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342 riuscita: CSV UTF-8, separatore punto e virgola, 13 righe/20 colonne. Il codice installato verifica dimensione e hash dei byte letti tramite Gateway prima di salvare il profilo. Hash e nome file non esposti dalla preview; nessun nuovo GET S3 indipendente. F1 PASS nel percorso Onboarding osservato; F2 e l'E2E ancora aperti. Coordinate STRING da interpretare prima del mapping; nessuna fonte/ingestion creata.

Preparata lettura UDP corrente con script fissato e controlli locali PASS (redazione segreti, allowlist, argomenti, sole letture); esecuzione VPS pendente. Nessun cambio UDP né nuova distribuzione. [Evidenza](../evidence/onboarding-seaweedfs-profile-success-20261107.json) · [Comando UDP](OUF_UDP_CURRENT_STORAGE_READ_20261107.md).


## 7 novembre 2026 — lettore UDP corretto dopo assunzione errata sul JAR

Ricevuta operatore READ_INCOMPLETE, KNOWN_UDP_JAR_LAUNCH_REQUIRED, zero modifiche di configurazione e nessuna credenziale emessa. Il lettore fissava /app/application.jar come per Onboarding; il Dockerfile UDP al commit 0d40da05 dichiara /app/app.jar. Non è un guasto UDP/SeaweedFS provato, né una misura del percorso live.

La correzione ricava il percorso dal -jar dell'avvio Java diretto, risolve i relativi contro WorkingDir e non esegue shell. L'ispezione facoltativa del JAR riporta INCOMPLETE senza perdere i binding Docker. Fixture locale della forma UDP e del JAR, percorso Onboarding/relativo, file mancante, wrapper e traversal: PASS, insieme alla redazione segreti. Nessuna nuova esecuzione VPS attestata. F1 resta PASS, F2 aperto. [Comando corretto](OUF_UDP_CURRENT_STORAGE_READ_20261107.md) · [Evidenza](../evidence/udp-storage-read-launch-fix-20261107.json).


## 7 novembre 2026, 18:27 CET — UDP identificato; prova client preparata

Ricevuta UDP_BINDINGS_READ_ONLY: immagine ae78f604…, JAR /app/app.jar, classi S3LakeConfiguration/S3LakeObjectStorageAdapter e SDK 2.54.17 identificati. Env dichiara http://ouf-minio:9000, bucket ouf-udp, path-style true e us-east-1; SPRING_APPLICATION_JSON presente, valori effettivi non ricostruiti. Rete ouf-backend interna, nessuna condivisa con SeaweedFS; target HTTPS privato con credenziali e CA già preparate. Zero richieste S3/DB o modifiche servizi.

Preparato un solo comando per leggere le proprietà storage del JSON e provare factory/adapter originali su SeaweedFS, in un container temporaneo della stessa immagine, senza Spring. Nuova chiave diagnostica; HEAD assenza, PUT+HEAD e GET completo con confronto corpo/hash/metadati, nessuna scrittura MinIO. Compilazione Java e fixture locali di JSON/redazione, successo, drift target, errore trasferimento e timeout cleanup PASS; test SDK/TLS reale non eseguito localmente. Rimane il solo piccolo oggetto diagnostico; rimozione container temporaneo e copia credenziali prevista anche su errore. Nessun cambio UDP o accettazione F2. [Procedura](OUF_UDP_SEAWEEDFS_CLIENT_PROBE_20261107.md) · [Preparazione](../evidence/udp-seaweedfs-client-probe-preparation-20261107.json).

## 7 novembre 2026 — Client UDP verificato, passaggio corrente preparato

Ricevuta operatore terminata alle 17:39:37 UTC / 18:39:37 CET: `UDP_INSTALLED_CLIENT_PUT_HEAD_GET_MATCH`. Factory e adapter originali nell'immagine conservata `ae78f604…`, SDK 2.54.17; PUT/HEAD/GET HTTPS, 33 byte, hash e metadati coincidenti. Nessun avvio Spring, nessun cambio al servizio. Il JSON dichiarato non contiene le proprietà storage selezionate. [Ricevuta](../evidence/udp-seaweedfs-client-success-operator-20261107.json).

Preparato il [passaggio UDP](OUF_UDP_SEAWEEDFS_SWITCH_20261107.md), sorgente `c5957208114803ade86630d0a8ff1d653c77b117`: allineamento del bucket attuale mentre UDP è fermo, stessa immagine, binding target e CA, vecchio container conservato spento. Solo il diagnostico di questa prova viene rimosso dopo hash; altri extra target conservati. Avviatore aggiornato per entrambi i marker. Prove locali di copia, sequenza/restore e ripartenza PASS; non sono prove del cambio sul VPS. Esecuzione operatore pendente, F1 PASS, F2–F6 aperti. Dopo il risultato serve la normale operazione applicativa UDP e il percorso CSV fino al grafo.

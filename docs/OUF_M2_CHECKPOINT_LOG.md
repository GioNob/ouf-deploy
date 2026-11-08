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

## 7 novembre 2026 — UDP passato a SeaweedFS, prosecuzione semantica bloccata

Ricevuta operatore terminata alle 17:59:28 UTC / 18:59:28 CET: `UDP_SEAWEEDFS_READY`. 110 oggetti/181.364 byte coincidenti mentre UDP è fermo, zero copie e sovrascritture, sorgente invariata; diagnostico rimosso, zero oggetti extra target. Stessa immagine, readiness/TLS e conservazione dei 118 certificati JDK più CA privata, vecchio container spento. [Ricevuta](../evidence/udp-seaweedfs-ready-operator-20261107.json).

Capacità successive: preview CSV leggibile; MCP HEALTHY; ricerca semantica `teatro` HTTP 502; lettura stato Ingestion authorization denied non ritentata. Il catalogo include semantic.search per admin ma non ingestion.status. Nessuna causa storage provata per questi errori e nessuna nuova grant proposal. Preparata [lettura mirata](OUF_SEMANTIC_UPSTREAM_READ_20261107.md) della rotta corrente con test locali PASS, esecuzione VPS pendente. F1 PASS, F2 ancora aperto per operazione lake applicativa, E2E fino al grafo non eseguito.

## 7 novembre 2026 — Semantica: DNS corretto, TCP non riuscito

Ricevuta VPS delle 18:10:35 UTC / 19:10:35 CET: container Semantic/APISIX/Gateway owner running, immagini conservate, nome upstream corretto e DNS riferito soltanto all'indirizzo corrente del registro. TCP dalla rete APISIX non riesce neppure verso l'indirizzo diretto. Indizio connectionRefused non correlato nei log APISIX; zero righe Semantic nella finestra di 30 minuti. [Ricevuta](../evidence/semantic-upstream-dns-pass-tcp-fail-operator-20261107.json).

La lettura precedente non esponeva processi e porta numerica. Estesa la [lettura v2](OUF_SEMANTIC_UPSTREAM_READ_20261107.md) con confronto avvio container/immagine, Java e listener/ownership IPv4/IPv6. Il Dockerfile del sorgente conservato eccef11a dichiara java -jar /app/application.jar e application.yml porta ${PORT:8080}; nessuna conclusione sulla configurazione effettiva corrente. Test locali PASS, esecuzione VPS pendente. Nessuna correzione di rotta, riavvio o grant effettuata.

## 7 novembre 2026 — Nessun Java nel registro; avviatore corretto

Ricevuta v2 delle 18:18:23 UTC / 19:18:23 CET: Semantic contiene soltanto sh/sleep, nessun Java, nessun listener 8080. [Ricevuta](../evidence/semantic-no-java-operator-20261107.json). Il comando di attesa nel sorgente richiede SIGUSR1 prima di exec Java. L'avviatore usato per la ripartenza controllava soltanto container running/health assente: difetto identificato.

Preparata correzione in `ouf-runtime-20261107.py`, modo semantic: verifica esatta del comando/processo/UID/privilegi e generazione, singolo segnale registrato, attesa Java nello stesso PID e readiness. In e2e Semantic passa dopo Gateway/APISIX/Caddy. Test locali, fixture shell nativa e regressioni Onboarding/UDP PASS. Nessun avvio VPS ancora eseguito; [comando](OUF_SEMANTIC_APPLICATION_START_20261107.md). Dopo il risultato occorre verificare semantic.search, non attribuire readiness a successo E2E.

## 7 novembre 2026 — Avvio Semantic fermato nel confronto; ambito corretto

Ricevuta `HELD/RETAINED_CONFIGURATION_CHANGED`, nessun ruolo avviato o raggiunto da `start_role`. Dal sorgente, nessun SIGUSR1 inviato. Ruolo/campi diversi non erano riportati; non sono stati dedotti dalla causa precedente. [Ricevuta](../evidence/semantic-start-retained-configuration-held-operator-20261107.json).

Il modo semantic riusava il controllo globale dello stack: separato il controllo dell'azione singola (configurazione Semantic esatta, dipendenze con immagini attese e running) dalla verifica completa e2e, che resta invariata. Aggiunte differenze per ruolo/campi senza segreti. Nessuna impronta aggiornata o normalizzazione arbitraria. Test di ambito, segnale e due marker storage PASS. [Comando aggiornato](OUF_SEMANTIC_APPLICATION_START_20261107.md), esecuzione VPS pendente.


## 7 novembre 2026 — Semantic avviato, ricerca ora negata dalla ricevuta/policy

Ricevuta operatore `OUF_SEMANTIC_APPLICATION_READY`: GATE_WAITING → APPLICATION_RUNNING, singolo segnale confermato, Java init nello stesso container/immagine, readiness 200/UP. Il confronto dello stesso Semantic passa; sulle sostituzioni Onboarding/UDP l'unico campo Config diverso è MacAddress. Il confronto completo e2e resta aperto, senza modifica delle impronte.

La successiva ricerca MCP `teatro`, limit 20, account ouf-admin, termina 403 `SEM_READ_RECEIPT_OR_POLICY_DENIED`; non ripetuta. Il codice installato accorpa verifica della ricevuta e decisione della policy, quindi causa non ancora distinta. Il grant admin è già presente nel catalogo letto. Preparato un controllo delle dichiarazioni selezionate e del token montato, con un solo GET HTTPS al canale policy. Nessun nuovo token, permesso o riavvio. Test locali PASS; esecuzione VPS pendente. Trasporto host e stato della policy in memoria sono distinti.

[Avvio](../evidence/semantic-application-ready-operator-20261107.json) · [403 e sorgenti](../evidence/semantic-ready-search-denial-20261107.json) · [Comando corrente](OUF_SEMANTIC_POLICY_READ_20261107.md).


## 7 novembre 2026 — recuperata la regola permanente MAC indicata dall'owner

Consultati integralmente `docs/OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md`, `docs/handoffs/OUF_ACQUISITION_MAC_LESSON_AND_RETAINED_STATE_20261025.md` e `tools/acquisition_read_native/retained_mac.py`. L'appunto esisteva: l'omissione è dell'assistente. Nei due AGENTS correnti non era richiamato; ripristinato il riferimento nella parte iniziale, senza nuovo checkpoint operativo da eseguire. La regola distingue Config legacy ed endpoint e vieta l'esclusione globale del campo.

L'attuale ricevuta indica il solo nome MacAddress sui sostituti Onboarding/UDP, mentre la primitiva storica riguarda il vecchio CID fermo e senza endpoint dopo STOP/DETACH. Dai sorgenti degli switch, gli snapshot dei sostituti sono salvati dopo avvio/readiness. Non sono ancora noti presenza/tipo prima-dopo e corrispondenza corrente degli endpoint: nessuna equivalenza dichiarata, guard non allentato, impronte non cambiate. Il comando già consegnato per il 403 Semantic rimane valido. Nessun effetto VPS di questo aggiornamento documentale.


## 7 novembre 2026 — token policy Semantic scaduto, rinnovo esistente preparato

Ricevuta operatore delle 18:52:14 UTC: token montato scaduto il 6 novembre alle 23:08:50 UTC, stessa sorgente host, GET configurato policy 401. Java rimane attivo; chiave di delega di forma valida, ricevuta non verificata e policy in memoria non letta. Il dato identifica un guasto da correggere, non prova che sia l'unica causa del 403 di ricerca.

Preparato rinnovo del solo produttore esistente `ouf-policy-token@semantic.service`, condizionato a sorgente SHA storica verificata, unità non mascherata, output esattamente coincidente col token montato e issuer/client/scope coerenti. Singolo tentativo manuale registrato prima del dispatch; token fresco e GET200 richiesti prima di abilitare il timer esistente. Nessun grant, nuovo servizio, riavvio Semantic, SQL diretto o S3. Test offline PASS; systemd/issuer/VPS non eseguiti. Comando pinned `591041c8c546c17cee56b129b1a5c908215cbfc0` nel [runbook](OUF_SEMANTIC_TOKEN_RENEWAL_20261107.md). Dopo esito positivo, ricerca MCP da riprovare. Riferimenti e regola MAC conservati, nessun guard di rete modificato.

## 7 novembre 2026 — Rinnovo fermato senza effetti; corretto il produttore selezionato

Ricevuta operatore 19:06:36 UTC: HELD `EXISTING_UNMASKED_SERVICE_REQUIRED`, coppia legacy Semantic masked/inactive, zero avvii/abilitazioni/GET policy. Correzione della voce precedente: quel produttore era sbagliato. Il metadata reader del 6 novembre documentava già il servizio continuo `ouf-registry-token-7cb59501000058b5dc5030ad.service` active/enabled, mentre il legacy era masked. La cattura ha fermato/disabilitato il servizio operativo; l'avviatore generale non lo ripristina. Nessuno smascheramento da effettuare.

Preparato `resume-current-semantic-operational-owner-20261107.py`, commit `1d0a93a9dbb3dd1a3f26a9fa92c71af841427084`: controlla review/configurazione/unità/output corrente, conserva registri e stati incerti, avvia il produttore esistente, verifica pubblicazione montata e GET policy, abilita il servizio al boot solo dopo successo. 13 scenari offline PASS; VPS pendente. [Istruzioni aggiornate](OUF_SEMANTIC_TOKEN_RENEWAL_20261107.md). F1 resta PASS, F2–F6 aperti; nessun nuovo test MCP/S3/SQL eseguito in questo turno.

## 7 novembre 2026 — Correzione metadati systemd e override di cattura

Ricevuta delle 19:18:38 UTC: HELD/SERVICE_METADATA_INCOMPLETE, servizio operativo corretto loaded/simple/root, inactive/disabled, Restart=no. Zero avvii, abilitazioni e GET policy. La v1 non esponeva i nomi mancanti. Il codice di cattura già usava array D-Bus tipizzati per gli hook vuoti e installava `zzzz-ouf-storage-offline-20261106.conf` con Restart=no: la ripartenza precedente non gestiva queste condizioni.

Commit `099f30a0d38af8170db5a5ddb67a055660bdaf1a`: v2 legge gli hook tipizzati e conserva l'esatto override prima di rimuoverlo dal solo servizio operativo fermo; daemon-reload, verifica impostazioni originali e conservazione altri drop-in, poi avvio e verifica token/policy. Registro incerto e file alterati bloccano prima della modifica; legacy resta masked. 19 scenari locali PASS con systemd/HTTP simulati e override su file temporanei reali. VPS pendente; nessun nuovo credito F2–F6 o test MCP. [Comando](OUF_SEMANTIC_TOKEN_RENEWAL_20261107.md).

## 7 novembre 2026, 20:43 CET — v2 fermata sulla lettura D-Bus

Ricevuta operatore: TYPED_SERVICE_METADATA_READ_FAILED, zero modifiche/avvii/GET policy. Ora verificati path/byte dell'override e i tre nomi omessi (ExecStartPre, ExecStartPost, ExecCondition). La fase D-Bus e il messaggio d'errore non sono conservati dalla v2; causa aperta. Nessun successo operativo deducibile dai 19 scenari simulati.

Preparata [lettura mirata](OUF_SEMANTIC_SYSTEMD_BUS_DIAGNOSTIC_20261107.md), commit `9745f249627469567f4a49d2cc7c3120b9bb4c90`: GetUnit e singole proprietà, exit code/stderr del comando, solo tipo/conteggio dei risultati riusciti. Nessun token, LoadUnit o mutazione. Verifica sintattica locale; VPS pendente. Ripristino v2 sospeso fino alla diagnosi; F1 PASS e F2–F6 invariati.

## 7 novembre 2026, 20:56 CET — GetUnit su unità non caricata; controllo dai file verificati

La diagnosi riporta GET_UNIT exit1, unità non caricata. Nessun effetto e nessuna lettura degli hook. La dipendenza v2 da un'unità già presente in memoria era inappropriata per il produttore inattivo; il preciso momento di scaricamento non è osservato.

Commit `c30f8c287bf4bb78cc07d73e18407eb019eec66e`: v3 controlla il main fragment vincolato all'hash e tutti i drop-in riportati da systemd, con NeedDaemonReload=no. Richiede assenza esplicita di hook nei file, ammette solo direttive previste rete/cattura nei drop-in, rifiuta sintassi non gestita. Nessun busctl, nessuna inferenza di vuoto da proprietà omessa. Conservati controlli su registro, override esatto, token/policy e abilitazione. 25 scenari locali PASS con systemd/HTTP simulati e file temporanei reali. VPS pendente. [Comando v3](OUF_SEMANTIC_TOKEN_RENEWAL_20261107.md). F1 PASS, F2–F6 aperti.

## 7 novembre 2026 — Ripristino produttore Semantic e letture MCP riuscite

Ricevuta operatore delle 21:07:05 CET: `SEMANTIC_OPERATIONAL_OWNER_ACTIVE_TOKEN_FRESH_POLICY_GET_OK`. Esatto override di cattura conservato/rimosso, altri drop-in invariati; un avvio del produttore continuo, ora active/running/enabled. Pubblicazioni 6468→6469; nuovo token montato, GET policy :61 HTTP200, Semantic invariato e legacy masked. Nessun cambiamento dei grant. Il secondo ciclo automatico non è ancora provato.

Le successive chiamate MCP come ouf-admin riescono: `teatro` e `Theatre` danno liste vuote; `Teatri` trova l'ontologia ACTIVE 1.0.0. La lettura della revisione `a1db3912-2b72-42eb-af88-a775fcd0e2ab` / publication set `9fe7d1ee-9e13-40bc-ad50-53e36ea0076b` restituisce 105 statement completi. Il precedente 403 non è osservato. Preview del profilo corrente riletta: 13 righe/20 colonne. Un primo input preview con solo assetId è stato respinto dalla validazione prima del dispatch; la lettura corretta usa assetId e profileId, come nel contratto.

Preparata la proposta di riuso del mapping Teatri per il nuovo asset: tutte le colonne RESTRICTED/IDENTITY, celle lessicali e chiave nome_teatro. Classe/20 proprietà presenti, 18 proprietà locali con range string; i due termini schema.org sono rdf:Property senza range/domain nello snapshot. Manca la scelta dell'owner sul nuovo asset. Nessun draft, approvazione, acquisizione o nuova pubblicazione semantica inviato; sorgente storica invariata. F2–F6 restano aperti.

[Ricevuta operatore](../evidence/semantic-operational-owner-active-operator-20261107.json) · [Risposte MCP](../evidence/semantic-recovery-functional-read-20261107.json) · [Mapping proposto](OUF_TEATRI_SEAWEEDFS_MAPPING_REVIEW_20261107.md).

## 7 novembre 2026 — OPEN acquisito; proprietà condivise per i nomi delle colonne

Giovanni accetta OPEN per le 20 colonne e affida l'analisi semantica all'agente. Chiarisce che interessa associare il nome/significato della colonna a una proprietà di vocabolario/ontologia condivisa per confronti tra oggetti diversi, non enumerare i valori. La richiesta iniziale di vocabolari di valori viene quindi superata.

MCP: ricerca Teatri riuscita; lettura esatta della stessa revisione/pubblicazione, 105 statement completi e risposta coincidente con la precedente conservata. Due termini schema.org presenti; 18 proprietà locali con dominio PerformingArtsTheater e range string. Predisposta analisi di tutte le 20 colonne; nessun IRI esterno inventato. Le ricerche nome(PROPERTY), indirizzo e coordinate restituiscono liste vuote, che non provano assenza dei termini contenuti negli snapshot. La ricerca Cinema viene rifiutata: orchestration budget exhausted, retryable:false; nessun retry/reset/cambio account.

Discovery request/status/candidates non esposte dalla connessione. Letti i candidati MCP PR81, Gateway PR84 e Registry PR41, aperti/non merged: sono riferimenti di sviluppo, non prova di installazione corrente. Nessuna web research/import manuale sostitutiva, pubblicazione o bozza applicativa. Il payload di lavoro è aggiornato OPEN e marcato incompleto per allineamento a proprietà condivise. Restano prova UDP applicativa e E2E.

[Tabella per colonna](OUF_TEATRI_COLUMN_SEMANTIC_REFERENCES_20261107.md) · [Evidenze](../evidence/teatri-column-semantic-reference-review-20261107.json).

## 7 novembre 2026 — Budget: diagnosi del limite e requisito proporzionale

Il sorgente MCP conservato d2454f3c applica una finestra di un minuto, capacità predefinita tre chiamate e ulteriori limiti byte/oggetti. L'errore live generico non consente di attribuire quella specifica saturazione a una dimensione. Preparata MCP PR82, head cdfb850b: profilo semantico separato da 60 chiamate/minuto e risposta temporanea con dimensione/scadenza/retry-after. Qualifica nativa 42413075158 e CI completa 42413075174 PASS, incluse prove PostgreSQL, build immagine, staticcheck e govulncheck. Formattazione iniziale corretta; nove sorgenti riletti coincidenti. Artefatto 13590830257 conservato, non distribuito.

Giovanni precisa che gli oggetti possono avere 50/100/200 colonne e il budget deve seguire la dimensione reale. Requisito acquisito: il valore fisso non è la soluzione finale e la PR resta draft. La preview ha già conteggio e descrittori, ma search/get non hanno riferimento al profilo. Distinguere budget totale dell'analisi, ritmo delle richieste e guard dei tentativi equivalenti. Due interventi: collegamento al profilo/dimensionamento/conservazione del consumo; poi avanzamento per colonna e attesa/ripresa attraverso finestre, con prove 20/50/100/200. Funzione quantitativa e implementazione dinamica non ancora qualificate.

Il lettore runtime MCP è conservato nel commit deploy 51125a9b; compilazione Python riuscita, nessuna esecuzione sul VPS e nessuna richiesta attuale all'operatore. Nessun cambio runtime, grant, SQL reset, storage, upload, profilo o Ingestion. Discovery esterna resta un problema distinto. [Decisione](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md) · [Evidenza](../evidence/semantic-analysis-budget-review-20261107.json).


## 7 novembre 2026 — Oggetti SUE fino a 1024 colonne: primo incremento

L'owner ha richiesto 1024 colonne e adeguamento dei limiti correlati, spiegando il caso di una pratica SUE da 300–400 campi. Il lavoro ha trovato e corretto anche i limiti a 32 proprietà/segnali, il body Gateway da 64 KiB e la memoria CSV. La prima prova 1024×10000 ha esaurito 384 MiB; la versione progressiva passa nello stesso heap, così come il caso 1024×2000 valori distinti e l'Ingestion completa 1024×10000. Native SDK/APISIX, draft PostgreSQL e decisione UDP hanno prove mirate. PR Onboarding55/MCP82/Gateway86/Ingestion48/UDP49; [evidenze](../evidence/wide-object-1024-20261107.json).

La CI immagine Onboarding inizialmente rifiutata per CVE-2026-109518 in APT è stata corretta tramite pacchetti ufficiali e base fissata, senza esenzione; scan e boot passano. Nessuna modifica VPS, policy o dati reali. Budget dinamico e avanzamento semantico durevole non ancora implementati; F2–F6 restano aperti. [Sequenza e rischi](OUF_WIDE_OBJECTS_1024_20261107.md).


## 7 novembre 2026 — analisi proporzionata al lavoro e composizione OntoPiA

Su richiesta dell'owner, proseguito il supporto a 1024 colonne con un piano di attività effettive e progressi persistenti. [MCP PR83](https://github.com/GioNob/ouf-mcp-server/pull/83), sorgente `907ace32100d44a0fcf1fcbda5d713ee7bd8fd94`, compone la discovery precedente e aggiunge `source.analysis.plan/read/step`. Profilo autorevole, ricerche condivise deduplicate, consumo/risposte per attività, copertura colonne, attesa delle finestre, controlli correnti di autorizzazione e fencing. Una chiamata terminata non dichiara corretta l'associazione semantica. Nessuno scheduler o nuovo potere HUMAN.

Qualifica [mirata Go/SDK/PostgreSQL](https://github.com/GioNob/ouf-mcp-server/actions/runs/42420569961) e [CI completa](https://github.com/GioNob/ouf-mcp-server/actions/runs/42420569963) riuscite; tutti i 23 workflow del commit verdi. Casi 20–1024 colonne, otto blocchi con una sola lettura di profilo, riconnessione, revoca, concorrenza, 61ª lettura in attesa, READ503, limiti retry/storage e discovery simulata. La CI completa ha rilevato e fatto correggere la convivenza fra la primitiva privilegiata 12→13 e la nuova migrazione ordinaria14; SQL storici invariati, privilegi temporanei non conservati.

I sei nuovi strumenti analisi/discovery restano INACTIVE. Una lettura live del catalogo CAPABILITIES ha restituito400: causa non attribuita e grant discovery correnti non verificati. Nessuna query al provider OntoPiA, nuova associazione alle colonne, upload/profilazione, bozza sorgente, Ingestion o modifica VPS/permessi. [Evidenza](../evidence/profile-analysis-discovery-20261107.json) e [prossimi passi](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md). F1 conservato, F2–F6 aperti.

## 7 novembre 2026 — sequenza di rilascio analisi/discovery e lettura target

Verificati i source-lock correnti prima del rollout: Registry `c2dae77b` discende di tre commit dall'applicazione discovery `4f8fb581` e preserva la correzione di custodia/rotazione credenziali; non installare il vecchio artefatto PR41. Gateway `81fdf7a5` e PR86 `560fbf6e` divergono (71/33): conservare l'owner operativo e riconciliare soltanto il delta necessario.

Preparato `scripts/read-analysis-discovery-runtime-20261107.py`, sorgente `7bdf0e107b534e9db90aabe5e0388c627b7150b8`, SHA256 `ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4`. Dieci prove locali e CI [42422417213](https://github.com/GioNob/ouf-deploy/actions/runs/42422417213) riuscite, log job 128553489638 letti. Fixture Docker inspect simulata, nessuna prova VPS/lifecycle native. [Unico comando corrente e interpretazione](OUF_ANALYSIS_DISCOVERY_ROLLOUT_20261107.md). Nessun effetto runtime, nuova discovery o mapping; F1 acquisito, F2–F6 aperti. Prossimo input: JSON dell'inventario target.

## 8 novembre 2026 — inventario acquisito, dipendenze discovery

Ricevuta delle 09:11:33 CET: sette immagini attese, nessun cambio durante la lettura, vecchi writer spenti. Onboarding/UDP conservano Config, HostConfig, mount e NetworkSettings dei sostituti; nessun delta MAC corrente. Altri cinque servizi: legacy ABSENT→STRING coerente con un endpoint; nessuna normalizzazione o modifica del guard. Registry trattiene il sorgente più recente ma ENV provider/worker=false; MCP ancora vecchio. [Ricevuta](../evidence/analysis-discovery-runtime-operator-20261108.json).

Preparato il lettore mirato `870b5e0cab438de2ed33936c97da28a6930da263`: un GET Admin route, metadata del mount credenziale provider senza contenuto, due sessioni SQL READ ONLY per migrazioni MCP/Semantic e conteggi discovery. Nessuna migrazione, grant, richiesta token/provider o stop/start. Dieci prove CI riuscite, zero skip, inclusa PostgreSQL17 isolata con ruoli fixture non amministrativi: [42463068093](https://github.com/GioNob/ouf-deploy/actions/runs/42463068093), log job128676349535 letti. Nove prove locali; quella PostgreSQL eseguita in CI. Route e mount-view fixture, nessuna prova VPS/provider. [Unico comando corrente](OUF_DISCOVERY_CONTRACT_READ_20261108.md). F1 conservato, F2–F6 aperti; atteso JSON del lettore mirato.

## 8 novembre 2026 — dipendenze acquisite, delta Gateway concreto

Ricevuta operatore delle 09:31:53 CET, READ_PARTIAL, runtime invariato: migrazioni MCP1–13 coincidono, resta soltanto14; tabelle analisi assenti. APISIX84 route, create256 campi/review32 segnali, tre route discovery assenti. Credenziale workload provider senza mount dichiarato, ENV provider/worker=false. Semantic DB non letto: causa e backlog ignoti. Zero modifiche e richieste token/provider/business/S3. [Sintesi normalizzata della ricevuta](../evidence/discovery-contract-operator-summary-20261108.json), non copia byte per byte del messaggio originale.

Il provider punta a un distinto gateway southbound; l'assenza dei path nell'APISIX letto non autorizza a considerarli assenti là. Non ripetere i lettori, non applicare di nuovo MCP12→13 e non accendere il worker senza riconciliare dipendenze/lavori pendenti.

Preparatore offline `5a8449b1a145a9607c5b9af537bd53d790c18aaf`: da route e stderr già conservati compone cinque aggiornamenti e tre aggiunte, conserva79 route e i binding IAM esistenti; nessuna sostituzione dell'owner Gateway, nessuna route provider creata. Script senza HTTP/Docker/SQL, applicazione non implementata, risultato target atteso. [Unico comando corrente](OUF_GATEWAY_ANALYSIS_DELTA_20261108.md).

[CI42464333835](https://github.com/GioNob/ouf-deploy/actions/runs/42464333835), job128680226233:9 PASS/0 skip, log letti, validatore JSON Schema reale1024/1025 e fixture di composizione/conservazione, non prova live APISIX. Gli altri due workflow PR dello stesso commit sono success. STATE, MiniPET2.10 e registro allineati. F1 conservato; F2–F6, installazione/attivazione budget dinamico, discovery e mapping restano aperti.

## 8 novembre 2026 — correzione della baseline del preparatore Gateway

[Ricevuta delle 09:53:25 CET](../evidence/gateway-analysis-preparation-held-operator-20261108.json): PREPARATION_INCOMPLETE/INSTALLED_MANAGED_SCHEMA_NOT_QUALIFIED_BASELINE; zero effetti runtime, query e richieste Admin/provider. Lo stderr già conservato indica MISSING_COLUMN; nome e migrazione non dimostrati.

Errore nel preparatore, non nuovo guasto SeaweedFS. Il suo schema preview includeva ASSETS non ancora installato. Review installata coincide con lo schema lessicale storico dopo la proiezione del solo identificatore annidato, già qualificata/documentata il 16 ottobre. Ricostruite tutte e quattro le impronte esatte da sorgenti, senza normalizzare lo schema target o allentare il confronto. Il candidato review conserva la stessa proiezione in assenza di riferimenti, mantenendo tutti i vincoli. Il controllo stretto è preservato.

Sorgente corretto `8a12592fdbf7b321a8b3c564081a1ab90b5b8c80`. [CI 42465156653](https://github.com/GioNob/ouf-deploy/actions/runs/42465156653), job128682843439: 13 PASS, zero skip, log letti; dodici locali, validatore JSON Schema in CI. La nuova regressione usa le impronte della ricevuta, indipendenti dal generatore. I nove test precedenti non coprivano questa divergenza e non provavano compatibilità target.

[Comando corrente aggiornato](OUF_GATEWAY_ANALYSIS_DELTA_20261108.md): stessi file privati, preparazione soltanto; può esporre dallo stderr esclusivamente i nomi della query pubblica già nota. Non riesegue SQL, non installa route, non riavvia servizi. Risultato della correzione atteso; F1 conservato, F2–F6 aperti.


## 8 novembre 2026 — proposta Gateway acquisita, applicazione qualificata

[Ricevuta operatore delle 17:32:01 CET](../evidence/gateway-analysis-prepared-operator-20261108.json): GATEWAY_DELTA_PREPARED_NOT_APPLIED, proposta `2876c0c3a892f0dce8accb08f5cbac523cfc541c43a264dfcb5944cd003c8f19`. Cinque aggiornamenti/tre aggiunte,79 route conservate; nessun effetto runtime. Stderr identifica recovery_state, introdotta nel sorgente Semantic V12; non dedotta la storia Flyway corrente.

Implementato l'applicatore `57647000a4d66ce4bc659ed54631e44ea8959978`: proposta/impronte esatte, confronto fresco dell'intera mappa, massimo8 PUT con intento durevole/ACK/rilettura, nessun retry/rollback automatico. Directory unica impedisce una ripetizione cieca. Nessun lifecycle container, owner sostituito, token/provider/S3/business. Una sessione SQL READ ONLY legge migrazioni, colonna effettiva e conteggi per stato senza identificativi o payload.

[CI42501682255](https://github.com/GioNob/ouf-deploy/actions/runs/42501682255), job128795585765:10 PASS/0 skip, log letti; APISIX reale con etcd e PostgreSQL17. Le prime prove native hanno trovato una fixture YAML errata e poi variazioni dell'ordine Mounts. Verificata uguaglianza dei record completi:28 variazioni d'ordine osservate nella prova riuscita. Il confronto ordina soltanto per Destination univoca, mantiene ogni campo mount e Config/MAC esatti, verifica prima gli hash originali della cattura. Gli errori e i limiti sono registrati nella [qualifica](../evidence/gateway-analysis-apply-qualification-20261108.json). Tutti e quattro i workflow PR del sorgente sono success.

[Unico comando corrente](OUF_GATEWAY_ANALYSIS_APPLY_20261108.md) pronto per l'operatore; applicazione sul VPS ancora attesa. Aggiornati STATE, MiniPET2.12 e registro. F1 conservato; F2–F6 e rollout completo1024/budget/discovery restano aperti.


## 8 novembre 2026 — Gateway applicato, Semantic V10 verificato e migrazione pronta

[Ricevuta operatore delle 17:56:09 CET](../evidence/gateway-analysis-applied-operator-20261108.json): otto PUT con ACK/rilettura, cinque aggiornamenti/tre aggiunte,87 route totali e79 conservate. Owner e container invariati; nessuna richiesta provider/token/S3/business. Semantic DB OID21558: V1–V10 riuscite, recovery_state assente, zero richieste discovery. Dieci checksum confrontati con il sorgente trattenuto: coincidono. Restano V11/V12; il comando Gateway è concluso e non va ripetuto.

Preparato il [comando Semantic](OUF_SEMANTIC_V11_V12_UPGRADE_20261108.md): immagine e librerie correnti, verifica dei file di migrazione nel JAR, configurazione ricostruita con configtree e binding/OID esatti, provider/worker disabilitati, due migrazioni Flyway raggruppate con limiti di lock/statement. Nessun repair, clean, inserimento manuale nella storia o riavvio; nessun dato di discovery prodotto. Un helper pubblico temporaneo in /tmp, rimosso al termine, con journal privato conservato. Esito incerto senza replay automatico.

Sorgente `33c54cf4b57a7577b9b9a8221e82d6c476976ffa`, consegna `03d2e7acf11ee3bc1f4b4a7ef164364896273831`. [CI42503772280](https://github.com/GioNob/ouf-deploy/actions/runs/42503772280), job128801887169:6 PASS/0 skip, log letti. UID10001 e ruolo DB non amministratore verificati; JRE/PropertiesLauncher/configtree/Flyway reali, storia e ricevuta sintetica preservate. Controlli negativi su checksum, descrizione Flyway, backlog, OID, package/configurazione e ripetizione. Prima prova fermata alla validazione pending; corretta soltanto la fase preliminare dopo verifica esatta delle due versioni. Fixture non amministrativa corretta usando un ruolo distinto dal bootstrap superuser. [Esiti e limiti](../evidence/semantic-v11-v12-upgrade-qualification-20261108.json).

STATE, MiniPET2.13 e registro allineati. Migrazione VPS ancora da eseguire; MCP14, rollout1024/budget, provider/grant/attivazione e mapping restano aperti. F1 conservato, F2–F6 non dichiarati conclusi.


## 8 novembre 2026 — package Semantic diverso, migrazione non partita

[Ricevuta delle 18:16:23 CET](../evidence/semantic-v11-v12-held-operator-20261108.json): HELD/INSTALLED_MIGRATIONS_DIFFER_FROM_SOURCE. Zero sessioni DB, esecuzioni Java, migrazioni, helper nel container o stop. Tentativo conservato in /var/lib/ouf-storage-migration/semantic-v11-v12-20261108; nessun replay.

Errore della ricostruzione dell'assistente: il source-lock del candidato, che dichiara allRuntimeArtifactMembershipProven=false, non prova il sorgente del JAR corrente. La corrispondenza imageId con la cattura trattenuta non colma questa lacuna. Ritirata l'affermazione “Registry già versione più recente”. I sei test nativi del migratore restano prove sul JAR ricostruito, non del package VPS. Non è ancora noto se la differenza riguardi file mancanti, aggiuntivi o byte cambiati.

Preparato il [lettore mirato](OUF_SEMANTIC_INSTALLED_PACKAGE_READ_20261108.md), sorgente `f636440dac4df2469e97d919c44fd64693b1fcea`: due GET Docker, JAR del processo corrente, hash e metadati selezionati, nessun exec/Java/SQL o effetto applicativo. Confronto preciso delle migrazioni e presenza/hash delle classi discovery; label/presenza non dichiarate prove di comportamento o provenienza. Tentativo precedente invariato, nuovo resoconto separato.

[CI42504819787](https://github.com/GioNob/ouf-deploy/actions/runs/42504819787), job128805066674:6 test riusciti/zero skip, log letti; sei locali. Fixture archivi e redazione, non JAR target. [Qualifica](../evidence/semantic-installed-package-read-qualification-20261108.json). STATE, MiniPET2.14, registro e runbook corretti. Risultato target della lettura atteso; prima riconciliare applicazione/schema, poi scegliere l'intervento. Gateway e F1 conservati.


## 8 novembre2026 — package corrente identificato; sostituzione coerente qualificata

Ricevuta operatore18:29 CET: JAR e runtime invariati, sole V1–V10 identiche al prefisso candidato, V11/V12 e tre classi discovery assenti; label eccef11a. Il vecchio tentativo rimane solo pre-dispatch. Salvato un estratto esplicito della ricevuta, non presentato come copia integrale.

Scaricato l'artefatto originale13066396654: ZIP203.419.418byte/hash coincidente, otto payload,221 blob Git del sorgente c2dae77b, dodici SQL/YAML e JAR nel layer verificati. Il sorgente dichiarato dal vecchio container ha YAML coincidente, senza dedurre l'identità dell'intero pacchetto. Serve applicazione+schema, non SQL aggiunto al vecchio JAR.

Controller c52804a, CI42506812587: job128811107718 containerd e128811107823 classic PASS; ciascuno2 cicli nativi e6 negativi MAC, zero skip, log letti. Artefatto originale, UID10001/configtree, DB owner nonadmin, V10→V12, history e ricevuta preservate, avvio Java e readiness. Conservati fallimenti CI su identificativo OCI e default Engine OOM/alias; correzioni puntuali, nessuna omissione globale di MAC. Fixture precedente in attesa, IAM/provider sintetici, nessun risultato VPS/E2E dedotto.

Consegna b2ef4a4d343716b40ae35a409c6a910a63f88721 con downloader pinned e alternativa ZIP locale. Disponibilità gh/accesso/ZIP sul VPS non osservata. Stato e MiniPET2.15 ripuliti: prossimo passo sostituzione Registry qualificata, poi MCP14/1024, provider/delega/grant e mapping Teatri→Ingestion→UDP. Nessun nuovo consenso generico, nessun merge, replay Gateway/vecchio migratore o modifica target effettuata dall'agente.

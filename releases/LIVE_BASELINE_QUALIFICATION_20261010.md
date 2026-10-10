# Qualifica sulla baseline live e verifica del canale — 10 ottobre 2026

## Risultato e limiti

Questa attività preserva il giro Cinema già consegnato e prepara candidati compatibili con i sorgenti avanzati del VPS. Non esegue deploy, replay, nuova ingestion, reset di claim o riavvio R9. I candidati restano su `codex/live-baseline-qualification-20261010`; non usare i vecchi main come sostituti della baseline installata.

### UDP

Baseline conservata: `83249a897eb4add4289b5181b3299f48ea4c0f99`, Flyway V34. Candidato qualificato: `bc336208ce41876f2854c3a4d8623fb6698bdcdd`.

Tutti i cinque workflow sono PASS sul candidato:
- [Module CI](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/38068463646): 208 test, zero failure/error, due skip preesistenti; PostgreSQL 17, performance, supply chain, disaster recovery.
- [Source continuity](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/38068463744): tutte le 34 migrazioni SQL conservate byte per byte come blob Git; file obbligatori presenti; sette test del verificatore.
- Materialization recovery 38068463572, Shared SDK 38068463688, CRS/grid 38068463612: PASS.

Sedici nuovi test eseguiti: sette nel resolver legacy, sette nella governance HUMAN, due sul motore governato. Il motore GovernedIdentityEngine e le sue regole di coverage, overflow REVIEW e sufficienza non sono rimpiazzati dal matching pesato legacy. Nature canoniche e tenant diversi non condividono candidati; binding incoerenti portano a REVIEW senza mutare il binding né esporre candidati estranei. La revisione legacy richiede scope conservato nella decisione immutabile. Il resume HUMAN esistente è preservato e rivalida lo scope. Merge HUMAN è limitato allo stesso tenant e alla stessa natura. SPLIT e certificazione generale dei replay rimangono gate separati.

Runtime Java 21 / Boot 4.0.8 / Tomcat 11.0.26 / Jackson 2.21.7, starter IAM conservato. Scansione fresca HIGH/CRITICAL, incluse vulnerabilità senza fix: nessun finding nell'artefatto 11675483037. Image ID CI `sha256:32fa42e3f906b8c8092a94e6a0a77fc5c5100e8f29583027478146ed5f97cfd3`. Non è un archivio firmato, importato o autorizzato sul target.

### Ingestion

Baseline avanzata: `163c167d09b8371ff7a62ce7068e9d485b6969b7`. Tutte le 14 migrazioni SQL e il consumer delle configurazioni frozen sono conservati; IAM non viene perso nel passaggio di runtime. Candidato in verifica: `8b908554314617298242eb2ae8312f734f55e817`.

La prima immagine distroless ha fallito il gate completo: nove HIGH nelle librerie libexpat/libuuid, prima escluse da ignore-unfixed. Il fallimento e l'artefatto 11675802424 restano evidenza, senza eccezioni o soppressioni. Il candidato Temurin Alpine e85d941d8da87f7a9f2af41f9ddaa4c62b1d3844 supera supply-chain, restore, tutti i workflow R2 e frozen consumer. Il test nel vero container ha intercettato un tmpfs noexec che impediva SQLite nativo: il commit 8b90855 rende esplicitamente exec il solo tmpfs effimero /tmp della prova, mantenendo root filesystem read-only, utente non-root, rete disabilitata, cap-drop ALL e no-new-privileges. Attendere il risultato dell'intero candidato; non estendere il PASS a SQLite/XLSX finché la prova non passa.

I tag base Docker devono essere fissati ai digest effettivi nella release: queste prove non dichiarano riproducibilità byte per byte di build future.

## Osservazioni reali via Gateway/MCP

Letture senza modifiche su entrambi i collegamenti OUF disponibili in questa sessione:
- system.status: MCP HEALTHY, actionRequired=false, partial=false, redacted=true. Prova limitata al modulo MCP, non salute dell'intero sistema.
- urban.object.search, tipo esatto `https://schema.org/MovieTheater`, pageSize=3: items=[], nextCursor=null, partial=false su entrambi i profili.
- semantic.search, MovieTheater CLASS, limite 5: [] sul profilo giovanni-chatgpt.
- ingestion.status sulla source Cinema: authorization denied sul profilo ouf-admin.

Una risposta vuota autorizzata non dimostra assenza degli otto oggetti storicamente materializzati; non certifica visibilità, namespace o tenant corretto. Non costituisce R-SMOKE PASS. Il deny viene conservato e non aggirato con escalation di account, SQL o grant automatici.

## Prossimi gate concreti

1. Chiudere la qualifica Ingestion con SQLite nativo e round-trip XLSX nell'immagine reale.
2. Riconciliare le baseline avanzate qualificate con i main preservando la documentazione aggiunta, senza deploy automatico.
3. Completare discovery Semantic/custodia OCI e readiness di migrazione per il candidato aggiornato; le vecchie attestazioni immagine e trust non si trasferiscono.
4. Verificare Search sul tenant/natura autorizzati: almeno tre oggetti, proprietà minimizzate, due pagine, cursor invalido, partial, label e audit. Non riacquisire Cinema per ottenere una fixture.
5. Teatri: riutilizzare asset/profile; mapping e identità canonica richiedono revisione HUMAN prima di ACTIVE.
6. Secondo file sovrapposto e relazioni pendenti/inverse governate; poi R-INSTALL ripetibile su host pulito. Solo dopo consolidamento file, verticali API PULL v2.3.

Questo documento non concede autorità di cutover, non prova salute applicativa continua e non è release acceptance.

## Chiusura della qualifica e riconciliazione

Ingestion 8b908554314617298242eb2ae8312f734f55e817: tutti gli otto workflow PASS; 118 test senza failure/error/skip; SQLite nativo e round-trip XLSX PASS nel container reale. Scansione fresca artefatto 11676426820: zero HIGH/CRITICAL, incluse vulnerabilità senza fix; image ID CI sha256:d6fd13e5d375d823dc6e54065bfd7688765b9c69049ea16ee0acb558abf27d1a. Il blocco temporaneo riportato sopra è chiuso da questa evidenza.

I main ora riconciliano entrambe le linee Git tramite commit a due genitori, preservano i documenti/evidenze storici e includono il gate di continuità automatico: UDP 48a86459fdeed38403838c5a2076b40cb082fe58; Ingestion 6d6777e20e0368c830d1e01de0494d9fa0197dbf. Nessuna migrazione SQL storica è cambiata. Nessun deploy o nuova ingestion è stato eseguito. Le qualifiche descritte sono ai commit candidati immutabili; i check automatici sui commit di riconciliazione devono essere letti separatamente.

## Rettifica basata sulla natura pubblicata e nuove letture positive

I risultati vuoti sopra riportati riguardavano la classe esterna di allineamento schema.org/MovieTheater. La natura esatta pubblicata e congelata per questa fixture è https://api.ouf-lab.it/semantic/cinema#Cinema: lo snapshot RDF afferma subClassOf MovieTheater, non equivalenza automatica di tipo per la ricerca o per l'identità. Questo chiarisce la causa della prima ricerca vuota senza modificare grant, mapping o dati.

La ricerca corrente tramite Gateway/MCP ouf-admin della natura esatta restituisce otto oggetti ACTIVE distinti, tre pagine da 3/3/2, nextCursor finale null e partial=false in tutte le pagine. Solo le due proprietà nome/indirizzo vengono restituite. È una prova positiva di visibilità e paginazione, non una prova negativa su proprietà vietate né una nuova attestazione della lineage della source. semantic.get sui pin storici restituisce l'ontologia ACTIVE, pubblicazione f92a2e17-30c9-456f-bb12-63afa84f41e6 e snapshot RDF di 17 statement con hash 4340986102db6e47345dd8157734d9db83b928edd94485f1b9a5b9e81c497a2e. semantic.search di tipo ONTOLOGY restituisce la stessa pubblicazione; CLASS vuoto non dimostra indisponibilità dell'ontologia importata.

La lettura paginata dei grant configurati nella policy ouf-lab-authorization:38 conferma Search/Semantic nel tenant ouf-lab, incluse label, ma il server dichiara CONFIGURED_GRANTS_NOT_EFFECTIVE_PERMISSIONS. Nessuna modifica IAM. Il tentativo di cursore invalido termina ORCHESTRATION_BUDGET_EXHAUSTED/retryable=false: il rifiuto owner del cursore non è provato e non viene ritentato per aggirare il limite. operations.summary restituisce 400; ingestion.status era negato. Restano aperti audit, partial/budget, controlli negativi, storage indipendente, secondo file e R-INSTALL.

Tutti i workflow sui main riconciliati UDP 48a86459fdeed38403838c5a2076b40cb082fe58 e Ingestion 6d6777e20e0368c830d1e01de0494d9fa0197dbf risultano ora PASS. La pipeline separata di packaging unsigned 38069730894 è in corso: fissa i digest delle basi Docker, scansiona l'immagine realmente costruita e congela sorgenti, JAR, immagine Docker-save e checksum. Non firma né importa sul target e non conferisce autorità di applicazione.

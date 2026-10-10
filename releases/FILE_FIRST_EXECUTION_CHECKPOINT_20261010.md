# Giro dei file prima delle API dei verticali

Decisione dell'owner del 10 ottobre 2026, dopo il documento narrativo: completare e consolidare onboarding di file, arricchimento semantico, ingestion, UDP e ricerca; affrontare poi i verticali tramite pull sulle API definite nel documento di indirizzo v2.3. Nessun workflow verde isolato sostituisce la prova completa sulla combinazione corrente.

## Correzioni concrete e perimetro

Le precedenti CI Ingestion fallivano per interferenza fra run dei test; i test vengono isolati e il polling automatico viene ritardato soltanto nel contesto della fixture. I controlli di stato, ACK e recupero rimangono invariati. La fixture MinIO non dipende più dal pull di un'immagine non disponibile: il medesimo rilascio del binario viene verificato con SHA-256 e confezionato localmente; acceptance e restore usano la stessa immagine verificata.

La scansione corrente ha inoltre rilevato dipendenze vulnerabili. È qualificata una linea runtime supportata liberamente, senza eccezioni al gate HIGH/CRITICAL: Spring Boot 4.0.8 / Framework 7.0.9, Jackson 2.21.7 in compatibilità transitoria e Tomcat 11 aggiornato per UDP. Questa è un'evoluzione tecnica esplicita rispetto a Spring Boot 3.x citato nella baseline PET; non una dichiarazione che la baseline originale prescriva Boot 4. È scelta nel mandato tecnico dell'owner per preservare sicurezza, uso di componenti OSS e sostenibilità, evitando un requisito di supporto proprietario. Restano Java 21, contratti intermodulo, SQL e migrazioni, ownership, SDK di autorizzazione e limiti IAM. Prima dell'integrazione si richiedono le stesse prove funzionali, di recupero, serving e sicurezza. La baseline tecnologica di rilascio deve riportare questa evoluzione; il candidato Semantic firmato già preparato sul VPS non viene sostituito automaticamente.

Per l'identità UDP il ramo SourceObjectBinding e i replay vengono sottoposti agli stessi vincoli di tenant, natura canonica e stato ACTIVE. Una riclassificazione non cambia automaticamente il binding: genera una issue governata. Gli attributi vuoti non costituiscono chiave d'identità. Le prove distinguono cinema e indirizzo anche con attributi identici. Nessuna equivalenza fra classi viene dedotta liberamente. Questi controlli non certificano da soli tutte le strategie, merge/split HUMAN o scoring ponderato.

Il nuovo compilatore di dichiarazione runtime conserva integralmente Config, HostConfig, mount e reti del container osservato e dichiara come delta host soltanto l'aggiunta dei tre bind read-only già contrattualizzati. Rifiuta collisioni, shadowing, drift del contratto, scrittura sui mount, cambio UID e scope host impropri. Scrive un nuovo snapshot privato, non monta file, non importa immagini, non chiama Docker e non tocca R9. Le osservazioni restano storiche. La dichiarazione non è un OCI realizzato, un peer reciproco, una firma o un'autorizzazione di cutover.

## Sequenza di completamento

| Ordine | Risultato richiesto per avanzare |
| --- | --- |
| 1. Baseline riproducibile | CI corrente di Ingestion e UDP, inclusi recupero e sicurezza, qualificata per SHA; nessun uso delle vecchie prove verdi per coprire errori nuovi. |
| 2. Applicatore e configurazione | Dichiarazione completa, closure firmata del trasporto/profilo, coordinazione senza replay R9, fencing/backup fresco, recupero compatibile con le migrazioni e readiness host. |
| 3. Semantica applicativa | Discovery reale tramite provider autorizzato, adozione/pubblicazione governata, mapping/bundle attivo e descrittori abilitati solo dopo readiness. |
| 4. Un file completo | Source governata, classificazione, arricchimento con provenance, durable ACK, oggetti/revisioni UDP e ricerca autorizzata con verifiche negative. |
| 5. Più file e relazioni | Stessa natura prima delle evidenze di matching; authority per proprietà; target tardivo, ambiguità, riconciliazione con profilo originario e ricerca inbound/outbound. |
| 6. Consolidamento e installazione | Replay e recovery, diagnostica, configurazione dichiarativa, installazione verificata su host pulito senza adattamenti manuali del VPS. |
| 7. API dei verticali | Solo dopo il consolidamento dei file: catalogo/schema/codelist, snapshot paginato e delta/checkpoint/retention; profilo di estrazione approvato, pull nativo read-only e proiezione tecnica prima del trasferimento. |

Il verticale espone sourceObjectId e typeCode nativi; non conosce UrbanObjectId, ontologie o capability OUF. Gateway proietta, Ingestion normalizza, UDP risolve. La risposta HTTP della sorgente non equivale al durable ACK UDP. Si mantiene il confine fra identità e relazione: stesso indirizzo non implica stesso cinema; relazioni, domain/range e eventuale inversa derivano dalla semantica approvata. La navigazione inbound non inventa una nuova proprietà ontologica.

La ricevuta target più recente resta APPLICATION_INPUT_CONTRACT_PREPARED_NOT_APPLY_READY. Nessuna nuova salute live è inferita; i claim consumati e le istanze Cinema/Teatri sono conservati. I 23 gap PET non sono chiusi collettivamente da queste correzioni.

Riferimenti: roadmap F0–F11 in ouf-semantic-registry; PET UDP v1.3 §11, Object Resolution, relationship resolution e deployment/recovery; PET Ingestion v1.3; Blueprint v0.3 e Matrix v1.7; Linee di indirizzo API verticali v2.3. Fonti upstream: https://spring.io/security/cve-2026-47884/ ; https://spring.io/security/cve-2026-47890/ ; https://github.com/spring-projects/spring-boot/releases/tag/v4.0.8 ; https://github.com/FasterXML/jackson/wiki/Jackson-Release-2.21.7 ; https://tomcat.apache.org/security-11.html .

## Security refresh qualification — 2026-10-10

The retained Semantic candidate source `403531a9df1cbc877078f8126fd1fc4ff18acea9` remains a separate historical signed artifact. Branch `codex/discovery-security-refresh-20261010`, qualified source `622614b0040cf11be2f6c7e3568733a488ca4ca8`, updates Tomcat to 11.0.26 and adds a fresh image scan with HIGH, CRITICAL and UNKNOWN failures, including unfixed findings, without exceptions. No Java, SQL, API contracts or retained Dockerfile bytes changed.

Module run [38065957754](https://github.com/GioNob/ouf-semantic-registry/actions/runs/38065957754) passed functional PostgreSQL tests (90 tests, zero failures/errors, two existing skips), recovery scripts, non-root container smoke and image scanning. Authorization, SDK and Discovery Gateway pairwise runs 38065957664, 38065957691 and 38065957683 also passed. Artifact `semantic-current-image-scan-38065957754` (ID 11674238309) reports no vulnerabilities at the selected severities; scanned CI image ID is `sha256:a19ee71a3f976087f3f4f3b0ea3609a28bcf12a41464519fcbf6b8bc00ea5aa8`. This is a bounded scan result, not a universal absence-of-vulnerabilities claim.

First run 38065793902 failed because the historical checksum register did not describe the already retained Dockerfile. The follow-up corrects that metadata to the unchanged recipe hash `da4d4fb4b5b677dea4e3d15427412cf87ddb80e84b9c42e2346d416adea5216b`; failed evidence is retained.

The refresh is source/CI qualification only. It does not inherit the old signed archive, target image, Java trust preparation, installation authority or transport closure. A fresh reproducible package and complete attestation/extended inventory remain required before target staging or cutover. The runtime declaration launcher still composes only the historical candidate bindings; it does not deploy this refresh.

Ingestion and UDP main documentation heads 98a845b453362ec35a55fbebf9156204cc804e10 and c786dbae32ce77a6c4a858e3f85181e45020c480 have now also passed every triggered workflow. Full target file-to-search acceptance, industrialized clean-host installation and the vertical API phase remain open.

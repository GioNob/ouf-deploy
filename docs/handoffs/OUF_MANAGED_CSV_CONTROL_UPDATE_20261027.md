# Nuovo aggiornamento Onboarding/MCP — QUALIFICATO, prima review/esecuzione target da ricevere

27 ottobre 2026, Europe/Rome. Questo è un nuovo intento di manutenzione per installare i due fix di controllo persistenti. Non è una nuova esecuzione della V35→V36 già riuscita. L'APPLY V36, cattura/riconciliazione, publisher e preparazione immagini/piano sono consumati e non devono essere riconsegnati o rilanciati.

## Stato acquisito

La ricevuta target `MANAGED_CSV_CONTROL_IMAGES_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED` è completa, Exit0/DeliveryExit0. [Prova](../../evidence/managed-csv-control-image-plan-target-20261027.json). Tre metadata/580635 byte, due ZIP originali, due archivi nativi; zero Engine/import/SQL/OAuth/credenziali/chiavi/authority/effetti di dominio. I contatori della cattura restano separati e conservati: 8 metadata/1153763 byte/27 GET Engine.

- Input conservati: `14a96f782827c8948fabd857d9e3958cbe588a38dc9bd0968c342467f09ca9c1`.
- Input di esecuzione: `900b09c6d29a20fda5dfff1f1333df167363c96e865cc2c13a7b58791f4e0c51`.
- Piano condizionale: `73d5733b86f2f8c8430a6a978540607557a8cd925911321ab58ae7b011bc1f7e`.
- Scope preparazione CONSUMATO: `/etc/ouf/deploy-snapshots/managed-csv-control-image-plan-14a96f782827c894-v1`.
- Scope NUOVO controller: `/etc/ouf/deploy-snapshots/managed-csv-control-update-900b09c6d29a20fd-v1`; non ancora eseguito sul target.

Ultimi owner provati installati: Onboarding `6ea5242f711761a384fa1b23667971601bc2c38b` / native `sha256:e4690481db28e3e70335704de89e563dcf32ecf70e4a0caea1bdc30c48aa4359`; MCP `9a374dd07745f059de3ad39757c68f02db6d29c3` / native `sha256:9a1af5be94ff3dda4084b829e824482c5cf863525375c6f104a3fe89517e781e`. Non attribuire il nuovo codice al runtime prima della ricevuta del nuovo controller.

Candidati da installare: Onboarding [PR53](https://github.com/GioNob/ouf-source-onboarding/pull/53) `9890b31868641e5be43c949a56f4ef69dd23bdfd` / native `sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3`; MCP [PR80](https://github.com/GioNob/ouf-mcp-server/pull/80) `d2454f3cb8cd410d284b9dc78349a170187aea1c` / native `sha256:a52180123104ac97e4979ad1b9b291654b076692da51708bb2a377301fef1220`. Custodia dei due archivi già qualificata; nessun rebuild o relabel. Tutte le 36 migrazioni e il YAML applicativo sono identici alla V36 installata.

## Riuso Teatri/V36 e delta esatto

I fix del prodotto sono persistenti nei repository Onboarding/MCP: ownership durevole dello stesso asset/job prima delle risorse di controllo, risorsa `managed-profile-job` autorizzata per il contesto HUMAN limitato, controllo CSRF prima dei lookup mutanti, rifiuti sicuri con causa e nessun retry di 401/403, comando pendente stabile in UI; MCP usa lo stesso contesto solo per la preview esatta asset/job. Il modello ruolo confezionato non assegna automaticamente grant o ruoli.

Il nuovo pacchetto `tools/managed_csv_control_update/` compone i primitivi qualificati di firma Ed25519, journal/CAS/claim, custodia immagini, lifecycle, TTY e backup già usati nel percorso Teatri/V36. Nessun vecchio entrypoint o authority viene eseguito. Gli adattatori nuovi cambiano i due target, l'ordine Onboarding→MCP e il fence di una V36 già installata. Le costanti del caso restano vincoli della manutenzione di questa installazione, non default di un installer universale.

Prima della review: 3 metadata esatti, archivi nativi verificati, JAR esatto estratto offline, un solo YAML owner esistente letto in memoria e precedenze configurative riclassificate; coorte esatta 13, pin PID1/daemon/owner/peer, socket ROOT/SO_PEERCRED, rete e capacità attuali. Zero SQL, firme e lifecycle prima del consenso. Nessun peer nuovo o mancante viene adottato; i nomi `peer-<id>` originali rimangono nella provenienza, gli alias dei soli due target sono espliciti.

Dopo la decisione umana nel terminale: authority nuova di 900s, 26 passaggi chiusi. Otto SQL tecniche READ ONLY, con storia36 esatta, Farmacie FAILED/5 e intero snapshot V36 uguale al primo campione fresco. Due campioni circondano il backup con Onboarding fermo: pg_dump custom massimo256MiB/90s e parsing pg_restore a `/dev/null`, senza restore. Nessuna nuova migrazione, DDL, riparazione dati o query libera.

Prima si sostituisce Onboarding; solo dopo readiness e fence si sostituisce MCP. Ogni vecchio owner viene fermato, scollegato, rinominato e trattenuto. Preservati Env/launch/mount/label, MAC/IP/alias/porte e policy risorse, incluso Memory=0. Undici peer invariati, Registry e worker intatti. Transizione Config.MacAddress solo dopo stop/detach provati, per il profilo legacy esatto; nessuna normalizzazione per gli altri owner.

Readiness sul processo candidato esatto: Onboarding percorso già classificato `/actuator/health/readiness` con UP; MCP trasporto del caso già qualificato8080 `/health/ready`,204. Pausa di startup finita180s,2s±20% jitter, massimo128GET complessivi; 401/403/404/altri errori permanenti o sconosciuti bloccano. Il nuovo codice non trasforma readiness in E2E.

Tre firme usano le due chiavi installazione esistenti solo dopo consenso, massimo15 aperture. Il controller non emette OAuth; il normale bootstrap OAuth/catalogo degli owner può avvenire entro l'autorità già configurata del workload. Questo non concede nuovi permessi o budget.

Un unico watchdog effimero, privo di intenti di avanzamento, applica l'authority negativa per ulteriori30s: può soltanto disabilitare restart e fermare i propri due candidati verificati e non committed. Non avvia vecchi owner, non fa rollback, non tocca peer o Registry. Esito ambiguo rimane CLAIMED; scope consumato e contatori conservati, niente rilancio, reset o scope alternativo per tentare ancora.

## Qualifica

[Dossier di qualifica](../../evidence/managed-csv-control-update-qualified-20261027.json). Codice di produzione74c4ddd77ff6f0e2122ff139eebdbd80dc671f0f; wrapper965583e9aadc1a690541c83d543626abe8bf165c/SHAf91f09abc6b8c399256a246ff738c462d59540d5cd36a047041d81a4ab94260a; chiusura28fonti e manifestebd7f080088da1c62e126ecd12e1228203be74039925080d322203a29a40ba61, root/usr/local/lib/ouf-managed-csv-control-update-ebd7f080088da1c6. I byte di tutti i primitivi riusati sono immutati.

Qualifica finaleaf635f7f7d9b1eae8866f90dbf563cc478e763b4, [run40595845656](https://github.com/GioNob/ouf-deploy/actions/runs/40595845656),9jobPASS e log diretti ispezionati:

| Prova | Job | Esito |
| --- | --- | --- |
| Ed25519/CAS/no replay + fence36/comandi/readiness |122511425936|12+7test,0skip |
| Percorso completo due owner e import esatto |122511425790|26stage,8SQL,backup,11peer,3firme PASS |
| Percorso completo Memory0 |122511425716|Stesse prove, policy risorse conservata PASS |
| Lavoro READY blocca prima di write/import |122511425792|PASS |
| Modifica esterna conservata, stop prima di start |122511425830|PASS |
| Perdita reale controller, solo2nuovi candidati fermati |122511425887|PASS |
| Sudo/TTY use_pty e !use_pty |122511425899 /122511425728|11casi ciascuno PASS |
| Due ZIP/JAR/configurazione/36migrazioni/YAML reali |122511425533|PASS, override rifiutati |

Consegna realebc622c7fc55b02de111a40b569f026768e44a2d6, [run40594822521](https://github.com/GioNob/ouf-deploy/actions/runs/40594822521)/job122507943603PASS, log diretto ispezionato. Primo run40594379341 conservato: i due percorsi positivi erano completati, poi la fixture richiedeva erroneamente2load mentre manifest sintetici lasciati da casi precedenti erano già esatti/presenti. Corretto soltanto isolamento/pulizia immagini sintetiche e selezione dei casi CI; nessun codice o guard di produzione cambiato. Le tre prove native di errore erano già PASS e sono state ripetute correttamente. Le fixture CI hanno workload/identità/chiavi/dati sintetici, Docker29.8.1/containerd e PostgreSQL17 reali. Il JAR, le migrazioni, il YAML e i due archivi qualificati sono verificati separatamente sui byte CI esatti. Nessuna prova CI è una nuova ammissione del target o E2E applicativo.

La consegna protetta verifica28 fonti e `sources.json` root0400/checksum ROOT, dopo HTTPS pubblico finito180s e verifica da root. Nessun gh/timeout/token. Stdio diretto al TTY, niente pipe o consenso incorporato; log runtime root0600 e log bootstrap operatore0600. Hash privato errato, ingresso nonTTY e scope già consumato sono rifiutati prima degli effetti. Il percorso umano consente correzione della riga, Backspace/Ctrl-U e Invio, senza modificare review o scadenza.

## Una sola prossima azione operatore

Qualifica completa. Il [solo nuovo comando](../../releases/OUF_MANAGED_CSV_CONTROL_UPDATE_COMMAND_20261027.sh), fissato al wrapper immutabile avvia la review fresca sul VPS come `oufadmin`. Può richiedere sudo. Il terminale mostra perimetro, limiti, review privata e una riga `APPROVO <hash-fresco>`; decide e inserisce la riga esclusivamente l'operatore. L'agent non la simula e non usa hash storici. Dopo una mancata approvazione o qualunque STOP conservare directory e log senza rilanciare.

Esito positivo atteso: `MANAGED_CSV_CONTROL_UPDATE_INSTALLED_E2E_NOT_ACCEPTED`, complete=true, componentReadinessProven=true, 8SQL, backup verificato, zero nuove migrazioni, 11peer invariati, Exit0/DeliveryExit0. Restituire il risultato e i percorsi nuovi; non serve il log del vecchio APPLY36, già acquisito integralmente.

## Dopo la manutenzione: stessa Farmacie fino a UDP

Prima di capability governate verificare l'identità OUF effettiva `ouf-admin`, tenant, ownership, Gateway e permessi correnti. Policy56 SERVICE strutturale è già pubblicata/verificata; niente rinnovi temporanei. Catalogo/scopes/hop nativo e accesso HUMAN devono essere provati sul codice installato; il template ruolo non è un'assegnazione.

THS ESCLUSIVA UTENTE. Link esatto, da inviare quando serve: https://api.ouf-lab.it/trusted-human/managed-files/recovery/?asset=9c502da5-b5d8-405e-b3f5-60eb31ecb513&job=677480c8-3d10-44fd-9dad-f72ddeed20a4 . Non proporre la root API come login o pagina del job; non accedere alla THS per l'utente.

La concessione di una sessione3tentativi/900s e il successivo resume sono due decisioni HUMAN separate sullo STESSO job, con stato/review freschi. Tentativi cumulativi6–8, mai azzeramento. Risposta ambigua: riconciliare lo stesso comando/sessione, nessuna seconda concessione. Nessun nuovo upload/job o acquisizione usata come scorciatoia.

Poi lettura originale, confronto SHA `f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311`, parser installato, preview61righe/10colonne e percorso semantico governato→Ingestion→UDP. Le61righe non implicano61nuovi oggetti: ogni riga va contabilizzata secondo gli esiti UDP. Riusare typed/ASSETS/LATEST, Teatri, recovery, Registry e riconciliazione già fatti; D5/D6/D7 e requisiti restanti del [mini-PET M2](../OUF_M2_MINIPET_v1_0_20261026.md) e della roadmap rimangono aperti.

M1/G4 e la prova conservata8/8tecniche/6/6funzionali restano acquisiti. M2/G5/G6/G7, due client reali, originale/hash/parser/UDP, accettazione e Supervisor restano distinti; Supervisor solo dopo E2E completo. Nessun Registry restart/reinstall, terza acquisizione Teatri, merge o release acceptance. Nessun subagente o automazione operativa.

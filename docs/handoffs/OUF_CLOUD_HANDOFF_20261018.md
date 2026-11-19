# OUF — handoff cloud, lavoro interrotto su richiesta dell’utente

## Stato e ordine dell’utente
L’utente ha richiesto di interrompere immediatamente il lavoro in questa chat locale e di passare a una NUOVA chat CLOUD. Nessuna ripresa automatica: attendere un esplicito messaggio dell’utente nella nuova chat.

Obiettivo: completare il percorso generico chatbot/MCP → onboarding semantico file/CSV → ingestion → riconciliazione identità/proprietà → commit → grafo UDP. Teatri è soltanto il collaudo: nessuna logica applicativa specifica. Supportare anche altri file/GeoPackage/API/scheduler/delta/layer dinamici. Autorizzazione permanente dell’utente a leggere/scrivere i repository GioNob e usare tutti gli strumenti OUF MCP: non chiedere nuovamente consensi generici. Non inventare cardinalità, priorità delle fonti o cancellazioni; preservare provenienza e valori concorrenti. Distinguere codice installato, profilo pubblicato e prova funzionale. Preparare e qualificare prima di login temporanei.

**Tecniche 8/8; funzionali 4/6.** Il recupero infrastrutturale non aumenta i funzionali. Nessun profilo nativo di riconciliazione pubblicato. Restano collaudi5/6: seconda acquisizione controllata dello stesso CSV senza duplicati e verifica di entrambe le acquisizioni con conservazione degli8Cinema.

## Ultimo job / azione conclusa sul VPS
Il recupero rete amministrativo è COMPLETATO, da non rilanciare:
- delivery runtime75c6fd77721df109b9176f8ff3900b2b71355049; source17d4cf452a445a1fa96824c6ce7b46339133f914.
- qualificazione37 test: CI39152854468, root117749880923, Docker117749912306, commit testc86a7e44c12e56fda8fc0a3ecdff3293fa5532bb.
- contesto /etc/ouf/deploy-snapshots/host-network-reconciliation-c_zpdhof.
- plan SHA256 e8dd1322daea4ee8b2f1b8fbe332c76014d998ff89577443fca0ba0ccd2d2b0b.
-6endpoint corretti,13 scritture Docker, UDP esistente avviato.
- APISIX172.18.0.5→15; MinIO6→16; Keycloak2, PostgreSQL3, Caddy4 e Gateway operational owner8 diventati fissi mantenendo IP.
- stessi container/immagini/processi/volumi/MAC/alias e reti indipendenti.5 soli aggiornamenti Config.MacAddress derivati dalla rappresentazione legacy, verificati con profilo ristretto.
- preboot HostConfig.Dns null→[] sulle3 app; nessun altro campo immutabile diverso e nessuna riscrittura del riferimento storico.
- tutte5 verifiche sui file montati passate. Nessun chmod/chown o modifica contenuti.
- provider nativo **BLOCKED**, kernel vuoto, authority revocata, avvio NON autorizzato; riconciliazione ancora necessaria.
- nessuna migrazione/pubblicazione/nuova decisione identità/retry esplicito dei job; worker preesistenti possono essere ripartiti.
- ricevuta utente salvata in evidence/host-network-reconciliation-target-complete-20261018.json. Non è ancora un readback indipendente del journal root.

Ultimo job indipendente del runner **CONCLUSO CON SUCCESSO**:
- commit ce132bbcb3bd8239689415797371afe636db7762.
- workflow Post host network native read, run39158332027.
- test di redazione4 passati, job117766124391.
- lettura VPS job117766143548 completata:6 endpoint fissi corrispondono;9 identità/processi stabili.
- UDP: HTTP200 UP; Onboarding: HTTP200 UP; MCP: HTTP204 pronto.
- allThreeNativeReadinessProven=true. Questo NON prova disponibilità Semantic/provider né integrazione grafo.
-3 GET native di salute,0 mutazioni/SQL/credenziali/pubblicazioni/retry; nessun redirect/retry automatico.
- La ricevuta di questo job è nei log GitHub (non ancora salvata in un nuovo commit di documentazione quando l’utente ha interrotto).
- stato MCP via connettore: HEALTHY soltanto modulo MCP.
- ouf.operations.summary con account admin ha restituito403, wrapper INVALID_ARGUMENT: NON ritentato, NON sostituito con SQL sugli incidenti. Riepilogo incidenti non verificato.

## Lavoro interrotto: preparazione del successore privato postboot
Stavo preparando la riconciliazione esplicita degli input privati prima del rilascio nativo Onboarding/MCP.
**NON è stato eseguito alcun nuovo programma root, login, grant, backup, migrazione o rilascio. Nessun job di questa preparazione avviato sul VPS.**

Sono appena state scritte DUE BOZZE LOCALI NON COMMITTATE/NON TESTATE/NON QUALIFICATE:
- work/revision/post-network/policy.py
- work/revision/post-network/prepare.py
Saranno conservate come allegati testuali di questo handoff, NON come script eseguibili o consegna approvata. Non eseguirle. Non hanno test, launcher, selezione finale o hash di consegna.

Intento delle bozze, da riesaminare criticamente:
1. verificare pointer/journal/plan root del recupero completato, le13 claim esatte e la parentela col vecchio input c23;
2. verificare ancora endpoint e provider vuoto/revocato, sul lock originale;
3. caricare SOLO come librerie gli81 file del pacchetto di esecuzione già qualificato c750, verificando ogni hash e il loader in memoria;
4. leggere c23 e produrre un successore privato esplicito con nuovi socket/PID/namespace/PG, senza sovrascrivere gli originali e senza riusare authority storiche;
5. conservare archivi candidati/custodia, configurazioni, route e semantiche; adattare solo l’intento di creazione Dns null→[] se già provato;
6. ricontrollare migrazioni/privilegi Onboarding e compilare interamente il piano nativo usando il verificatore Spring già qualificato;
7. riconciliare il vecchio STOP55e confrontando i7 file del gateway-compiler e assenza di artefatti di authority;
8. terminare **readyForExecution=false**, prima di HUMAN/login/authority.

Limiti IMPORTANTI delle bozze:
- non qualificate nemmeno sintatticamente; non presumere correttezza.
- la bozza usa compile_private come libreria con una proposta di case/input nuovi; la dichiarazione chiusa del pacchetto staged resta legata al case storico. NON riusare un piano così compilato per l’esecuzione: il successivo executor dovrà avere case/hash/closure postboot espliciti e qualificati.
- execute-source-revision-update attuale ricarica prepared dal vecchio bundle: per la futura esecuzione manca ancora un percorso esplicito e validato per il prepared originale riconciliato. Non basta cambiare hash/PID.
- il verificatore di STOP parziale va riesaminato e testato, così come le letture root, stabilità dei processi e dipendenze importate.
- non aprire una sessione HUMAN prima che preparazione e verifiche siano concretamente complete.

## Repository e documentazione
Repo principale GioNob/ouf-deploy, branch feat/chat-only-recovery-package-20261018.
Head remoto all’interruzione: ce132bbcb3bd8239689415797371afe636db7762.
PR41 DRAFT già allegata alla vecchia chat: https://github.com/GioNob/ouf-deploy/pull/41 ; non crearne duplicati.
Doc principali:
- docs/CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md
- docs/CHATBOT_CSV_ROADMAP.md
- docs/POST_BOOT_NETWORK_CORRECTION_PLAN_20261018.md
Le doc registrano host COMPLETE e lettura di disponibilità in corso; alla ripresa aggiornare con il job39158332027 già riuscito.
Spec da rispettare: https://github.com/GioNob/ouf-deploy/blob/83e2e85a0ae4107ba52486de7bdcbfe4502761cc/docs/LINKED_OBJECT_PROPERTY_RECONCILIATION_V1.md
Leggere AGENTS.md e releases/PET_ROADMAP_RECONCILIATION_20261010.md. PET = documenti progettuali, NON plugin di animali.
Baseline PET: Matrice1.7/Blueprint0.3, Onboarding1.6, Auth1.5, Gateway1.5, Ingestion1.3, UDP1.3, Semantic1.3, MCP1.4.
Retry: transitori espliciti e finiti, backoff/jitter/fencing/journal; sconosciuto/integrità/config drift blocca; effetti incerti si riconciliano senza replay. Nessun reset budget/grant consumati; nessun lock durante attese di retry.

## Rilascio nativo revisione fonte già implementato: NON rifare
- GioNob/ouf-source-onboarding PR46: be388e1462778438a208c2e00e166370fee32189.
- GioNob/ouf-api-gateway PR79: dd8553da90d7a6cfc1083e1cf4d9075c09ee389b.
- GioNob/ouf-mcp-server PR74: a79b139c7a26d64a584b0a432ebb8df8c32a52ed.
- nuove capabilities ouf.onboarding.revision.read/prepare.
- owner /api/internal/v1/onboarding/source-revision-mcp/{read,prepare}; Gateway /internal/capabilities/v1/execute/source.revision/{read,prepare}.
- dedupe parentVersionId/commandKey, hash/lock stale guards, DRAFT nativo, avviso NEW_PUBLICATION_MAY_START_ACQUISITION, nessuna autopubblicazione.
- candidato già costruito39085780635 e consegnato39086004570:
  /home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-39086004570
  manifest83c8d7fc8f28e954960899f8e066a31e1dc06de86f89431c6f607c79219c9ee7.
- immagini candidate Onboarding f6c005160610cbf35d2296e1e1eb107469ad527c97196f94cbda21946d65e85e;
  MCP e03ae46ae6cf1c2742549b208b7611ac97f4fe9ffa25189ff5087b07c3a6f7e5.
- input privati preboot:
  /etc/ouf/deploy-snapshots/source-revision-prepared-lssxnowq/prepared-plan.json
  SHA c23ec15b43427c4558b5b06bf36c2c1b4fa73943efbc0e081ad2731b69c9bc89.
  Candidati root-custodied già presenti: riusare e verificarne gli hash, non rifare copie/import.
- precedente executor fermato prima di authority:
  /etc/ouf/deploy-snapshots/source-revision-execution-55e7sduq
  reason UNREVIEWED_SPRING_OVERRIDE_CHANNEL; solo gateway-compiler con7 sorgenti, nessun login/backup/effetto.
  Non rilanciare il vecchio launcher.
- verificatore Spring corretto e **74 test passati**:
  source c750125eb2995789d499e369d06b9223fc869811, CI39147241974;
  pacchetto81 file STAGED, non installato:
  /home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-code-39147241974
  package.json SHA c6d6cc3b63336aa3060a434eb20d019496cbc63ca4b25b37965d7fe3d062a423.
  Ammette solo7 proprietà owner/THS di SPRING_APPLICATION_JSON, rifiuta datasource/Flyway/profili/loader e duplicati; conserva byte/hash.
- Onboarding attuale33→candidato34, UDP36, migrazioni MCP invariate13.
- V34 Onboarding checksum -1996496299, SHA08161423d63540db5ee5e3084361370e0e774448ed0bd9d37acacd6ae42ff4e5.
- backup quiescente verificato prima di Flyway applicativo; niente SQL manuale di migrazione.78 route baseline, solo2 route additive.
- autorizzazione/signature native reali, nessuna firma o acceptance fabbricata. HUMAN vecchio circa168/256 tentativi OAuth: preservare journal/budget; non rinnovare automaticamente.
- il compile_private corrente esige uguaglianza dei binding preboot (socket/PID/PG/APISIX), e replacement verifica HostConfig.Dns dell’intento vecchio: vanno riconciliati ESPLICITAMENTE nel successore, non disabilitati.
- Native GatewayRuntime.compile_runtime rifiuta endpoint statici APISIX per un’eventuale sua sostituzione. Qualificare conservazione prima di future sostituzioni; non togliere guard. Il rilascio attuale sostituisce solo Onboarding/MCP e modifica2 route.

## Identità e rete attuali utili
Backend ouf-backend id113b5f0a3c53059b087a2ce997d2670cc057e88c0c17d4291b3b41a51ce26ba3,172.18.0.0/16, internal=true.
- UDP946fd69972ada2e310c32f72da27f19a04e7a2043dc330f116e8ba1c507e6e3b,IP5,
  image ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52,
  source0d40da05408a14db31d4d41af2372d6a71480291.
- Onboarding8dc539b0756beb40cee0d45b2b223a18eee1a53d8cdb4389d7d914dbda66aad9,IP7,
  image b5f09f8b0273e4c2c6d99003b7d10e2f79e733811f5de18185843c7ed8e9b80d,
  sourcecc7766e6348f9ed2e66ec04018ebb63a904d202d.
- MCPc2c2893f1b2f03a7a5216a3b21601c5c639ab5f4f7b193d5a960271ba19b0696,IP11,
  image141ee11efe39c1790f85e843bb012928fd17d75c8156ac87277c660c140c6dfb,
  source15b49f495267ef8da9edd23f03b6e5018ec98d5e.
- APISIX733c5bdeca250fba778d431e121120e6653296d84c747552d8f95290ad01e8d9,IP15.
- PostgreSQL50b36d71620ad00fee1bae45aaf0bf652b9171dc09f567fa552798daf12614ea,IP3.
PID/socket/namespace sono generazioni correnti da verificare nuovamente, mai authority da copiare dal testo.
Provider boot profile:
 /etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-v2-e4repg0a/boot-profile.json
 SHA b247b94ac8d77d3604840e052878fcc12f4dc6f7e7e8df548f6971c227504845.
Lock /run/ouf-semantic-boot-guard/guard.lock. Originali boot/lease owner/restorer preservati.
L’host ha riavviato Docker dopo riparazioni lock e sandbox journal, già concluse: NON rilanciarle.

## Sorgente funzionale e prove da preservare
sourceId teatri-csv-6609b245; parent ACTIVE9860853e-e8f3-4b93-b9d2-03521a039962,lock4.
configurationHash sha256:ae7f46b4214d09c55a9885530920026258f0dcd588462c353b06d82185e12c9b.
publication996d58ca-43d6-42f5-a42a-311940e742f9,sequence1.
publicationChecksum sha256:c997e4ccdb1e97823e1a55f4e5a549ee6cecee80da865bb246bb297d8cbd7431.
INTERNAL_MANAGED/MANAGED/FULL_SNAPSHOT/NONE.
13 righe/oggetti già materializzati,13ACK/lineage,0quarantena nell’ultima prova funzionale.
12 CREATE_NEW umani; oggetto originario d6051381-934b-4a11-8e71-e1d89cee4e49 conservato.
Ultimo jobc5692362-8a22-4656-97b6-46b5ba8ce17f già recuperato: NON ritentarlo.
Tappa4: proposta94306235-fc45-4433-a05e-0ead3f83a9f8 PUBLISHED,policy43; ricerca MCP13oggetti ACTIVE con20proprietà.
20 proprietà reconciliation:null; profilo nativo non pubblicato.
Proposta20regole in releases/source-property-revision-proposal-20261018.json: preparata, non inviata.
Non ripetere decisioni d’identità o acquisizioni storiche implicitamente. Nuova pubblicazione può essere consumata dallo scheduler.

## Strumenti / vincoli per la chat CLOUD
Usare GitHub e OUF MCP con gli account autorizzati. Admin link OUF della chat precedente:
link_6aafef96b4148191b767e9af7b756a07 (verificare disponibilità nella nuova chat).
Repo onboarding corretto: GioNob/ouf-source-onboarding, NON GioNob/ouf-onboarding.
Nessun SSH o canale admin root diretto era disponibile. Runner self-hosted [Linux,X64,ouf-vps-test] può fare letture Docker ma non leggere tutti i riferimenti root né modificarli. NON usare container privilegiati/exec per aggirare questi limiti.
Password sudo richiede intervento fisico; nessun nuovo consenso generico repository/MCP.
GitHub CLI VPS disponibile: $HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh.
Le cartelle locali Windows NON saranno accessibili dal cloud. Questa nota e le bozze testuali sul repo sono il trasferimento necessario.
L’utente non ha chiesto subagenti: non delegare.
Nessun goal attivo creato. Non creare automazioni o riprese periodiche.

## Stato dell’interruzione
Il job operativo su cui stavo lavorando (preparazione privata postboot) è **FERMATO IN BOZZA**, non qualificato e non eseguito.
Il job di lettura39158332027 è già **COMPLETATO**, non c’è un job di deploy nuovo da interrompere.
Eventuali workflow CI generici avviati automaticamente dal commit ce132 sono indipendenti e non sono stati dichiarati deployment né cancellati alla cieca.
La prossima chat deve attendere il via dell’utente; poi aggiornare la documentazione con il readback riuscito e riesaminare le bozze, prima di proporre qualunque esecuzione.

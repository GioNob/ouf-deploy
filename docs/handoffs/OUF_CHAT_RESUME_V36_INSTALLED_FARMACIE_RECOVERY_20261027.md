# Ripresa OUF — APPLY V36 completato; prossimo recupero HUMAN dello stesso job Farmacie

## Aggiornamento accesso HUMAN — 27 ottobre 2026

L'owner ha chiarito: **alla THS accede e decide soltanto l'utente, non l'assistente**. L'assistente fornisce il link esatto a ogni decisione necessaria; non apre o controlla ulteriormente la THS e non simula consenso, budget o resume.

La pagina recovery è raggiungibile. Un primo tentativo di sola lettura dell'assistente ha mostrato «Accesso non autorizzato o sessione scaduta». Successivamente l'utente ha riportato lo stesso messaggio. Il JS installato presenta quel testo sia per HTTP401 sia per403: status esatto, identità effettiva, scope/label e gate Gateway/owner non sono ancora distinti. NON è una nuova lettura riuscita del job.

[Ingresso OIDC verificato nel codice installato](https://api.ouf-lab.it/oauth2/authorization/ouf-ths). Dopo questo passaggio l'utente ha riportato404 Route Not Found sulla radice https://api.ouf-lab.it/ . Il404 della radice non prova fallimento del login né indisponibilità della recovery. È stato fornito nuovamente il [link esatto alla scheda Farmacie](https://api.ouf-lab.it/trusted-human/managed-files/recovery/?asset=9c502da5-b5d8-405e-b3f5-60eb31ecb513&job=677480c8-3d10-44fd-9dad-f72ddeed20a4); l'utente ha poi confermato di aver riaperto il link esatto. Il contenuto attuale della scheda e l'identità effettiva non sono ancora stati riportati: non dedurre successo dalla sola riapertura.

Se la scheda è disponibile: verificare account ouf-admin, stesso asset/job e stato fresco prima delle due decisioni separate, sessione3tentativi/900s e poi resume. FAILED5 resta l'ultima osservazione acquisita dall'APPLY, non una nuova lettura della scheda. Se esistono già sessione o comando pending, riconciliare quelli senza nuova concessione.

Se il diniego persiste: localizzare il gate con letture governate minime e identità verificata; nessun grant largo/temporaneo per tentativi e nessun nuovo upload/job/APPLY. Gateway GET richiede preview; owner card richiede file.profile e ownership tenant/soggetto. Budget/resume richiedono inoltre quarantine.release. Policy56 SERVICE non prova questi permessi HUMAN.

[Evidenza di accesso e passaggio HUMAN](../../evidence/profile-recovery-human-handoff-20261027.json). Nessuna chiamata al connettore OUF, decisione HUMAN o acquisizione eseguita dall'assistente in questa ripresa. La discovery corrente elenca il routing ouf-admin; il nome del collegamento non è prova del principal effettivo. Non usare giovanni-chatgpt come fallback.

V36 resta installata secondo la ricevuta positiva già acquisita; tutti gli scope precedenti restano consumati. M1/G4 acquisiti; M2/G5/G6/G7 aperti.

27 ottobre 2026, Europe/Rome (UTC+1). Repository `GioNob/ouf-deploy`, branch `fix/registry-bound-owner-lineage-20261023`, PR draft [#50](https://github.com/GioNob/ouf-deploy/pull/50). Predecessore documentale `2b3e94c75f59c9eb1c057dc2765f2081436f8450`. Questo aggiornamento registra un risultato VPS già avvenuto: nessun nuovo comando VPS, chiamata OUF, concessione, resume, acquisizione, merge o accettazione eseguiti da questa chat.

## Risposta al dubbio dell’operatore

**Sì: log.txt corrisponde all’ultimo comando APPLY Onboarding V35→V36 consegnato, e mostra che quell’esecuzione si è conclusa positivamente. NON rieseguirlo.**

Il file, prima inaccessibile alla chat, è stato ora reso disponibile come allegato locale e letto integralmente. Contiene frame issued, tutti i16stage ordinati, risultato finale e footer con Exit=0/DeliveryExit=0. Sono coerenti con schema, input, piano condizionale, source, immagine, scope e percorso del codice/log pinned del comando consegnato. Sono state verificate monotonicità dei contatori e aderenza ai massimi.

Il precedente checkpoint “output non leggibile/esito sconosciuto” è SUPERATO da questa prova. Non mantenere la precedente incertezza e non chiedere un’altra esecuzione o nuova approvazione della manutenzione. Il file inizia dal frame issued: non contiene il preambolo di download/checksum o la riga APPROVO letterale; non dichiarare di averli osservati in questo allegato. Il controller riporta la nuova authority e tre operazioni di firma nel risultato completo. Non sono stati riletti file di firma/journal sul VPS né svolte nuove verifiche live: l’origine della prova è l’output VPS fornito dall’operatore, coerente con il controller qualificato.

- [Ricevuta strutturata completa](../../evidence/profile-recovery-v36-native-apply-target-20261027.json).
- [Log originale integrale](../../evidence/profile-recovery-v36-native-apply-target-20261027.log).
- SHA256 log originale: `481e6c8cfcb666594b726192d099ab7e1f5466a755f994d9e4bdec9edcab14a1`,10608byte.
- Status: `ONBOARDING_PROFILE_RECOVERY_UPDATE_INSTALLED_E2E_NOT_ACCEPTED`.
- complete=true; componentReadinessProven=true; Exit=0; DeliveryExit=0.
- applicationE2EProven=false; releaseAcceptance=false.

## Risultato VPS acquisito

Onboarding source `6ea5242f711761a384fa1b23667971601bc2c38b` e immagine nativa `sha256:e4690481db28e3e70335704de89e563dcf32ecf70e4a0caea1bdc30c48aa4359` risultano installati al completamento. Una sola migrazione nativa35→36; backup quiescente e payload verificato senza restore. Storia migrazioni esatta, nessun lavoro profile/readiness pendente al controllo finale, dati precedenti conservati. Nuove colonne ai default, nessuna nuova sessione/evento di recovery: `additiveV36AndZeroNewBudgetsProven=true`.

Il medesimo job Farmacie è rimasto FAILED/tentativi5; il controller non lo ha rilanciato e non ha concesso budget. Dodici peer invariati, vecchio owner trattenuto fermo, Registry worker non toccato. Nessun nuovo grant, Gateway request, attivazione, acquisizione, reset o rollback. Bootstrap OAuth ordinario del solo nuovo owner può essere avvenuto; il repair riporta0richieste OAuth proprie e non osserva il conteggio del bootstrap normale.

| Identità dell’esecuzione riuscita | Valore |
| --- | --- |
| reviewHash | 27355a4ee5c18d59e029d394aa871c6c34cd79103146cd95f15db4f6fd306a07 |
| authorityHash | 299960e8a9d0f174abe9d5936f9b45f35e8104cc8add76466d061d0bea9070d1 |
| executionInputsHash | 564038c5d487f0a4f4504cca4c6e9e418e1f715dbf95fe9ce97cb2b27c297b76 |
| retainedConditionalPlanHash | 432c2930c119223449870e935a1ac0f485607812e73019928b4148d9238ab22a |
| frozenPlanHash della review corrente | 51129bb14244fff13c5cb95f4c8c2844de0b1b1afa23733b2dba1393bd5dd576 |
| nativeBindingHash finale | a65fb7d4ab8833f47e42dd1f145131d30bd646344ea615b388e5b6cc29b9e5e7 |
| runtimeBindingHash | 05f8dab7097dd4a42d010b609d88b9be634d26b302222c67169a68377dd853d1 |
| operationalStateHash conservato | db5d8d256acc687e1ae696a5ac5072e25ee9774b39e976050c39abfe6c539fa6 |

I due hash di piano sono diversi per funzione:432c... identifica la proposta condizionale preparata;51129... il piano corrente incluso nella review con coorte/configurazione e vincoli runtime. Non è una discrepanza da “riparare” o motivo di rilancio.

Contatori finali di QUESTO scope, senza azzerare o riadottare i vecchi:
| Operazione | Effettivo | Massimo |
| --- | ---: | ---: |
| EngineGET | 300 | 512 |
| Enginewrite HTTP | 8 | 10 |
| Image load | 1 | 1 |
| SQL tecniche READ | 7 | 7 |
| Processi backup | 2 | 2 |
| ReadinessGET | 3 | 96 |
| Metadata owner | 7 | 64 |
| Contenuto config owner | 1 | 1 |
| Servicecredentialfile | 0 | 0 |
| Quarantena candidato | 0 | 1 |
| Gateway adminGET/PUT | 0/0 | 0/0 |

Tre operazioni di firma installazione riportate. Finestra originale review900s, esecuzione900s, startup180s,+30s solo quarantena; dump<=256MiB/processo90s/timeout interno85s. Questi limiti descrivono lo scope riuscito CONSUMATO, non un’autorizzazione riutilizzabile.

### Backup e log conservati sul VPS

- Scope CONSUMATO: `/etc/ouf/deploy-snapshots/onboarding-profile-recovery-v36-apply-564038c5d487f0a4-v1`.
- Backup: `/etc/ouf/deploy-snapshots/onboarding-profile-recovery-v36-apply-564038c5d487f0a4-v1/onboarding.dump`.
- Backup670478byte, SHA256 `e307358349886c1eaa860f47f063a29f31c69ef4fb37dae5a6a7dd21c792c133`; quiesced=true/payloadParsed=true/databaseRestorePerformed=false.
- Directory operatore/delivery: `/home/oufadmin/ouf-onboarding-profile-v36-apply-delivery.Te9b2Q4Y`.
- Log: `/usr/local/lib/ouf-onboarding-profile-recovery-update-a46b19156c35cb91/operator.log`.
- DeliveryLog: `/home/oufadmin/ouf-onboarding-profile-v36-apply-delivery.Te9b2Q4Y/bootstrap.log`.

Non cancellare, riscrivere, rilanciare o normalizzare questi file/contatori. Nessuna necessità di rileggere SQL o fare un nuovo APPLY soltanto per confermare il risultato allegato già coerente. Una futura verifica live deve avere uno scopo necessario e governato.

## Catena di codice, immagine e prove da leggere

Leggere integralmente questo handoff, intestazione corrente di AGENTS.md, poi:
1. [Controller V36, review e limiti](OUF_PROFILE_RECOVERY_V36_NATIVE_APPLY_20261027.md). Le istruzioni di PRIMA esecuzione lì riportate sono ora STORICHE e NON vanno eseguite.
2. [Preparazione immagine/piano](OUF_PROFILE_RECOVERY_IMAGE_PLAN_20261027.md), [ricevuta VPS preparazione](../../evidence/profile-recovery-image-plan-target-20261027.json).
3. [Recovery HUMAN/contratto/cattura](OUF_PROFILE_RECOVERY_NATIVE_REVIEW_20261027.md), [qualifica sorgente](../../evidence/profile-recovery-source-qualification-20261027.json).
4. [Piano M2](../../releases/csv-m2-plan-20261026.json), [minipet M2](../OUF_M2_MINIPET_v1_0_20261026.md), [roadmap](../OUF_M2_ROADMAP_20261026.md), confronto codice/prove/lacune e predecessori collegati.
5. [Qualifica controller](../../evidence/profile-recovery-v36-native-update-qualified-20261027.json), [manifesto chiuso](../../releases/onboarding-profile-recovery-native-closure-20261027.json).
6. [Vecchio checkpoint allegato non leggibile](OUF_CHAT_RESUME_V36_APPLY_OUTPUT_PENDING_READ_20261027.md): SOLO storia della conversazione, esito sconosciuto ora risolto dalla ricevuta positiva sopra.

Pin manutenzione già eseguita:
- codice `e5410467a410188a3b7ee7ae3264c7b0782f7b4a`, entry `scripts/apply-onboarding-profile-recovery-update-20261027.py`;
- wrapper `2f04dff7438b0f59c94e341d9c946f9098ba67ef`, `releases/apply-onboarding-profile-recovery-update-20261027.sh`;
- SHA256wrapper `dc1d4312f770f2dd4b95672060d189161344dbfd0e4f454ab6a32bf69bc03c07`;
- manifesto23fonti `a46b19156c35cb915b0842e52a72a97bac691c0cd64676aaaa704eb285793cc2`;
- source OnboardingPR53 `6ea5242f711761a384fa1b23667971601bc2c38b`, tested merge immagine `e42c398af3ab6989a956925445c478f8eb9f2446`;
- archivio nativo444241920byte/SHA256 `1553453fcdfd6166a38234194a81f8f6d04bb41a9552453fc51fb5c831e216a2`.

CI finale deploy b97ae857.../run40548069329:12protocollo,6MAC,9fence,7nativi Docker29.8.1/containerd+PG17/backup/watchdog,22TTY/sudo, JAR/configurazione reali e consegna curl/sudo root0400 PASS senza skip, log diretti letti. Fixture nativa Python/readiness con SQL36 esatta applicata dall’harness; JAR/integrazione Java35→36 separati in ownerCI329test/7browser/9diagnostica/2latenza/build-scan-boot PASS. Queste prove restano CI; la nuova ricevuta allegata è l’evidenza VPS distinta.

## Preparazioni e procedure già consumate

- Cattura `ONBOARDING_PROFILE_RECOVERY_CURRENT_INPUTS_CAPTURED_NOT_AUTHORIZED`, complete/Exit0/DeliveryExit0: hash `1ce0ce1cd27195565393798d4d06246047c5b46c12cef39bc31aee4ed7aff82c`, scope `/etc/ouf/deploy-snapshots/onboarding-profile-recovery-current-inputs-20261027-v1`,4metadata/3GET Engine/526335byte.
- Preparazione `ONBOARDING_PROFILE_RECOVERY_IMAGE_AND_CONDITIONAL_PLAN_PREPARED_NOT_AUTHORIZED`, complete/Exit0/DeliveryExit0: scope `/etc/ouf/deploy-snapshots/onboarding-profile-recovery-image-plan-1ce0ce1cd2719556-v1`, input564038c5.../piano432c2930...,3metadata/unZIP/unarchivio, zero runtime/SQL/OAuth/chiavi/credenziali.
- Publisher dei nove blocchi immagine già eseguito, nessun rebuild/relabel.
- APPLY V36 sopra completato. Anche review27355... e authority299960... sono prove storiche CONSUMATE, non mandate per altri lavori.
- Vecchia diagnosticaa5ed8b05.../native074bd16e... è ora il precedente owner trattenuto fermo, non l’owner attivo da reinstallare/riavviare.

Non cambiare i false “not authorized” nei file preparatori: descrivono correttamente quella fase storica, separata dalla nuova authority poi consumata. Non riavviare Registry worker e non reintrodurre guardie già risolte su Memory=0, peer rootPID1, MAC postdetach, OOM/profili mount nativi.

## PUNTO OPERATIVO SUCCESSIVO: HUMAN recovery nella THS

Asset Farmacie `9c502da5-b5d8-405e-b3f5-60eb31ecb513`; job `677480c8-3d10-44fd-9dad-f72ddeed20a4`. Dopo la manutenzione il controllo SQL finale conferma il precedente FAILED/tentativi5 conservato; nessun budget/resume eseguito. Non chiamare source.file.profile con una nuova chiave, non creare un altro job o upload e non usare SQL/release quarantena come concessione di budget.

1. Verificare l’identità effettiva HUMAN ouf-admin e l’accesso governato alla scheda del SOLO job. Le autorizzazioni richieste dalla nuova API sono file.profile per lo stato e file.profile+quarantine.release per azioni recovery; verificare anche il Gateway/preview gate, tenant/ownership, scope e label effettivi. CI e policy SERVICE non dimostrano questi permessi HUMAN attuali.
2. Usare la pagina nativa OIDC/CSRF/Gateway già installata. URL derivato dai parametri asset/job del JS qualificato, NON aperto né testato live da questa chat:
   [Recovery Farmacie nella THS](https://api.ouf-lab.it/trusted-human/managed-files/recovery/?asset=9c502da5-b5d8-405e-b3f5-60eb31ecb513&job=677480c8-3d10-44fd-9dad-f72ddeed20a4).
   Namespace `/trusted-human/managed-files/recovery/`; API `/api/onboarding/v1/managed-files/{assetId}/profile-jobs/{jobId}/recovery`. Pagina attiva solo con configurazione workflow THS già classificata. Non inventare query assetId/jobId: il JS legge `asset` e `job`.
3. La pagina esegue una READ di stato all’apertura; non concede o avvia automaticamente. Leggere stato e disponibilità azioni prima di decidere. Non simulare il consenso HUMAN e non trasmettere token/credenziali in chat.
4. Prima decisione HUMAN: nuova sessione managed-profile-recovery.v1,3tentativi/900s dalla concessione, motivo e revisione concreti. Snapshot privato del prior_job, expectedVersion/expectedGeneration/inputBindingHash/reviewHash e comando idempotente dalla scheda FRESCA. Concessione lascia FAILED e tentativi5.
5. Seconda decisione HUMAN distinta: resume della STESSA sessione/job. Cumulativi6–8, mai0–3; rilascio quarantena avviene in transazione sotto il mandato di dominio, non come bypass. Nessun budget di profiling dall’APPLY o da questa documentazione.
6. Risposta persa/errore ambiguo: mantenere stesso comando/sessione e riconciliare; nessun nuovo commandKey per aggirare esiti incerti. UI conserva pending in sessionStorage; monitoring dopo resume<=12READ/90s, senza estendere budget. Da non confondere con durata job900s.
7. Verificare esito reale dello stesso job, lettura originale/size/hash/parser/preview; poi riprendere composizione del CSV Farmacie fino a UDP. STOP/permanenti non si ritentano fuori budget.

Nessun tool MCP budget nuovo introdotto; le decisioni native non vanno sostituite da SQL, terminale manutenzione o token di altri account. Se accesso negato, localizzare il gate con letture governate minime; non ricreare grant SERVICE temporanei o modificare IAM alla cieca.

## Baseline, policy e lavoro restante

- CSV originale13903byte, UTF8BOM/punto e virgola,61righe/10colonne; SHA256 `f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311`. Parser locale valido; vecchio403 rilevato prima del body/parser. Non dichiarare ancora riuscita la lettura del CSV dopo policy56: questo APPLY non ha fatto profiling né acquisizioni.
- Policy56 SERVICE strutturale pubblicata/verificata: ouf-onboarding/tenantouf-lab/ouf.object-storage.content.read, valida fino15settembre2036 e revocabile. Vecchio grant scaduto conservato. Permesso strutturale distinto da token breve e sessione job finita: nessun rinnovo temporaneo ordinario da riproporre.
- M1/G4 acquisiti: due acquisizioni Teatri,26join,13stableID,20proprietà/oggetto,8Cinema preservati. Vecchi percorsi Registry osservati positivi, compreso GET originaleHTTP200; non estendere quella prova al CSV Farmacie senza verifica.
- M2/G5/G6/G7 APERTI. D4 codice e manutenzione V36 installati/provati; flusso HUMAN budget/resume e file-read/profiling target ancora non provati. Non chiudere D4/M2 soltanto da readiness/schema36.
- D5 vocabolari/relazioni e semantica managedCSV, D6 composizione Farmacie e resoconto61righe fino a UDP, D7 ripetibilità/resilienza/fault/coorte/accettazione restano nel piano con riuso del codice/prove già disponibili. Nessuna nuova stima di ore o percentuale inventata.
- Obiettivo dell’operatore: caricamento CSV→UDP fluido e autoguidato. I comandi VPS sono manutenzione eccezionale ora completata, non il flusso ordinario per ogni file.
- Supervisor dopo E2E completo. Nessun merge/release acceptance con questa ricevuta.

## Autorizzazioni e stile operativo persistenti

Autorizzazione a leggere/scrivere tutti i repository GioNob e usare capabilities OUF con account ouf-admin; verificare identità effettiva/link prima di agire. Link storico link_6aafef96b4148191b767e9af7b756a07 è solo riferimento, non prova della connessione corrente. Non sostituire giovanni-chatgpt o chiedere credenziali/token in chat.

Lavorare autonomamente, aggiornamenti brevi, mantenere GitHub aggiornato e fermarsi solo per intervento umano fondamentale. Nessun replay di scope consumati, reset di contatori/budget, nuovo job/upload o terza acquisizione per aggirare blocchi, attivazione non autorizzata, reinstallazione/riavvio Registry worker, approvazione simulata, merge/release acceptance. Niente subagenti/automazioni.

La nuova chat riparte dalla scheda HUMAN del job conservato, NON dall’incertezza dell’allegato e NON da un altro APPLY.

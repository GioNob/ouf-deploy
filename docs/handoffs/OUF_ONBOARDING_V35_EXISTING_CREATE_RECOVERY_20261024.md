# OUF — recupero della CREATE V35 esistente, 24 ottobre 2026

## Stato VPS e confine

Il lettore precedente è CONSUMATO: RETAINED_CREATED_CONFIG_DIFFERENCE_OBSERVED/Exit0, log /home/oufadmin/ouf-v35-retained-reader.ahKgZSQy/operator.log. UNICA differenza osservata: Hostname richiesto stringa vuota, restituito stringa nonvuota. Il valore non è stato stampato; uguaglianza a Id[:12] e stato CORRENTE non sono ancora prove VPS.

Journal255437a61e8b435862e85ddffa5edfef7365a42735301cefffbc299a9d149879, review828d9d6c5f04f8535801e45c2d284a71256232b778b3d6dc14afe6d468e5a94b/authorityaf9a8fbd77a7d5d7caabb436360650eb9ab4ea126684ea15cc70c1fd42f37d63.7APPLIED+CREATECLAIMED, candidato creato e ancora fermo prima di START da quell'ingresso. Cumulativi: EngineGET139/300, POST4/8, SQL5/6, backup2/2, imageLoad1/1, ownerConfig18/32, readiness0/128, negativeStop0/1. Il codice originale a0ce, tutti i file/evidenze/claim e backup restano intatti; nessun rilancio o reset.

## Qualifica completata, non ancora risultato target

Codice immutabile 45842a2dd38a1fde1b25052d5118b9fd9621cb62. Sourceworkflow da274ab3f9cb303e3665fee0213f80979a9ed2e2, sola CI rispetto al prodotto1b1222ceaa5af85a25c20857e7c8c1b548b12dc1/tested194b586508c6661b40a74d9c7f99ed3b876f5fbc; artifact12559990549 originale invariato.

- Push40135450245/job120995893916:3nativePASS in176.191sec+2mainPASS in0.010sec, zeroSkip, log diretto letto.
- PR40135454733/job120995906829:3nativePASS in194.077sec+2mainPASS in0.011sec, zeroSkip, log diretto letto.

Si riproduce davvero il guasto: B0/PG17, archivio CI originale/import, vecchi7stage e CREATE con Hostname vuoto fallita. Poi constructor e operator NUOVI reali, stesso candidato/stesso journal e original invocation lock, nuove firme Ed25519/APPROVO PTY,13APPLIED, V35 esatta e unica, dati review e revisioni conservati,3tentativi/gen4/PAUSED/0sessioni budget,6peer invariati, vecchio fermo. SQL cumulativo6, imageLoad1/backup2 e POST6: nessun vecchio stage ripetuto. Verificatore CI esterno osserva lo STESSO backend PID in entrambe le letture, stato idle e nessuna transazione aperta tra esse, poi connessione chiusa. Decisione terminale errata lascia vecchiojournal immutato/candidato fermo/nessuna authority. SIGKILLcontroller dopo START chiude SQL e ferma SOLO candidato esistente con UNA claim negativa, peer e vecchio intatti. Receipt finale Ed25519 verificata. Nuovi main e vecchio main gestiscono Stop/errore sconosciuto senza traceback o valori sensibili.

Limiti: identità/path/hash privati storici, authority-inputs/bootstrap precedente e osservazione scadenza della vecchia authority sono fixture (clock di prova SOLO nel constructor, ripristinato prima di ogni nuova revisione/firma/esecuzione).5peer sono hold container; PG17 è reale. Il nuovo main è testato per il percorso errore; bootstrap storico completo con i file segreti del VPS non è riprodotto. Non prova guasti host/Engine/reboot, tenuta permanente, E2E o accettazione release. I test Maven omessi nel build della SOLA vecchia immagine fixture non sono test prodotto rivendicati; il prodotto V35 è il precedente artifact già qualificato, non ricostruito.

## Operazione proposta

UN comando: releases/recover-onboarding-v35-existing-create-20261024.sh. Tre file pinned, SHA prima e dopo copia root0700/file0400, log conservato, python -I -B -S; nessun download/rebuild/relabel/load immagine. Bundle b1fea932736097753741ade8d70e0ab5de4fa4a27de585522c71aaa3abea3f4f; rootcodice /etc/ouf/deploy-snapshots/onboarding-v35-created-recovery-code-b1fea93273609775.

Il nuovo scope è SEMPRE created-hostname-recovery-v1 SOTTO la root logica originale, indipendente dall'hash codice. La creazione esclusiva impedisce rilanci. Il vecchio journal non viene inizializzato di nuovo. Prima di effetti: vecchia authority e cleanup scadute, boot identico, review/authority/journal/reader esatti, backup trattenuto riletto e verificato a SHA256; stesso candidato MAI avviato, image/config/HostConfig/mount/endpoint/ownerfile e tutte6generazioni peer correnti. Hostname ammesso SOLO uguale ai primi12caratteri dell'Id esistente, richiesta originale vuota e rete nominativa nonhost; tutti gli altri campi restano esatti. È una mappa esplicita della configurazione effettiva, non una nuova CREATE o una tolleranza per valori arbitrari.

Preflight corrente20GET e2letture dello STESSO owner overlay, nei cumulativi con marker durevoli propri; nessun SQL prima del terminale. File sensibile nominativo /opt/ouf/secrets/onboarding-ths.yaml conserva custodia10003/0400 e antenati nominativamente approvati, nessun chown o eccezione generica. Revisione privata completa fresca e APPROVO hash dal controlling TTY, poi firme dual-role e nuova autorità900sec+30solo negativa, chiavi valide intero930. Controlli correnti ripetuti attorno alla decisione. Nessuna vecchia authority riusata.

Sotto original invocationlock, CAS risolve esplicitamente la CREATECLAIMED con nuova prova corrente e nuovo reviewHash; primi7proof, vecchio intentHash, backup e copia immutabile del vecchiojournal sono conservati. I contatori includono TUTTI i preflight, non ripartono dazero e i massimi non aumentano. Avanza SOLTANTO stage8..12: nessuna seconda creazione/importazione/stop vecchio/backup/disconnessione/rename. Il vecchio eseguibile a0ce non viene modificato in-place e i142sealed rimangono identici.

Watchdog effimero ready/liveness PRIMA di SQL o START. UNA sessione psql residua, due transazioni READ ONLY firmate con BEGIN/ROLLBACK: V34/capacità/privilegi/dati prima di START, V35/checksum/dati/zero budget dopo readiness. Nessuna transazione durante le attese, statement5s/lock1s, sessione limitata alla restante authority≤900sec. Ogni transazione è CLAIMED prima di invio e APPLIED solo dopo JSON verificato e ROLLBACK; nessun reconnect/retry SQL. EOF su parentloss chiude il backend; timeout nel container indipendente dal controller. SQL resta6/6.

Avvio massimo180sec, retry readiness già qualificati e finiti, poi verifica esatta V35/history/schema/source, restartpolicy del solo candidato e receipt finale firmata. Negativa finita ferma SOLO il candidato noto non provato, una volta; nessun vecchio restart/restore/rollback, Registryworker indipendente/intatto. Nessuna GET originale/IAM/OAuth/grant budget HUMAN fonte o attivazione.

Atteso ONBOARDING_V35_EXISTING_CANDIDATE_RECOVERED_SOURCE_PRESERVED/complete=true/Exit0, stessa creazione adottata/nessunreplay, applicationReadinessProven/nativeFlywayHistoryVerified/backupVerified=true, checksum1095739786, sourcePAUSED/3/gen4, budgetSessionCount0/humanBudgetsGranted0/sourceActivations0, cumulativeSQL6, imageLoad1/backup2 conservati, releaseAcceptance=false. JSON issued non è completamento. Incollare SOLO JSON pubblici e Exit/Directory/Log, non review/config/SQL/chiavi/token.

Qualsiasi STOP consuma il nuovo scope: conservare log, marker preflight (anche se il vecchiojournal non è ancora stato aggiornato), journal, backup, authority e receipt. Nessun rilancio con hash nuovo, cambio scope, azzeramento, ripetizione SQL o rollback. Un effetto CLAIMED richiede la SUA riconciliazione esplicita, non replay automatico.

Dopo risultato VPS: nuova decisione HUMAN finita per la FONTE (3tentativi/900sec proposta, NON concessa qui), attivazione distinta stessa source/version/hash con storico/cumulativi/dedup conservati; E2E/F5/F6 e poi Supervisor.502/403 ha già la distinta prova VPS rete+GET originale200, non la chiusura del processo applicativo/E2E.8/8tecnico4/6funzionaleG3OPEN.


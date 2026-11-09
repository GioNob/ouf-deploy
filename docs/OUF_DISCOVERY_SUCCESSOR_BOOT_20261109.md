# Discovery: collegamento del successore al boot

9 novembre 2026. **Staging completato; collegamento al boot tentato e HELD prima della pubblicazione. Provider non avviato.**

La [ricevuta operatore delle 10:56 CET](../evidence/discovery-coordinator-staged-operator-20261109.json) conclude lo staging con `DISCOVERY_COORDINATOR_SUCCESSOR_STAGED_QUIESCED`. Non ripetere quel comando. Il contesto separato è `/etc/ouf/deploy-snapshots/discovery-coordinator-successor-20261109-uz9gw5ny`; il coordinatore attivo storico è BLOCKED, quello preparato QUIESCED senza lease o avvio.

## Pacchetto di attivazione conservato — non rilanciare

Il [controller](../scripts/activate-discovery-coordinator-boot-20261109.py) già pubblicato in `cf2de72e76c83e299348c3dc70de36defacb1039` collega questo esatto contesto ai due comandi systemd di boot e al puntatore letto dal preflight v3. Il [wrapper](../scripts/deliver-discovery-coordinator-boot-20261109.sh) scarica dallo stesso commit e verifica tutti i 14 file prima di sudo.

- SHA-256 controller: `153cd72eff8c50413cafce9875f272cd8eeddfbd4366c4f0e3f894665f8ce8ae`.
- SHA-256 wrapper: `8c1ab3f3b1c640ed1538a2f96a3407ec3a4c660568ed6b81b238e6d5df1191d5`.
- Ricevuta di staging serializzata dal produttore: 1.646 byte, SHA-256 `855e637ce5585269c4eae33b13b23b4b3e1a92c3b305c1d1ba3a6cabfc4ca45f`.

Prima delle modifiche verifica ricevuta e completamento identici, preparazione, sorgenti, vecchio puntatore e driver, journal storico BLOCKED, assenza nativa dei vecchi provider, quattro set vuoti, footprint e impronta esatta attuale. Prende i lock esistenti e richiede i comandi systemd caricati esatti e Docker running senza processo di controllo.

Scrive un intento separato, conserva i file precedenti e prepara un'installazione privata. Cambia soltanto `ExecStart` di `ouf-semantic-boot-guard.service` e il comando selezionato `ExecStartPre` nel drop-in Docker. Se necessario aggiunge la sola directory del successore a `ReadWritePaths` del guard. Esegue `systemctl daemon-reload`, verifica i comandi caricati e il PID Docker invariato; poi pubblica il puntatore e verifica l'osservatore installato. Il lettore preflight v3 resta identico.

**Effetti reali previsti:** due file systemd, un daemon-reload e un puntatore attivo, oltre ai nuovi file privati di evidenza/installazione. Nessun avvio o stop di servizi/container, riavvio Docker, scrittura nft, nuova generazione provider, token, DNS, DB, S3 o richiesta applicativa. I journal e la configurazione runtime storici restano intatti. Il nuovo puntatore seleziona il contesto QUIESCED; il vecchio journal resta BLOCKED.

## Esito da restituire

`DISCOVERY_SUCCESSOR_BOOT_BOUND`, con `loadedBootCommandsVerified`, `dockerPidUnchanged`, `installedObserverPassed` e `activeInstallationPointerChanged` true; `newGenerationAdmitted`, `providerReady`, `leaseAuthorized` e `startAuthorized` false.

Il controller ha limite di 180 secondi. Intento: `/var/lib/ouf-storage-migration/discovery-coordinator-boot-activation-20261109`. **Se HELD, restituire il JSON senza rilanciare.** Un errore dopo l'inizio della pubblicazione conserva i file parziali e segnala `INCOMPLETE_RECONCILIATION_REQUIRED`; non tenta rollback o replay automatico.

## Prove e limiti

[CI push 42599093020](https://github.com/GioNob/ouf-deploy/actions/runs/42599093020), job 129098851349, sul sorgente esatto: **9 test unitari e 3 nativi PASS, zero skip; log letti**. Anche la [CI PR](https://github.com/GioNob/ouf-deploy/actions/runs/42599102979) è SUCCESS. I 9 test unitari sono stati rieseguiti durante la ripresa della chat. Le prove native verificano pubblicazione privata, guard owner originale e nft reali, rifiuto di file estranei e conservazione dei parziali dopo verifica caricamento fallita.

**systemd è simulato in CI.** L'intero controller, il caricamento reale delle unità e l'osservatore sull'installazione VPS restano da verificare con questa esecuzione. Nessun reboot reale è provato; il passo non qualifica una nuova generazione né la ripresa successiva a perdita della generazione nft. L'osservatore è legato ai file e alla struttura dello staging corrente: non promette readiness dopo un futuro boot. Restano ammissione della nuova generazione provider, credenziale/TLS Semantic, backlog/grant, installazione MCP PR84 e discovery applicativa. F2–F6 aperti.

## Diagnosi del blocco delle 11:24 CET

La [ricevuta operatore](../evidence/discovery-successor-boot-held-operator-20261109.json) è HELD prima di intento, pubblicazione, daemon-reload o cambio puntatore. Le verifiche precedenti sono state attraversate in quella invocazione; questo non è un'attestazione dello stato live successivo.

La riga 170 combina quattro condizioni: proprietà richieste tutte presenti e nessuna extra; LoadState=loaded; NeedDaemonReload=no; ControlPID=0. Non conserva il dettaglio fallito. Non eseguire un daemon-reload alla cieca. L'ipotesi iniziale sui valori vuoti non è provata: nel [sorgente systemd v252](https://github.com/systemd/systemd/blob/v252/src/systemctl/systemctl.c), l'opzione --property abilita BUS_PRINT_PROPERTY_SHOW_EMPTY. Non basta aggiungere --all per dichiarare il difetto risolto.

Il [lettore mirato](../scripts/read-discovery-boot-systemd-20261109.py) esegue quattro systemctl show: ciascuna delle due unità prima col comando originale e poi con --all. Restituisce soltanto nomi delle proprietà mancanti/vuote, sei campi di stato e le condizioni fallite. Non emette ExecStart/ExecStartPre, percorsi o credenziali. Nessuna modifica di unità, reload, start, stop, richiesta applicativa o lettura di file credenziali. Ogni comando ha timeout 15 secondi e uscita massima letta 65.536 byte; osservazioni sequenziali non atomiche. File temporanei anonimi per contenere l'output del processo.

Verifica locale con subprocess simulato: proprietà omesse/vuote, reload pendente, ControlPID attivo, proprietà ancora assente con --all, oscuramento dei comandi e argv limitato alle letture. PASS; non è una prova systemd reale. Controller e wrapper di attivazione restano invariati. Eseguire soltanto il lettore e restituire il JSON; l'esito SYSTEMD_BOOT_PREDICATES_READ significa lettura conclusa, non autorizzazione di attivazione.

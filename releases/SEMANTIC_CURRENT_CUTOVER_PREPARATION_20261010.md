> **11 ottobre, continuazione dopo R12 attivo:** il vecchio comando R10 riportato qui resta sospeso. Usare soltanto la [nuova preparazione qualificata contro R12](CSV_END_TO_END_AFTER_R12_20261011.md), dopo aver letto il suo perimetro. [Ricevuta R12](../evidence/resilient-r12-active-target-20261011.json). Non riapplicare R10/R11/R12.

> **Policy di piattaforma vigente:** [Resilienza, quarantena, incidenti e alert — v3](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md). Obbligatoria per sviluppo e revisione; [adozione e prove](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_ADOPTION.md).

# Cutover Semantic: avanzamento autonomo e prossimo passaggio protetto

## Risultati acquisiti il 10 ottobre 2026

L'utente ha delegato le decisioni tecniche alle22:51:27 CEST, chiedendo autonomia e confronto continuo con i PET. Questa delega autorizza il lavoro tecnico; non diventa una ApprovalDecision HUMAN/THS, un grant di dominio o una pubblicazione semantica.

[Evidence strutturata completa](../evidence/semantic-autonomous-cutover-progress-20261010.json) riunisce le prove nominate qui. I dati del VPS sono stati acquisiti autonomamente dal runner esistente. Sono osservazioni puntuali e non autorità di cutover.

| Ambito | Prova e risultato | Limite |
|---|---|---|
| Pacchetto Semantic corrente | [CI38085528129](https://github.com/GioNob/ouf-deploy/actions/runs/38085528129): ZIP e config ImageId esatti; JAR0897e392…; startup Spring, IAM reale di fixture, positive Search e7 rifiuti per ciascun avvio; V10 e restore di snapshot con scritture successive, storico preservato | Fixture isolata; provider/discovery worker disabilitati; vecchia applicazione non rieseguita in questa prova; nessuna salute del provider target dimostrata |
| File secret | Lo stesso JAR avvia con password DB da configtree obbligatorio, senza password nell'environment applicativo; secret/configtree mancante impedisce avvio | Proiezione locale preparata; integrazione OpenBao/secret manager piattaforma ancora da chiudere |
| Host e servizio R10 | [Runner38085676564](https://github.com/GioNob/ouf-deploy/actions/runs/38085676564): R10 active/running, PID2201693, restartno,0 riavvii, ExecStart del suo snapshot; Semantic originale PID3789123 e immaginef6525f…; circa11GB RAM disponibili e466GB disco libero | Nessuna lettura nft o snapshot root; membership/liveness continua non dimostrate; readiness/capacity non accettate |
| Database applicativo | Stesso runner:23 relazioni, V1–V9 più la riga baseline Flyway senza versione;10 sessioni del solo Semantic;0 prepared transactions, large objects, subscription o relazioni fuori schema; ruolo applicativo non superuser | Visibilità dell'account applicativo incompleta; nessun fence/backup |
| Scope amministrativo esistente | [Runner38086062418](https://github.com/GioNob/ouf-deploy/actions/runs/38086062418): PostgreSQL17.11, database OID21558, superuser esistente autenticato dall'identità OS PostgreSQL/socket locale, canale fuori dal DB applicativo, visibilità completa, fsync/synchronous_commit on,10 sessioni | Non sono state terminate sessioni, creati grant o installati fence |
| Preparazione protetta | [CI38086191419](https://github.com/GioNob/ouf-deploy/actions/runs/38086191419):17 verifiche distinte qualificate;16 nella suite ordinaria, più il test POSIX eseguito realmente nella suite root di9 test; source/download/hash drift, frame, env, mount, authority e native-command denial | Compilatore qualificato; preparazione protetta sul VPS ancora da eseguire |

Le tre nuove immagini Semantic/Ingestion/UDP non risultano importate nel motore target. Il container Semantic originale usa ancora `RestartPolicy=unless-stopped` e limite memoria0. Il nuovo intento disabilita il riavvio automatico; il budget di memoria e l'ammissione completa delle risorse rimangono gate prima del cutover. Non sono stati modificati container o database. Cinema8/8, Teatri e R10 consumata restano preservati.

## Confronto PET e decisioni

- Semantic1.3 §16 e configuration reference §160.10: secretRef/workload identity, non credenziali in config plaintext. La receipt della dichiarazione qualificata mostrava `OUF_SEM_DB_PASSWORD` ereditata. Il nuovo intento la rimuove dall'Env candidato e usa un file readonly UID/GID10001,0400, in directory0500. La password è copiata dalla binding già approvata, non ruotata. Il frame originale privato rimane custodito per audit/recovery.
- Semantic1.3 §24: readiness include DB e migrazioni; sono state qualificate quelle del pacchetto corrente, senza promuovere prove del precedente b1a795… alla nuova immagine e826bd….
- Authorization1.5 §7.2 e §23.1: default deny e audit minimo. Nessun grant emesso, log pubblico senza valori segreti, nessun globale NOLOGIN o cambio pg_hba; metadata/read-only transaction usano le identità già disponibili.
- Semantic1.3 §74: approvazione/pubblicazione ACTIVE restano umane e owner-enforced. Le prove IAM positive/negative non autorizzano adoption/publish di dominio.
- OCI/peer e transport devono essere vincolati alla generazione nuova, con recupero consapevole delle migrazioni. Il nuovo candidato usa restartno nell'intento; nessun restart dell'app originale o R10 è stato eseguito. Non abilitare boot/restart automatici sulla sola base di queste prove.

## Perché serve ora l'operatore

È stata tentata la preparazione esatta tramite il runner, usando soltanto i privilegi sudo non interattivi già disponibili. [Run38086291549](https://github.com/GioNob/ouf-deploy/actions/runs/38086291549) ha fermato sudo prima dell'esecuzione del programma: exit1, hash stderr9b3a3b7a… esattamente corrispondente a `sudo: a password is required\n`. La conclusione success del workflow significa che il limite è stato rilevato; **non** significa preparazione eseguita. Nessuna password è stata cercata o inviata e nessun permesso è stato ampliato.

Questo è il solo intervento manuale richiesto ora. Il comando raggruppa:
1. Verifica immutabile della nuova dichiarazione privata78dc… e del programma R10 consumato.
2. Lettura del worker R10, servizio e generazione, native lease nft in secondi, shared guard/provider OCI e peer Semantic reciproco, senza acquisire il lock di rinnovo.
3. Confronto del frame applicativo completo corrente con il frame storico approvato e controllo dei tre file role-owned (credenziale workload, MAC discovery, truststore) per bytes/hash/UID/GID/mode. Le chiavi vengono lette solo in memoria per la verifica, mai stampate o firmate.
4. Nuovo snapshot root0700: file DB readonly per UID10001, Env candidato senza password, import configtree obbligatorio, un bind readonly aggiuntivo e RestartPolicyno. Reti, risorse e altri HostConfig sono conservati; nessun mount viene installato.
5. Receipt pubblica con hash e osservazioni; tutte le prove dovranno essere riverificate nell'applicatore al momento della mutazione.

Non esegue provider/DNS request, query DB, nft write, import immagine, stop/start container o alterazione dei claim. La lettura stabili-riletture non è una transazione atomica con il worker R10: drift o una corsa di aggiornamento bloccano il passaggio prima di concedere autorità. Non aggirare un blocco cambiando hash.

## Comando immutabile

Delivery527710b438fc777428cb9f5e5a6b98c62852231e; compilatore7584cbdc369cdc7f4cf042e36e05914de5192e54, SHA2569aca6a4c…; helper custodycb9ff646…. Eseguire come oufadmin:

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-current-cutover-inputs-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/semantic-current-cutover-inputs-20261010.sh?ref=527710b438fc777428cb9f5e5a6b98c62852231e' > "$OUF_LAUNCH"
  printf '%s  %s\n' '66f5c02dbb774f18b74c5429125a2f6c9b869d6b473474b4403facc34028413b' "$OUF_LAUNCH" | sha256sum -c -
  /usr/bin/bash "$OUF_LAUNCH"
)
```

Restituire output completo fino a `OUF_CURRENT_CUTOVER_INPUTS_EXIT`. Successo atteso: `CURRENT_INPUTS_AND_FILE_SECRET_DECLARED_NOT_APPLY_READY`, exit0. Non è un comando di cutover e non ripete R10. Anche dopo un successo, la nuova dichiarazione resta `productionApplyReady=false`.

## Continuazione

Usare lo snapshot protetto appena compilato per comporre il cutover generazione-bound e il trasporto firmato/coordinato con R10, con fence writer, backup fresco, host/OCI/resource admission, recovery governato e readiness IAM/provider. Non riusare la precedente autorità di installazione o il vecchio peer quando una ricreazione cambia generazione. Nessuna inversione automatica verso il vecchio peer se non è più vivo; nessun restore pre-migrazione sopra scritture successive.

F10 file-loop completo, F11 installer riusabile e accettazione piattaforma restano aperti. Files prima dell'API verticale PULLv2.3. Contributi di questo passaggio: prove specifiche, reader autonomi, preparazione integrata e consegna qualificata; non un applicatore di produzione già accettato.

## Esito operatore ricevuto l'11 ottobre 2026, 02:59 CEST

Il launcher e i due sorgenti hanno superato i checksum. La preparazione root ha restituito exit1, `CURRENT_CUTOVER_INPUT_PREPARATION_BLOCKED`, fase `VERIFY_CURRENT_R10_AND_RETAINED_APPLICATION_FRAME`, motivo `CURRENT_R10_PRIVATE_WORKER_UNPROVEN`. [Receipt completa](../evidence/semantic-current-cutover-inputs-blocked-target-20261011.json). Nessuna operazione lifecycle/import/database/firewall/configurazione esistente, nessun lock comune e R10 non toccato. La proiezione file secret e la nuova dichiarazione non sono state preparate. Il precedente comando di preparazione è sospeso: non ripeterlo prima della diagnosi.

Il controllo richiede lo stato scritto dall'activation_core R10: `LEASE_ACTIVE`, refreshCount intero>=2 e workerPid intero. La ricevuta generica non distingue uno stato FAILED/QUIESCED da altri dati mancanti; non dimostra ancora la causa. È necessaria una lettura protetta di worker-status/worker-denial e delle sole proprietà systemd. Il nuovo osservatore `scripts/read-current-r10-denial.py` legge soltanto i due file root0600 con ancestry/nlink/no-follow/limite dimensionale, proietta codici e conteggi consentiti e legge systemctl senza journal, chiavi, credenziali, lock o mutazioni. Tre prove locali passano, inclusi esclusione messaggi privati, stati e limiti di tipo/catena. SHA25698f83e645812ae7e215a0a30a7be50a7bc112a916dc1d0c79cbaba6182f88c5a. La diagnosi non autorizza un nuovo start: claim R10 resta consumato, nessun replay/restart/reset/enable.

## 11 ottobre 2026, 03:06 CEST — R10 fallito dopo250 rinnovi

Ricevuta diagnostica operatore: servizio failed/exit-code, MainPID0, NRestarts0, Restartno. worker-status e worker-denial hanno lo stesso SHA25696f10ca10c9f9409bb6fff310cc58886b58421b9bd2292ddaf3142fb61a9b05a, stato LEASE_WORKER_FAILED, refreshCount250, exceptionChain NFT_SET_TTL_UNPROVEN e doNotRerunApplytrue. [Receipt](../evidence/finite-r10-worker-failed-target-20261011.json). Questo sostituisce l'osservazione storica active/running: l'attivazione iniziale era riuscita, ma non dimostra durata continua. Nessun riavvio/replay/reset del claim. Il controllo nft raggruppa TTL non intero/non positivo/oltre leaseSeconds e indirizzo duplicato: senza i dettagli non va attribuita una causa specifica. Revoca effettiva e set correnti non sono ancora provati da questa ricevuta.

La prima proiezione diagnostica ometteva il nftReadback già previsto da activation_core. L'osservatore aggiornato ne espone esclusivamente sei campi tipizzati (famiglia, indice flusso, tipo/valore expires, duplicato, leaseSeconds), senza indirizzi/valori privati. Inoltre esegue in memoria il reader.py R10 installato, solo dopo verifica SHA2564ddfda694150771fc8059ce22080a44c1d42db80c4f85b6b42f85c46442536d2, per la proiezione networkLease corrente mediante collect() di sola lettura, senza lock comune o mutazioni. Quattro test passano, inclusi TTLzero diagnostico e rifiuto estensioni private. SHA256 sorgente aggiornato f7ab09f97d4d97b4616e07ca14ee3e0ea4191def6fc46032f22e4a972198a9ef. Non modifica il backend o attenua i suoi predicati; preparazione/cutover restano sospesi in attesa della diagnosi completa e prova di quiescenza.

## 11 ottobre 2026 — revoca nativa confermata e difetto riprodotto

La diagnosi operatore ricevuta alle03:08:55 CEST prova il rifiuto preciso: inet/provider_1, expiresTypeint, expiresValue0, duplicateAddressfalse, configuredLeaseSeconds30. R10 ha effettuato250 rinnovi e poi si è fermato senza riavvii. Il journal corrente è QUIESCED, leaseAuthorizedfalse, startAuthorizedfalse; entrambi i flussi hanno0 indirizzi approvati e0 membri inet/bridge. Struttura nativa verificata, journal/membership coerenti, hash journal a58f0cb6e011879fc22723356d19926adf8945c38dcdbf2d21ab3fa34dd6f7f1. [Receipt completa](../evidence/finite-r10-native-quiescence-target-20261011.json). Si tratta di osservazione puntuale, non salute applicativa/acceptance.

[CI38101012511](https://github.com/GioNob/ouf-deploy/actions/runs/38101012511), sorgente4c044ec2b22e328da690b6951d4e910e79426aba, job114356768291 SUCCESS: quattro test di aritmetica/deny dell'intero batch e regressione con nft reale in namespace isolato. Il compiler corrente ammette1secondo; nft riporta0 e il backend R10 invariato emette NFT_SET_TTL_UNPROVEN. Il candidato readback_margin_compiler.py rifiuta piani sotto2secondi senza estendere il TTL; il piano2secondi è letto come1positivo in entrambe le famiglie, poi revocato con set vuoti. [Evidence CI](../evidence/finite-lease-readback-margin-qualified-20261011.json). Riproduce un meccanismo compatibile con l'incidente: la ricevuta target non conserva il piano che originò l'elemento o la latenza, quindi NON dimostra che il target avesse installato esattamente1secondo anziché raggiunto zero per ritardo.

Decisione PET: mantenere default-deny e allowlist indipendente dalle route (Gateway1.5 T11.3, GW-NET-01/02/04); mai accettare/arrotondare/estendere TTLzero, mai aggiungere endpoint o risoluzioni storiche. Il candidato modifica solo l'ammissione del piano, non modifica fonti R10 installate, claim, configurazione owner, profilo DNS o grant. Non è una correzione completa della disponibilità: lease molto brevi vengono ora rifiutati prima dell'installazione, e preemption/readback lento può ancora esaurire una lease valida. Servono una qualificazione completa della nuova chiusura worker, politiche versionate dei budget/retry e prove di cache DNS decrescente, risposte persistentemente inutilizzabili, controllo configurazione lento e scadenza durante le letture. Solo dopo si prepara una nuova attivazione finita, con nuovo claim/unità e decisione propria; R10 resta consumato.

Preparazione secret-file e cutover applicativo sospesi. Nessun comando di applicazione/riattivazione viene proposto con la sola prova del compiler candidato. Non ripetere i launcher R9/R10 o il precedente launcher di preparazione.

## 11 ottobre 2026 — worker candidato qualificato in fixture e prossimo intake protetto

[CI38101472898](https://github.com/GioNob/ouf-deploy/actions/runs/38101472898), sorgente113dcfeedb2a885ac0ef82814ebbdcb9b0ba4d00, job114358105225 SUCCESS. Quattro test del compiler e tre scenari nativi: riproduzione timeout1s→expires0/rifiuto candidato; worker reale con nuovo hash compiler, DNS/systemd/nft, due cicli freschi, TTLzero persistente, revoca e replay negato; altro worker isolato con DNS TTL4 positivo ma margine insufficiente, rifiuto prima dell'ammissione kernel e revoca/replay negato. Entrambe le chiusure fixture preservano fonti storiche e vecchio claim sintetico. [Evidence](../evidence/finite-lease-readback-margin-worker-qualified-20261011.json). Metadata Docker e decisione sono sintetiche CI: non prova nuova chiusura target, disponibilità prolungata, salute applicativa o acceptance. La prima prova worker38101274234 fallì per prefisso snapshot errato nella fixture; il vincolo del worker è rimasto invariato e la fixture corretta è stata rieseguita con successo.

Per costruire il prossimo recupero servono gli hash privati esatti di claim/autorizzazione/receipt R10 e una verifica attuale di chiusure driver/OCI/peer. Non si ricavano dalla sola receipt pubblica. `scripts/read-new-finite-recovery-preflight.py`, sorgente immutabilee3008220b671f7bd81ce18a079202f29e7b03a34, SHA25612359da3c9e5d65c2800b1a9290434a8a27d4e805a6cfc0fe07554600a278984: quattro test locali su consumo, assenza di autorità start/restart/boot/lifecycle, binding owner/service/programs e rifiuto claim straniero. Fonte read-only già usata per la custodia R10; reader installato eseguito in memoria solo dopo verifica di tutti i sette hash. Rilegge artifact stabili e current collect_cutover, richiede quiescenza con journala58f0cb6… e R10 failed/MainPID0/Restartno/NRestarts0. Nessun lock, firma, DNS/provider call, scrittura root, nuovo claim, servizio o traffico concesso. Bootstrap isolato verifica hash prima e dopo sudo.

Lettura root non eseguita automaticamente: l'account runner richiede password sudo, già provato senza alterare permessi. Output atteso `OUF_NEW_RECOVERY_PREFLIGHT`, stato `NEW_RECOVERY_INPUT_BINDINGS_CAPTURED_NOT_APPLY_AUTHORITY`; può negare per drift e resta sempre productionApplyReadyfalse/newStartAuthorizedfalse. Questo comando raccoglie solo i vincoli per preparare un recupero distinto; non è un apply o un ApprovalDecision semantico.

**STORICO — COMANDO SOSPESO DAL11 OTTOBRE2026: non eseguire. La nuova chiusura resiliente richiede preparazione e qualificazione proprie.**

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_READ="$(mktemp "$HOME/ouf-new-recovery-preflight.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
    'repos/GioNob/ouf-deploy/contents/scripts/read-new-finite-recovery-preflight.py?ref=e3008220b671f7bd81ce18a079202f29e7b03a34' > "$OUF_READ"
  printf '%s  %s\n' \
    '12359da3c9e5d65c2800b1a9290434a8a27d4e805a6cfc0fe07554600a278984' \
    "$OUF_READ" | sha256sum -c -
  sudo /usr/bin/python3 -I -B -c '
import hashlib, sys
with open(sys.argv[1], "rb") as f:
    source = f.read(65537)
if hashlib.sha256(source).hexdigest() != "12359da3c9e5d65c2800b1a9290434a8a27d4e805a6cfc0fe07554600a278984":
    raise SystemExit("PREFLIGHT_SOURCE_HASH_MISMATCH")
exec(compile(source, "<qualified-recovery-preflight>", "exec"), {"__name__": "__main__"})
' "$OUF_READ"
)
```


## 11 ottobre 2026 — resilienza predefinita e recupero limitato qualificato

Decisione dell'owner: pausa e retry incrementali finiti sono il default di tutto OUF, anche quando una dipendenza resta indisponibile per ore. [Politica v1](../docs/OUF_RESILIENCE_POLICY.md), registrata anche negli AGENTS.md dei sette repository: 5/15/60/300/900 secondi, jitter fino al20%, massimo128 tentativi e24ore per operazione/incidente; prevale il primo limite. Profili specifici versionati, Retry-After rispettato, checkpoint/budget persistenti, nessun reset al riavvio. Revoca, integrità, generazioni/configurazioni mutate ed esiti ambigui non diventano retry permissivi.

[CI38102725541](https://github.com/GioNob/ouf-deploy/actions/runs/38102725541), commit587d436b972def56911c01d80d3bb1e0b5611035, job114361821303 SUCCESS:16 test del controller/journal POSIX e prova nativa DNS/nft con quattro ore virtuali di indisponibilità.21 tentativi nel percorso nativo, set sempre vuoti nella pausa, riapertura con nuove risposte DNS e TTL strettamente positivo in inet/bridge; revoca durante la pausa impedisce ulteriori query. Lock lease assente durante DNS e attese; journal riaperto senza reset; vecchio claim/fonti preservati. CI adattiva sullo stesso commit38102725565 SUCCESS. [Evidenza e limiti](../evidence/bounded-resilient-lease-qualified-20261011.json), [integrazione richiesta](../docs/OUF_RESILIENCE_IMPLEMENTATION.md).

Qualificazione di recupero isolato con scope/metadata sintetici, non quattro ore reali di uptime né worker target completo. Il nuovo controller restituisce il controllo al normale owner dopo il recupero: il supervisore di rinnovo, la nuova autorità live e la chiusura source/command/OCI/peer target devono ancora essere collegati e qualificati. Gli errori di custodia/journal impediscono nuovi tentativi e richiedono gestione osservabile dall'entrypoint, senza auto-ripristino del budget. Nessun apply, restart, enablement, lifecycle applicativo o modifica VPS.

**Il comando root preflight precedente è sospeso e non va eseguito ora.** Rimane storico; non è un'autorizzazione di recupero. R10 resta consumato, failed/QUIESCED secondo l'ultima osservazione operatore; non riavviare/ripetere R9/R10. Preparazione secret-file e cutover restano sospesi. Il seguito prepara una nuova chiusura resiliente distinta, preservando Cinema/Teatri, default deny e authority HUMAN/THS dei PET.


## 11 ottobre2026 — policy di piattaforma v2 e prima tranche HUMAN integrata

L'owner ha confermato quarantena persistente, isolamento dello scope indipendente, budget finiti, nuovi budget concessi da HUMAN, sessioni atomiche/fencing, capacità protetta e recupero graduale. [Policy v2](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md) e AGENTS.md aggiornati nei sette repository; [registro di adozione](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_ADOPTION.md). Riferimenti PET/AWS nominati nel documento, nessun nuovo broker/incident service o grant di dominio implicito.

[Ingestion PR34](https://github.com/GioNob/ouf-ingestion-runtime/pull/34) integrata in main, merge6f583ca6b226a63c4a9b55df19f28728c4fd9348. Candidato qualificato80bcb2f8c1f478c0b6d18c46b9eeff5cede5f68f: [PostgreSQL38104209271](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38104209271), job114366142916,35 test PASS inclusi16 nuovi; [module38104209251](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38104209251),134 test senza errori/failure e controlli supply-chain/nonroot/DR SUCCESS. Tutti gli altri gate owner/pairwise/serving/publication/GIS/continuity sullo stesso candidato sono SUCCESS. [Evidenza](https://github.com/GioNob/ouf-ingestion-runtime/blob/main/evidence/human-recovery-budget-qualified-20261011.json).

V15 additiva introduce un ledger di sessioni, non reset del budget storico. La ripresa originale del run PAUSED richiede HUMAN+capability+tenant+decisionRef e preflight baseline fuori dalla TX; grant/sessione e cambio stato atomici su control_version. Default versionato128 batch owner/24ore, limite100 record/45secondi del loop per batch, una batch recovery posseduta alla volta; limiti finiti personalizzabili. Non è il conteggio di tutti i retry HTTP. Budget verificato prima I/O e pubblicazione; risultato remoto tardivo non avanza handoff/checkpoint. Scheduler non crea nuovi run intorno all'incidente esaurito OPEN, vecchi claim e percorsi unclaimed non aggirano la sessione. Issue risolta soltanto dopo completamento reale e ACK/drain. Dati/checkpoint/lineage/idempotency e storico fallito preservati.

La prima prova38104025072 fallì soltanto per operatore JSON ? nella query di test con JdbcClient; correzione jsonb_exists, senza modificare quel comportamento produttivo, e riesecuzione PASS. La fixture legacy HUMAN_USER è stata allineata a HUMAN+capability del SDK, non rilassata l'autorizzazione.

Adozione completa ancora aperta: retry automatici del worker, budget iniziali/source/publication/dispatcher/replay storico, circuiti/quote multi-run, capacità/retention/backpressure della quarantena e superfici operatore THS/MCP. I rolling counter circuit esistenti non sono nuove concessioni di budget. Nessuna migration/apply sul VPS, cutover, firma o replay R9/R10; precedente root preflight sospeso. Cinema/Teatri e gap PET/F0–F11 preservati. La suite DR prova la fixture nominata, non il recupero dell'intera piattaforma o dei nuovi ledger popolati sul target.


## 11 ottobre 2026 — resilienza v3 e prima tranche Operational Awareness

[Policy canonica v3](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md) obbligatoria, [registro con prove](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_ADOPTION.md) e [piano di allineamento](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_OPERATIONAL_RESILIENCE_PLAN.md). Comprende retry finiti, quarantena/budget umano, un incidente per dipendenza con lavori coinvolti separati, catch-up persistente, crisi su segnali attuali e alert deduplicati.

Integrate MCP PR51, Ingestion PR35 e Gateway PR59: priorità prima dei limiti, recuperi vecchi visibili nel catch-up supportato, conteggi Gateway dell'intera finestra e troncamento esplicito. Prove: MCP full38105960598/race38105960600 e gate sicurezza con0 vulnerabilità raggiungibili dopo aggiornamento Go/dipendenze; Ingestion native21/module137 test; Gateway229 test + APISIX reale. [Evidenza](https://github.com/GioNob/ouf-deploy/blob/main/evidence/operational-priority-qualified-20261011.json).

Restano OPEN cursor/checkpoint operatore, grouping multirun per dipendenza/contatori impatto, detector/quote/capacità, outbox alert e integrazione target multi-owner/autorizzazioni. Reference/fixture e summary di finestra non provano conformità globale o salute corrente. Nessun deploy VPS o email; R9/R10 consumati e precedente preflight sospeso. Le accettazioni precedenti restano preservate.

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

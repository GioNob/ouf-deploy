# Discovery: collegamento del successore al boot

9 novembre 2026. **Collegamento boot completato sul VPS alle 11:42:59 CET. Non ripetere il comando.**

## Risultato VPS concluso

[Ricevuta operatore](../evidence/discovery-successor-boot-bound-operator-20261109.json): DISCOVERY_SUCCESSOR_BOOT_BOUND, phase COMPLETE, puntatore cambiato, comandi caricati verificati e osservatore superato. PID Docker, frame container, staging e contesti storici invariati. ReadWritePaths del guard esteso alla sola directory prevista; daemon-reload effettuato, nessun restart/start/stop o scrittura nft. Il coordinatore selezionato è QUIESCED, lease/start false; provider non pronto e generazione non ammessa.

Installazione: `/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-successor-b3c3uwwt`. Evidenza privata: `/var/lib/ouf-storage-migration/discovery-boot-activation-f_9dwjoh`. Ricevuta nella serializzazione del controller: 1.434 byte, SHA-256 `ffd4362f54b766a25c7afa0dc9f62129284a72b616cfdf518c39a79f64fea585`. I 43 campi sono conservati nel file operatore.

**Intento presente e operazione conclusa: non rieseguire alcuna consegna di questo runbook.** Le sezioni seguenti descrivono il pacchetto storico e i suoi controlli. Il prossimo lavoro è la nuova generazione provider/runtime; la configurazione runtime storica è rimasta invariata e non è riavviabile per effetto del cambio di puntatore.

## Diagnosi e correzione

La [ricevuta delle 11:24 CET](../evidence/discovery-successor-boot-held-operator-20261109.json) è HELD su SETTLED_LOADED_SYSTEMD_UNITS_REQUIRED, prima di intento/pubblicazione. Puntatore e servizi invariati. La [lettura delle 11:33 CET](../evidence/discovery-boot-systemd-operator-20261109.json) identifica la sola proprietà omessa: ExecStartPre del guard, anche con --all. Docker supera i quattro predicati, PID26930; entrambe le unità loaded, NeedDaemonReload=no e ControlPID=0.

Il [controller corretto](../scripts/activate-discovery-coordinator-boot-20261109.py), sorgente `6f378f07921baefd092b0b20b7f6368c0d10dd09`, usa una lettura busctl del solo ExecStartPre del guard quando questo è l'unico campo omesso. Richiede risposta esatta `a(sasbttttuii) 0`: firma tipizzata e zero elementi. Un array popolato, tipo diverso, output troncato, errore o proprietà non disponibile blocca l'operazione. Nessuna equivalenza automatica campo omesso = vuoto. Gli altri campi e il comando ExecStartPre Docker restano obbligatori.

La continuazione richiede la ricevuta originale `/var/lib/ouf-storage-migration/discovery-boot-activation-a2tzafec/result.json`, esattamente 1.195 byte nella serializzazione del produttore, SHA-256 `865ee49a11d64aba5e2e72858cf757511c199e04ffb84948c33fd515ae7c2466`. Un intento di attivazione già esistente continua a impedire l'esecuzione. Non vengono cancellati o riscritti claim, ricevute e parziali. Non riusare il vecchio wrapper.

## Effetti e controlli

Lo [staging delle 10:56 CET](../evidence/discovery-coordinator-staged-operator-20261109.json) resta concluso e non va ripetuto. Contesto separato `/etc/ouf/deploy-snapshots/discovery-coordinator-successor-20261109-uz9gw5ny`, QUIESCED senza lease/avvio; coordinatore storico BLOCKED.

Prima della pubblicazione: ricevuta e completamento staging identici, preparazione e sorgenti fissate per hash, vecchio puntatore e driver, journal storico, assenza nativa dei vecchi provider, quattro set vuoti, footprint e impronta esatta attuale; lock esistenti e comandi systemd caricati esatti. La lettura tipizzata ha timeout15s e resta entro la deadline complessiva180s.

Effetti previsti: nuovo intento privato, conservazione dei precedenti, modifica di ExecStart del guard e del comando selezionato ExecStartPre nel drop-in Docker; eventuale aggiunta della sola directory staged a ReadWritePaths del guard. Un daemon-reload, confronto dei comandi caricati e PID Docker invariato; poi pubblicazione del puntatore e verifica dell'osservatore installato. Lettore preflight v3 invariato. Nessun start/stop di servizi o container, restart Docker, scrittura nft, token, DNS, DB, S3 o richiesta applicativa. Journal/configurazione runtime storici conservati.

## Pacchetto eseguito — riferimento storico

Il [wrapper aggiornato](../scripts/deliver-discovery-coordinator-boot-20261109.sh) scarica e verifica 14 file dal sorgente qualificato `6f378f07921baefd092b0b20b7f6368c0d10dd09`, poi invoca il controller tramite sudo con Python isolato e bytecode disabilitato.

| File | SHA-256 |
| --- | --- |
| Controller | `3538db93c67b230cf5aacdb45250df6c39da5f9727528859b8a91c0bfff2ae48` |
| Wrapper | `f7e009f13e9b64fa451627a3cc5d940940ccfd62f65c9818717130af6778daa8` |

Consegna eseguita dal commit `82b4ce6077ed295331357e54a57a7c8af069ba68`. Esito ottenuto: DISCOVERY_SUCCESSOR_BOOT_BOUND con loadedBootCommandsVerified, dockerPidUnchanged, installedObserverPassed e activeInstallationPointerChanged true. newGenerationAdmitted, providerReady, leaseAuthorized e startAuthorized restano false.

**Se HELD, conservare e restituire il JSON senza rilanciare.** Un errore dopo l'inizio della pubblicazione conserva i parziali e richiede riconciliazione; niente rollback o replay automatico. Intento invariato: `/var/lib/ouf-storage-migration/discovery-coordinator-boot-activation-20261109`.

## Prove e limiti

[CI42602163458](https://github.com/GioNob/ouf-deploy/actions/runs/42602163458), job129109035198, sorgente esatto6f378f07: SUCCESS, log letti. **14 test unitari, 1 test con systemd reale, 3 native pubblicazione/nft PASS; zero skip.** Systemd reale sul runner Ubuntu24.04 riproduce l'omissione dell'array vuoto e conferma la lettura tipizzata; un array popolato è rifiutato. Le unità fixture sono create e rimosse sul runner, mai sul VPS. [Qualifica e limiti](../evidence/discovery-boot-empty-prestart-qualification-20261109.json).

La prova nativa di pubblicazione/nft continua a simulare i metadata systemd; l'intero controller e l'osservatore installato sul VPS sono ora verificati dalla ricevuta operatore delle 11:42:59 CET. Il test reale aggiunto qualifica il difetto concreto di serializzazione, non un cutover VPS o reboot. L'osservatore è legato ai file e alla generazione nft staged. BOOT_BOUND non è provider readiness. Restano nuova generazione provider, credenziale/TLS Semantic, backlog/grant, installazione MCP PR84 e discovery applicativa; F2–F6 aperti.

La [qualifica precedente](../evidence/discovery-successor-boot-qualification-20261109.json) e le ricevute originali restano storiche e inalterate.

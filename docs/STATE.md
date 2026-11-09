# Stato corrente OUF

9 novembre 2026, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile**. Requisiti: 1024 colonne e budget proporzionato al lavoro, discovery OntoPiA del significato delle colonne. Agente principale, esecuzione sequenziale; industrializzazione rinviata.

## Risultato e blocco attuale

**F1 PASS; F2–F6 aperti.** Onboarding e UDP sono collegati a SeaweedFS. Upload e profilo Onboarding sono riusciti; normale operazione lake UDP ed E2E fino al grafo restano da provare.

La [ricevuta delle 09:06 CET](../evidence/discovery-placeholder-removed-operator-20261109.json) conferma **SOUTHBOUND_UNMOUNTED_PLACEHOLDER_REMOVED**: rimosso il solo segnaposto già smontato, senza umount. Frame dei container, journal storici e metadata containerd conservati. Non ripetere il comando concluso.

La quiescenza delle 09:31 CET si è fermata prima di intento o scritture per NFT_INSTALLATION_STRUCTURE_DRIFT. Il [confronto delle 09:48 CET](../evidence/discovery-nft-drift-operator-20261109.json) ha chiarito il caso: **driver e proprietario installato coincidono; il footprint di boot coincide con le tabelle correnti in formato ordinario; la vecchia impronta esatta differisce**. Letture stabili, quattro set vuoti, nessuna modifica. Il formato numerico non risolve la discrepanza. Non è provato quale evento storico abbia cambiato i campi esclusi dal footprint.

Il codice di boot prevede esplicitamente una riconciliazione dopo la perdita della generazione nativa. Riscrivere soltanto lo stato del vecchio journal lascerebbe il controllo esatto incompatibile.

La [preparazione delle 10:46 CET](../evidence/discovery-coordinator-stage-held-operator-20261109.json) si è fermata su `EXACT_DRIFT_RECEIPT_REQUIRED`, prima di intento, creazione del contesto o modifiche. Errore nella consegna: la copia della ricevuta usata per calcolare l'hash ometteva `installedBoot.retainedPreflightFootprintMatches: false`, presente nel JSON operatore. L'omissione riproduce esattamente il vecchio hash; il file VPS non viene riscritto.

La [ricevuta delle 10:56 CET](../evidence/discovery-coordinator-staged-operator-20261109.json) conferma **DISCOVERY_COORDINATOR_SUCCESSOR_STAGED_QUIESCED**: contesto separato creato, guard superato, journal QUIESCED senza lease/avvio. Coordinatore attivo storico BLOCKED, puntatore e servizi invariati, nessuna richiesta applicativa. **Non ripetere lo staging completato.**

**Boot fermato alle 11:24 CET:** la [ricevuta](../evidence/discovery-successor-boot-held-operator-20261109.json) riporta `HELD / SETTLED_LOADED_SYSTEMD_UNITS_REQUIRED` alla riga 170 del lettore `loaded`, prima di intento o pubblicazione. Nessun cambio del puntatore, restart Docker, avvio provider o scrittura nft. L'evidenza privata resta in `/var/lib/ouf-storage-migration/discovery-boot-activation-a2tzafec`.

**Prossima azione concreta:** sola [lettura mirata systemd](OUF_DISCOVERY_SUCCESSOR_BOOT_20261109.md#diagnosi-del-blocco-delle-1124-cet), senza replay del controller e senza daemon-reload. Il controllo riunisce quattro condizioni: insieme completo delle proprietà, LoadState=loaded, NeedDaemonReload=no, ControlPID=0. La ricevuta non identifica quella fallita. Non attribuire il blocco alla sola assenza di `--all`: il sorgente systemd v252 abilita già i valori vuoti quando si usa `--property`. La versione e il risultato del VPS restano da osservare.

La nuova generazione provider resta da preparare/ammettere. L'esito previsto `DISCOVERY_SUCCESSOR_BOOT_BOUND` non prova provider pronto, reboot reale o discovery; lease/start restano false. Il vecchio journal resta BLOCKED. Se HELD, conservare il JSON senza replay: una pubblicazione parziale richiede riconciliazione.

**Altre dipendenze già identificate:** Semantic è running ma provider/worker restano dichiarati disabilitati; credenziale e truststore preparati sono coerenti ma non installati. Certificati validi per data/nome, TLS/issuer non provati. Legacy provider fermo e scollegato, da conservare. MCP PR84 ha qualificato codice e immagine con sei descrittori ACTIVE; non è installata, il VPS resta PR83/INACTIVE. [Stato del controllo di avvio concluso](OUF_DISCOVERY_STARTUP_READ_20261109.md).

## Componenti già aggiornati

| Componente | Esito dell'ultima ricevuta | Prova |
| --- | --- | --- |
| Gateway | 87 route; otto modifiche verificate, 79 conservate | [Ricevuta](../evidence/gateway-analysis-applied-operator-20261108.json) |
| Semantic | V12, readiness 200; corretta la chiave discovery esistente | [Ricevuta](../evidence/semantic-discovery-key-repaired-operator-20261108.json) |
| MCP | PR83/schema 14, readiness 204; strumenti nuovi ancora INACTIVE | [Ricevuta](../evidence/mcp-analysis-ready-operator-20261108.json) |
| Onboarding | 1024, readiness 200; storia e righe Teatri conservate | [Ricevuta](../evidence/onboarding-wide-ready-operator-20261108.json) |
| Ingestion | 1024, readiness 200; storia, sei tabelle e campi stabili delle pianificazioni conservati | [Ricevuta](../evidence/ingestion-wide-ready-operator-20261108.json) |
| UDP | 1024, readiness 200; storia e 59 tabelle conservate, entrambe le reti e truststore preservati | [Ricevuta](../evidence/udp-wide-ready-operator-20261109.json) |

**Non ripetere gli installer completati.** I predecessori e i vecchi writer MinIO restano spenti secondo le ricevute. Onboarding e UDP usano `https://ouf-seaweedfs-stage:9002`. Readiness e CI non dimostrano il percorso funzionale completo a 1024 colonne o E2E. CID, immagini e dettagli sono nel [registro](../releases/storage-functional-status-20261107.json).

## Dati da conservare

Teatri, senza nuovo upload o profilo:

- asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94`;
- profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`, 13 righe e 20 colonne, UTF-8, separatore `;`;
- tutte le 20 colonne OPEN per decisione owner; questa scelta non si estende automaticamente ai dati SUE;
- associazione dei nomi/concetti delle colonne a proprietà con URI condivisi, non enumerazioni dei valori;
- policy :61 nell'ultima lettura; produttore token Semantic ripristinato. Ricerca/lettura locale Teatri via MCP riuscite, 105 statement. Discovery esterna ancora da provare.

## Sequenza rimanente

1. Collegare al boot il contesto coordinatore già preparato; qualificare/ammettere una nuova generazione provider, poi credenziale/TLS Semantic. Segnaposto e confronto nft conclusi; nessun replay dei vecchi CID o journal.
2. Verificare trasporto, identità e backlog prima di abilitare il worker; pubblicare la build MCP con i sei strumenti attivi e grant coerenti.
3. Usare analisi persistente e discovery sul profilo Teatri esistente, associare le colonne a proprietà, completare review THS → Ingestion → UDP e leggere il grafo.
4. Provare il caso ampio su fixture distinto e ripetere il percorso con un secondo CSV senza riparazioni manuali; verificare la ripresa da una nuova conversazione.

Ogni passo richiede un risultato applicativo osservato. Nessuna data finale attendibile è ancora dimostrata. [MiniPET](OUF_STORAGE_MINIPET.md), [budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md), [contratti 1024](OUF_WIDE_OBJECTS_1024_20261107.md), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare o modificare container consultare la [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md); nessuna esclusione globale di MacAddress.

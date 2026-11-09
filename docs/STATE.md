# Stato corrente OUF

9 novembre 2026, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile**. Requisiti: 1024 colonne e budget proporzionato al lavoro, discovery OntoPiA del significato delle colonne. Agente principale, esecuzione sequenziale; industrializzazione rinviata.

## Risultato e blocco attuale

**F1 PASS; F2–F6 aperti.** Onboarding e UDP sono collegati a SeaweedFS. Upload e profilo Onboarding sono riusciti; normale operazione lake UDP ed E2E fino al grafo restano da provare.

La [ricevuta delle 09:06 CET](../evidence/discovery-placeholder-removed-operator-20261109.json) conferma **SOUTHBOUND_UNMOUNTED_PLACEHOLDER_REMOVED**: rimosso il solo segnaposto già smontato, senza umount. Frame dei container, journal storici e metadata containerd conservati. Non ripetere il comando concluso.

La quiescenza delle 09:31 CET si è fermata prima di intento o scritture per NFT_INSTALLATION_STRUCTURE_DRIFT. Il [confronto delle 09:48 CET](../evidence/discovery-nft-drift-operator-20261109.json) ha chiarito il caso: **driver e proprietario installato coincidono; il footprint di boot coincide con le tabelle correnti in formato ordinario; la vecchia impronta esatta differisce**. Letture stabili, quattro set vuoti, nessuna modifica. Il formato numerico non risolve la discrepanza. Non è provato quale evento storico abbia cambiato i campi esclusi dal footprint.

Il codice di boot prevede esplicitamente una riconciliazione dopo la perdita della generazione nativa. Riscrivere soltanto lo stato del vecchio journal lascerebbe il controllo esatto incompatibile.

La [preparazione delle 10:46 CET](../evidence/discovery-coordinator-stage-held-operator-20261109.json) si è fermata su `EXACT_DRIFT_RECEIPT_REQUIRED`, prima di intento, creazione del contesto o modifiche. Errore nella consegna: la copia della ricevuta usata per calcolare l'hash ometteva `installedBoot.retainedPreflightFootprintMatches: false`, presente nel JSON operatore. L'omissione riproduce esattamente il vecchio hash; il file VPS non viene riscritto.

La [ricevuta delle 10:56 CET](../evidence/discovery-coordinator-staged-operator-20261109.json) conferma **DISCOVERY_COORDINATOR_SUCCESSOR_STAGED_QUIESCED**: contesto separato creato, guard superato, journal QUIESCED senza lease/avvio. Coordinatore attivo storico BLOCKED, puntatore e servizi invariati, nessuna richiesta applicativa. **Non ripetere lo staging completato.**

**Boot fermato prima della pubblicazione:** la [ricevuta delle 11:24 CET](../evidence/discovery-successor-boot-held-operator-20261109.json) riporta HELD senza intento, cambio puntatore o servizi. La [lettura delle 11:33 CET](../evidence/discovery-boot-systemd-operator-20261109.json) identifica l'unico campo omesso: `ExecStartPre` del guard, anche con `--all`. Docker supera tutti i predicati, PID 26930; nessun reload pendente o processo di controllo. Sono osservazioni dell'operatore, non dello stato live attuale.

**Prossima azione concreta:** eseguire la [continuazione corretta](OUF_DISCOVERY_SUCCESSOR_BOOT_20261109.md), sorgente `6f378f07`. Se il solo `ExecStartPre` del guard manca, il controller richiede via busctl il valore tipizzato esatto di array vuoto; non assume che un campo omesso sia vuoto. Tutti gli altri campi e il comando Docker restano obbligatori. La continuazione verifica la ricevuta HELD conservata, richiede intento ancora assente e ripete i controlli correnti prima di due comandi systemd, daemon-reload e puntatore. Nessun restart Docker o avvio provider. CI **14 unitari + 1 prova con systemd reale + 3 native pubblicazione/nft PASS**; l'omissione è riprodotta e un array popolato è rifiutato. VPS corretto pendente; non usare il vecchio wrapper.

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

# Stato corrente OUF

9 novembre 2026, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile**. Requisiti: 1024 colonne e budget proporzionato al lavoro, discovery OntoPiA del significato delle colonne. Agente principale, esecuzione sequenziale; industrializzazione rinviata.

## Risultato e blocco attuale

**F1 PASS; F2–F6 aperti.** Onboarding e UDP sono collegati a SeaweedFS. Upload e profilo Onboarding sono riusciti. La normale operazione lake UDP e l'E2E fino al grafo restano da provare.

La [ricevuta delle 07:24 CET](../evidence/discovery-activation-bindings-operator-20261109.json) identifica gli ostacoli discovery:

- provider v2 e southbound v2 sono entrambi **exited**; le reti condivise risultano configurate, senza prova di connettività;
- Semantic è in esecuzione Java con listener 8080, ma provider/worker sono dichiarati disabilitati e la credenziale provider non ha mount;
- MCP è running con l'immagine attesa; i sei strumenti analisi/discovery sono INACTIVE nel manifesto incorporato. Policy o ENV da sole non li espongono: serve la build con manifesto aggiornato;
- provider legacy è created e scollegato: mantenerlo fermo.

**Prossima azione operatore:** [controllo di avvio v2 pronto](OUF_DISCOVERY_STARTUP_READ_20261109.md). Verifica runtime personalizzato, configurazione/TLS e materiale credenziale già preparato. Non avvia servizi. Due sorgenti e wrapper riletti, dieci test locali con OpenSSL riusciti; nuovo reader non ancora eseguito sul VPS. La precedente lettura è conclusa e non va ripetuta.

## Componenti già aggiornati

| Componente | Esito dell'ultima ricevuta | Prova |
| --- | --- | --- |
| Gateway | 87 route; otto modifiche verificate, 79 conservate | [Ricevuta](../evidence/gateway-analysis-applied-operator-20261108.json) |
| Semantic | V12, readiness 200; corretta la chiave discovery esistente | [Ricevuta](../evidence/semantic-discovery-key-repaired-operator-20261108.json) |
| MCP | PR83/schema14, readiness204; strumenti nuovi ancora INACTIVE | [Ricevuta](../evidence/mcp-analysis-ready-operator-20261108.json) |
| Onboarding | 1024, readiness200; storia e righe Teatri conservate | [Ricevuta](../evidence/onboarding-wide-ready-operator-20261108.json) |
| Ingestion | 1024, readiness200; storia, sei tabelle e campi stabili delle pianificazioni conservati | [Ricevuta](../evidence/ingestion-wide-ready-operator-20261108.json) |
| UDP | 1024, readiness200; storia e 59 tabelle conservate, entrambe le reti e truststore preservati | [Ricevuta](../evidence/udp-wide-ready-operator-20261109.json) |

**Non ripetere gli installer completati.** I predecessori e i vecchi writer MinIO restano spenti secondo le ricevute. Onboarding e UDP usano `https://ouf-seaweedfs-stage:9002`. Readiness e CI non dimostrano il percorso funzionale completo a 1024 colonne o E2E. CID, immagini e dettagli sono nel [registro](../releases/storage-functional-status-20261107.json).

## Dati da conservare

Teatri, senza nuovo upload o profilo:

- asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94`;
- profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`, 13 righe e 20 colonne, UTF-8, separatore `;`;
- tutte le 20 colonne OPEN per decisione owner; questa scelta non si estende automaticamente ai dati SUE;
- associazione dei nomi/concetti delle colonne a proprietà con URI condivisi, non enumerazioni dei valori;
- policy :61 nell'ultima lettura; produttore token Semantic ripristinato. Ricerca/lettura locale Teatri via MCP riuscite, 105 statement. Discovery esterna ancora da provare.

## Sequenza rimanente

1. Leggere i binding di avvio, poi ripristinare il percorso provider/southbound e collegare credenziale/TLS Semantic. Non assumere che il vecchio runtime accetti un semplice restart; non riusare scope consumati.
2. Verificare trasporto, identità e backlog prima di abilitare il worker; pubblicare la build MCP con i sei strumenti attivi e grant coerenti.
3. Usare analisi persistente e discovery sul profilo Teatri esistente, associare le colonne a proprietà, completare review THS → Ingestion → UDP e leggere il grafo.
4. Provare il caso ampio su fixture distinto e ripetere il percorso con un secondo CSV senza riparazioni manuali; verificare la ripresa da una nuova conversazione.

Ogni passo richiede un risultato applicativo osservato. Nessuna data finale attendibile è ancora dimostrata. [MiniPET](OUF_STORAGE_MINIPET.md), [budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md), [contratti 1024](OUF_WIDE_OBJECTS_1024_20261107.md), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare o modificare container consultare la [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md); nessuna esclusione globale di MacAddress.

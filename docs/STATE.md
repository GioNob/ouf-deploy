# Stato corrente OUF

9 novembre 2026, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile**. Requisiti: 1024 colonne e budget proporzionato al lavoro, discovery OntoPiA del significato delle colonne. Agente principale, esecuzione sequenziale; industrializzazione rinviata.

## Risultato e blocco attuale

**F1 PASS; F2–F6 aperti.** Onboarding e UDP sono collegati a SeaweedFS. Upload e profilo Onboarding sono riusciti; normale operazione lake UDP ed E2E fino al grafo restano da provare.

**Collegamento al boot completato alle 11:42:59 CET.** La [ricevuta operatore](../evidence/discovery-successor-boot-bound-operator-20261109.json) riporta `DISCOVERY_SUCCESSOR_BOOT_BOUND`: puntatore attivo aggiornato, comandi systemd caricati verificati, daemon-reload effettuato, osservatore installato superato e PID Docker invariato. Aggiunta la sola directory staged a ReadWritePaths del guard. Frame container, contesti storici e staging conservati; nessun avvio/stop, restart Docker, scrittura nft o richiesta applicativa. È l'esito dell'invocazione osservata, non una verifica live successiva.

Il coordinatore selezionato dal boot è **QUIESCED**, con lease/start false. La configurazione e i journal runtime storici restano invariati. Nuova generazione provider non ammessa e provider non pronto. BOOT_BOUND non prova reboot reale, discovery o E2E. **Non ripetere staging, diagnosi o collegamento boot: l'intento di attivazione è presente e il passo è concluso.** [Runbook completato](OUF_DISCOVERY_SUCCESSOR_BOOT_20261109.md).

**Input della nuova generazione preparati alle 11:55:17 CET.** La [ricevuta operatore](../evidence/discovery-generation-inputs-prepared-operator-20261109.json) conferma entrambi i ruoli e tre file con hash verificati in `/etc/ouf/deploy-snapshots/discovery-generation-inputs-99d46y_j`. Template storici e selezione del nuovo coordinatore sono separati. Quattro percorsi di riferimento a identità storiche per ruolo; nessuna nuova identità o autorità emessa. Coordinatore QUIESCED, puntatore/wrapper/journal invariati, zero CREATE, firme, avvii e richieste applicative. **Preparazione conclusa: non ripetere il comando.** [Runbook](OUF_DISCOVERY_GENERATION_INPUTS_20261109.md).

**Prossimo lavoro di sviluppo:** consumare questi esatti input, costruire il profilo di creazione della nuova coppia e collegarlo al peer Semantic corrente usando aspettative OCI/rootfs indipendenti e i componenti esistenti di creazione/profili/ammissione. I CID nuovi devono provenire da creazioni governate, non da sostituzioni nei journal; transazioni e autorità devono essere nuove. Le osservazioni correnti non diventano da sole aspettative o autorizzazioni. Poi firma iniziale, pubblicazione separata dei profili, switch runtime controllato e avvio con riconciliazione dell'esito. Questo percorso non è ancora qualificato per il VPS; nessun nuovo comando operativo da eseguire ora.

Gli input preparati non sono profili runtime e non attestano ammissione, provider pronto, TLS/issuer o discovery. Non reimpostare DELETED/DELETING e non riavviare i vecchi CID.

Segnaposto nativo, confronto nft, staging e boot sono conclusi; le precedenti ricevute HELD restano nello [storico](OUF_M2_CHECKPOINT_LOG.md). Non riaprire quei passi per preparare la nuova generazione.

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

1. Preparare e qualificare la nuova generazione provider/runtime sul coordinatore collegato al boot, poi ammetterla e verificare credenziale/TLS Semantic. Boot già concluso; nessun replay dei vecchi CID o journal.
2. Verificare trasporto, identità e backlog prima di abilitare il worker; pubblicare la build MCP con i sei strumenti attivi e grant coerenti.
3. Usare analisi persistente e discovery sul profilo Teatri esistente, associare le colonne a proprietà, completare review THS → Ingestion → UDP e leggere il grafo.
4. Provare il caso ampio su fixture distinto e ripetere il percorso con un secondo CSV senza riparazioni manuali; verificare la ripresa da una nuova conversazione.

Ogni passo richiede un risultato applicativo osservato. Nessuna data finale attendibile è ancora dimostrata. [MiniPET](OUF_STORAGE_MINIPET.md), [budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md), [contratti 1024](OUF_WIDE_OBJECTS_1024_20261107.md), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare o modificare container consultare la [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md); nessuna esclusione globale di MacAddress.

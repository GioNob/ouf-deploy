# Stato corrente OUF

10 novembre 2026, Europe/Rome. Priorità operativa **discovery OntoPiA live su schema.gov.it dal chatbot**, senza fallback locale. Agente principale, esecuzione sequenziale. Per ogni effetto sul VPS e per ogni merge serve un sì esplicito di Giovanni.

## Risultato e blocco attuale

**F1 PASS; F2–F6 aperti nel registro funzionale.** Onboarding e UDP sono collegati a SeaweedFS. Il [caso Teatri v4](https://github.com/GioNob/ouf-deploy/pull/56) è concluso fino alla ricerca MCP. I 13 teatri sono stati ricondotti agli UUID storici. Preservare i dati e il kit di quella PR.

**Collegamento al boot completato alle 11:42:59 CET.** La [ricevuta operatore](../evidence/discovery-successor-boot-bound-operator-20261109.json) riporta `DISCOVERY_SUCCESSOR_BOOT_BOUND`: puntatore attivo aggiornato, comandi systemd caricati verificati, daemon-reload effettuato, osservatore installato superato e PID Docker invariato. Aggiunta la sola directory staged a ReadWritePaths del guard. Frame container, contesti storici e staging conservati; nessun avvio/stop, restart Docker, scrittura nft o richiesta applicativa. È l'esito dell'invocazione osservata, non una verifica live successiva.

Il coordinatore selezionato dal boot è **QUIESCED**, con lease/start false. La configurazione e i journal runtime storici restano invariati. Nuova generazione provider non ammessa e provider non pronto. BOOT_BOUND non prova reboot reale, discovery o E2E. **Non ripetere staging, diagnosi o collegamento boot: l'intento di attivazione è presente e il passo è concluso.** [Runbook completato](OUF_DISCOVERY_SUCCESSOR_BOOT_20261109.md).

**Input della nuova generazione preparati alle 11:55:17 CET.** La [ricevuta operatore](../evidence/discovery-generation-inputs-prepared-operator-20261109.json) conferma entrambi i ruoli e tre file con hash verificati in `/etc/ouf/deploy-snapshots/discovery-generation-inputs-99d46y_j`. Template storici e selezione del nuovo coordinatore sono separati. Quattro percorsi di riferimento a identità storiche per ruolo; nessuna nuova identità o autorità emessa. Coordinatore QUIESCED, puntatore/wrapper/journal invariati, zero CREATE, firme, avvii e richieste applicative. **Preparazione conclusa: non ripetere il comando.** [Runbook](OUF_DISCOVERY_GENERATION_INPUTS_20261109.md).

**Lettura delle ricette conclusa alle 12:25:29 CET.** La [ricevuta](../evidence/discovery-generation-sources-read-operator-20261109.json) conferma 25 metadata stabili: entrambe le ricette OCI indipendenti coincidono con le policy installate, senza differenze. Adapter a due reti e southbound a tre, peer reciproci coerenti. L'ingresso Semantic resta il BRIDGE_PORT storico 1377 per 172.18.0.6→172.18.0.14:10443/tcp. Runtime non osservato, zero CREATE/firme/richieste Engine o applicative. **Non ripetere il lettore.** Il sigillo rootfs storico non diventa l'aspettativa del nuovo container.

**Composizione della coppia implementata e qualificata in 11 test CI.** Il [compilatore](OUF_DISCOVERY_SUCCESSOR_COHORT_20261109.md) conserva NIC/MAC, flussi e ricette indipendenti; richiede CID/transazioni distinti, ricompila i frame e collega i due nuovi peer reciproci. Sostituisce 1377 con una dichiarazione Semantic completa, senza inventare un nuovo indice. Produce soltanto una proposta non firmata, non un runtime ammesso.

**Peer Semantic verificato il 10 novembre alle 13:29:10 CET.** La ricevuta operatore riporta `SEMANTIC_PEER_RECIPE_MATCHED_NOT_AUTHORIZED`.
La ricetta indipendente coincide con l'intera configurazione OCI e il collegamento di rete coincide con la dichiarazione.
La lettura ha scritto una directory di evidenza privata e non ha ammesso o avviato la nuova generazione. Il controllo vale per il Semantic osservato.
**Prossimo passo:** preparare la creazione governata della coppia e i nuovi sigilli. Il lettore è concluso. [Runbook](OUF_RETAINED_SEMANTIC_PEER_20261109.md).

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

- **1 — Lettura del peer Semantic.** Conclusa con ricevuta operatore riconciliata. Conservare la dichiarazione per la generazione osservata.
- **2 — Nuova generazione provider/runtime, in preparazione.** Separare la creazione dei due container fermi dall'ammissione. La prima operazione deve produrre due nuovi ID, mantenere gli alias DNS usati da TLS e verificare due reti per l'adapter e tre per il southbound. [Precedente di creazione a container fermi](../releases/PROVIDER_V2_STOPPED_CREATION.md).
  Il controller storico della creazione è vincolato al runtime vuoto di ottobre. L'owner di installazione successivo richiede una sola rete e un Registry creato nella propria finestra. Usare il compilatore già qualificato per la coppia e mantenere i controlli di custodia e proprietà della creazione.
  Prima di ammettere la coppia, associare il peer alla generazione Semantic che monta la credenziale e il truststore. Se cambia la generazione, serve una dichiarazione indipendente e un'osservazione nuova. Verificare credenziale e TLS lungo il percorso verso schema.gov.it prima del passo 3.
  Il 10 novembre alle 13:54:15 CET, il [controllo in sola lettura](../scripts/read-discovery-stopped-creation-preflight-20261110.py) ha restituito `PREFLIGHT_PASSED`, senza scritture. Hash del readback Docker `32e8d5251c68f2d4c0b4b1f0ffe03d550f28bb0d34c50c5da6794486706f1105`.
  Gli IP previsti non hanno endpoint attivi o riserve IPAM visibili. I tre container storici sono fermi, con riavvio Docker disabilitato e senza riferimenti di avvio systemd o Compose rilevati.
  Creazione sospesa prima di qualsiasi scrittura. La ricetta storica del southbound inserisce credenziali nelle variabili Docker, che Docker conserva nei metadati della nuova istanza.
  L’11 novembre è stata preparata la [bozza del comando](../scripts/create-discovery-stopped-candidates-20261111.py). Elimina il segreto OIDC di APISIX dalla ricetta JWT/JWKS e legge la chiave HMAC dal file protetto all’avvio.
  La bozza ripete il controllo IP e alias prima di ciascun CREATE. Le prove locali con dati sintetici coprono la trasformazione delle route, il lancio e il rifiuto di un conflitto IPAM.
  Prossimo passo: qualificare la bozza su Docker e sull’immagine APISIX effettiva prima della consegna operativa. La creazione sul VPS richiede il sì dell’owner.
- **3 — Worker.** Verificare trasporto, identità e backlog, poi abilitare il worker.
- **4 — MCP e accesso.** Installare MCP PR84 con i sei descrittori ACTIVE e predisporre i grant coerenti per ouf-admin con scope `ouf.semantic.discovery`.
- **4-bis — Revisione semantica HUMAN.** La prova live ha restituito il solo riferimento `ths://` e il link costruito a mano ha dato 404. Nel codice Onboarding esiste un ramo semantico di `workflow-review` e il backend `SemanticTrustedHumanApi` espone scheda, decisione e pubblicazione.
  - Rendere raggiungibile e completare la pagina THS con scheda, differenze, approvazione, rifiuto e pubblicazione. Rinnovare la sessione lato server e provare la ripresa dopo la scadenza del token durante una revisione lunga. Verificare separatamente la durata e la ripresa della challenge.
  - Esporre le route northbound Gateway per scheda, decisione e pubblicazione verso l'API esistente, con le rispettive autorizzazioni HUMAN.
  - Restituire da `semantic.review.prepare` l'URL HTTPS diretto generato da OUF per la challenge. Il chatbot usa l'URL restituito dal servizio.
- **5 — Prova applicativa.** In una chat nuova, con ouf-admin, eseguire una discovery MCP reale e leggere stato e candidati OntoPiA con IRI, etichette e versione. Aprire dal link OUF una review, approvare e pubblicare il riferimento, poi provare che `source.onboarding.create` lo accetta in una bozza di prova separata. Mappare anche il profilo Teatri esistente senza creare nuove versioni della fonte.

Ogni passo richiede un risultato applicativo osservato. Nessuna data finale attendibile è ancora dimostrata. [MiniPET](OUF_STORAGE_MINIPET.md), [budget](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md), [contratti 1024](OUF_WIDE_OBJECTS_1024_20261107.md), [cronologia](OUF_M2_CHECKPOINT_LOG.md).

Prima di confrontare o modificare container consultare la [regola MAC](OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md); nessuna esclusione globale di MacAddress.

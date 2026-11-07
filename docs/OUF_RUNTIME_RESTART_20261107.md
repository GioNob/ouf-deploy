# Ripartenza OUF sul VPS

**Passaggio Onboarding → SeaweedFS:** la versione corrente dello script legge il marker del passaggio, usa il nuovo container dopo `ONBOARDING_SEAWEEDFS_READY` e avvia SeaweedFS prima dello stack. Rifiuta un passaggio incompleto o un vecchio owner ancora running. Le versioni precedenti contengono il vecchio ID Onboarding: non riutilizzarle dopo il cambio. [Procedura corrente](OUF_ONBOARDING_SEAWEEDFS_SWITCH_20261107.md). Le sezioni seguenti descrivono il riavvio storico dello stack originale.

Il comando `e2e` riavvia i 14 container originali legati al piano privato del VPS, da PostgreSQL e MinIO fino a MCP. Usa configurazione, immagini, mount e rotte già installati. Dopo l'avvio di Keycloak esegue i cinque servizi host di rinnovo dei token esistenti e riattiva i timer che erano stati fermati per la cattura. Ripristina l'ingresso normale dell'installazione. Se viene interrotto, un nuovo avvio riusa i container già accesi e riparte da quelli fermi con lo stesso binding. In caso di HELD riportare il ruolo e la causa, che il comando rende nel JSON.

Il comando `seaweedfs` avvia la candidata OCI33 con un volume di lavoro distinto e i binding TLS già preparati. Il nome `ouf-seaweedfs-stage` coincide con il certificato. La rete Docker è interna e il servizio non pubblica porte. Ripetere il comando riusa la stessa istanza e lo stesso volume di lavoro. Il JSON di successo attesta l'avvio e TLS sul VPS. Il cambio dei binding di Onboarding, UDP e del percorso di lettura resta un'azione distinta. I dati scritti su MinIO dopo il riavvio non sono presenti automaticamente su SeaweedFS.

I modi usano [lo stesso script](../scripts/ouf-runtime-20261107.py), con un lock condiviso fra `e2e`, `auth` e `mcp` e un lock separato per `seaweedfs`. Esecuzione sul VPS come root con Python isolato. Per l'E2E usare la capability reale di upload e il CSV Teatri. Conservare i riferimenti di asset, onboarding, registry semantico, run di ingestion, merge UDP e verifica del grafo. Il criterio di fine è l'arrivo al grafo con una seconda esecuzione eseguibile dalla stessa procedura. Teatri, Farmacie e Cinema sono fixture. Conservare contratti, rotte, script e configurazione.

## Stato dopo il primo avvio operativo

Il VPS ha confermato `ORIGINAL_OUF_STACK_STARTED` per tutti i 14 ruoli e `SEAWEEDFS_PRIVATE_SERVICE_STARTED`. La chiamata reale di upload come ouf-admin ha ancora restituito MCP `-32603` prima del selettore. Il primo comando non aveva ripristinato i timer host fermati dalla procedura di cattura. Il modo `auth` ripristina solo i cinque rinnovi e timer esistenti, senza riavviare Docker. Il nesso tra i rinnovi e l'errore MCP resta da verificare attraverso l'upload reale. SeaweedFS gira sulla rete privata. L'E2E resta su MinIO fino al cambio dei binding.

## MCP dopo il ripristino dei token

Il VPS ha confermato cinque rinnovi e cinque timer attivi. Il selettore ha ancora risposto MCP `-32603`. La lettura sul VPS ha poi osservato MCP uscito, con Caddy, APISIX, Gateway, Onboarding e Keycloak in esecuzione. I conteggi dei proxy includono 401 e 502 senza correlazione a una singola richiesta. La causa dell'uscita di MCP resta da acquisire.

Il modo `mcp` avvia soltanto il container MCP già installato. L'avvio generale colloca ora MCP dopo Gateway, APISIX e Caddy. Entrambi i modi attendono HTTP 204 su `/health/ready` di MCP nella sua rete. Se il processo esce o non diventa pronto, riportano stato, codice di uscita e categorie del log del solo avvio corrente. L'esecuzione del comando aggiornato sul VPS resta pendente.

# Discovery: dipendenze correnti e attivazione degli strumenti

9 novembre 2026. UDP1024 è installato secondo la ricevuta delle06:58CET. Gli installer completati non vanno ripetuti. Questo passo prepara il percorso Teatri con il profilo esistente, senza nuovi upload, reset o replay.

## Risultato della lettura del codice

Nel candidato MCP installato, source `907ace32100d44a0fcf1fcbda5d713ee7bd8fd94`, i tre strumenti `semantic.discovery.request/status/candidates` e i tre `source.analysis.plan/read/step` sono `INACTIVE` in [capabilities.json](https://github.com/GioNob/ouf-mcp-server/blob/907ace32100d44a0fcf1fcbda5d713ee7bd8fd94/internal/manifest/capabilities.json). Il file è incorporato nel binario da [manifest.go](https://github.com/GioNob/ouf-mcp-server/blob/907ace32100d44a0fcf1fcbda5d713ee7bd8fd94/internal/manifest/manifest.go); il kernel registra soltanto strumenti ACTIVE. Il main legge questo manifesto e lo persiste. Non risulta un override di pubblicazione tramite ENV in questo percorso.

Quindi un grant o un flag ENV da soli non espongono questi sei strumenti: occorre una build con il manifesto aggiornato, oltre ai grant e alle dipendenze operative. Non modificare direttamente il catalogo DB come sostituto del manifesto incorporato. I file del permesso storico di reprocessing scaduto non vanno rinnovati o riscritti per questa attività: `configureReprocessing` conserva metadata scaduti anche attraverso un aggiornamento di catalogo; le relative operazioni restano soggette alla loro verifica.

Semantic source `c2dae77b42f1811b704465f6ab813c91d808ade4` usa client credentials per il gateway provider; richiede endpoint token HTTPS, scope e file credenziale leggibile con custody ammessa. Il provider usa una ricerca lessicale sulle etichette/URI. Non dedurre da questo codice che credenziale, token o rete siano attualmente funzionanti.

## Lettura completata sul VPS

[Ricevuta delle 07:24 CET](../evidence/discovery-activation-bindings-operator-20261109.json): Semantic e MCP running; provider v2 e southbound v2 exited, reti condivise configurate. Credenziale Semantic senza mount; provider/worker dichiarati false. Legacy created/senza reti, da mantenere fermo. Nessuna connettività o autenticazione provata. Prossimo passo: [binding di avvio](OUF_DISCOVERY_STARTUP_READ_20261109.md).

Il reader osserva gli esatti Semantic e MCP delle ultime ricevute; risolve solo i nomi `ouf-semantic-southbound-v2`, `ouf-semantic-provider-v2` e `ouf-semantic-provider`. Sono nomi da verificare, non identità già provate. Se assenti, lo segnala senza pretendere che non esistano provider con altri nomi. Non elenca indiscriminatamente container o file del server.

Produce:
- generazione/immagine/stato, reti condivise e mount dei componenti selezionati;
- dichiarazioni Semantic, presenza dei riferimenti OAuth e soli metadata del file montato;
- tipo del processo iniziale e porte TCP in ascolto nel namespace, con il limite che non sono health check o prova di processo applicativo;
- presenza dei due mount di configurazione APISIX del southbound, senza aprirne il contenuto;
- confronto delle generazioni e dei frame prima/dopo, API1.44 uniforme e nessuna normalizzazione MAC.

Massimo13GET Docker e90secondi per il reader. Nessuna query DB, lettura del contenuto di credenziali/config, richiesta token/provider/business, modifica di servizi o permessi. Le ispezioni selezionate complete restano nella directory privata0600/0700; il JSON pubblico non contiene ENV grezze, argomenti o segreti. Il backlog dei job e il trasporto JVM non vengono provati da questa lettura: saranno verificati prima di abilitare il worker.

## Consegna completata

La lettura è stata eseguita con successo. Il comando storico resta nella versione Git precedente; non ripeterlo per proseguire. La ricevuta documenta zero modifiche e zero richieste DB/token/provider/business.

## Qualifica e limiti

Source `73bb41e5d6165ec704b06cb45c3a198669ebc6e1`, script SHA256 `7f9232b3c2832a57769f0271003b1ce0f2ea57b7e6b0ba266e02dbf6549cc8a7`. Delivery `08e179dbf5cefc415f2eb469d9bbfba2c00cef00`, wrapper SHA256 `5cabf7aa7cece2f7afa13a25e049ad26cfec662d0c277da887cf28f4a05f4a5b`. Tre sorgenti e wrapper riletti byte per byte; sintassi Bash verificata.

Nove test locali, zero errori/skip: redazione, assenze, cambio immagine, variazione frame/MAC, scope GET, parser processi/porte e metadata indisponibili. [Evidenza](../evidence/discovery-activation-bindings-qualification-20261109.json). Il probe diretto /proc nel workspace non era disponibile (FileNotFoundError): non è contato come test nativo riuscito. Nessuna qualifica Docker nativa CI è dichiarata; l'esecuzione VPS è successivamente documentata dalla ricevuta collegata.

## Dopo il risultato

Correggere soltanto le dipendenze effettivamente mancanti, verificare trasporto/credenziale e backlog prima di abilitare il worker. Preparare la build MCP con pubblicazione dei sei strumenti e relativi grant; conservare budget/progresso già persistiti. Poi una discovery di proprietà sul profilo Teatri conservato, mapping delle20colonne, review THS e percorso Ingestion→UDP→grafo. La prova funzionale1024 su fixture distinto resta aperta.

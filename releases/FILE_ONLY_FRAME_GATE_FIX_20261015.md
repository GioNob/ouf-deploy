# Composizione del comando di attesa e del frame — 15 ottobre 2026

## Risultato sul VPS

Il tentativo prepare-only con sorgente912ec9d90015a2742957e49f72bc3a483e759e10 supera tutti i15 controlli preflight. retainedEnvironment=true e historicalDiscoveryJvmTrustOptionRemovedFromProposal=true confermano sul target la correzione dell'ambiente storico. La sessione amministrativa GET è disponibile. Il tentativo si ferma dopo la fase CURRENT_HUMAN_OWNER_AUTHORIZATION_REVIEW con UNRESOLVED_TEMPLATE_SLOT; non produce la review completa e non emette autorità runtime.

Dall'ordine del sorgente fissato si deduce inoltre che il primo controllo del prefisso migrazioni semantic/ruolo bootstrap superuser e quello del bridge selezionato sono stati superati: precedono la compilazione del frame che riproduce l'errore. È una deduzione dal percorso del codice, non un nuovo report SQL indipendente. Le riletture finali e il controllo corrente R12 successivi restano da completare.

## Difetto riprodotto

La sequenza creation → compile_inputs → compile_policy falliva anche localmente senza dati privati del VPS. creation inserisce il comando di attesa preapplicazione esatto, contenente la variabile shell runtime $OUF_APPLICATION_GATE. Il controllo generico b'$OUF_' la scambia per un segnaposto Docker non compilato.

I test precedenti coprivano separatamente la creazione con gate e un frame senza gate. Anche il lettore dell'immagine reale si fermava a FileOnlyProfile: non provava la successiva compilazione completa del frame. Il nuovo test composto fallisce con lo stesso UNRESOLVED_TEMPLATE_SLOT prima della correzione. È un difetto deterministico della preparazione che avrebbe dovuto essere trovato in CI.

## Correzione

Sorgente eseguibile: 951f91c8df3d252c720ffa4f0fc787ff90d91b9e, PR31.

Il wrapper file-only valida il profilo e la corrispondenza esatta degli argv firmati/proposti, proietta i soli due campi argv del comando runtime durante la compilazione generica e ripristina nel risultato gli argv originali byte per byte. La verifica finale esclude dalla scansione soltanto quelle due liste complete ed esatte; rimangono vietati segnaposto residui in ambiente, percorsi, metadata, mount e comandi alterati.

Il compilatore generico compile_creation_frame_policy.py e il comando gated_creation_plan.py restano invariati. Non vengono rinominate variabili, rimossi controlli generali o cambiati i requisiti di rilascio del gate. I sei sorgenti applicativi e il pacchetto esistente non cambiano.

## Qualificazione

- CI nativa [38685001075](https://github.com/GioNob/ouf-deploy/actions/runs/38685001075), job116257719205: **200 test,26 suite,PASS,nessun test saltato**.
- CI immagine reale [38684997298](https://github.com/GioNob/ouf-deploy/actions/runs/38684997298), job116257708073: PASS della sequenza creation → compile_inputs → compile_policy, con fourMountFramePolicyCompiled=true ed exactRuntimeGatePreserved=true.
- La stessa immagine conserva PASS della verifica Java HTTPS predefinita sulla discovery pubblica Keycloak; è una prova CI, non della rete del VPS.
- Verificatore HUMAN38685001079:PASS.
- Casi negativi: segnaposto in ENV, fonte di directory ripristinata e metadati; comando di attesa alterato; argv OCI diverso dagli argv indipendenti. Tutti respinti.
- I112 membri della capsula sono verificati per hash: rispetto alla precedente cambia un solo sorgente selezionato, compile_file_only_frame_policy.py.

La fixture usa i31/19 nomi osservati con valori pubblici ricavati dai sorgenti e valori di test. Il contesto Docker usa i profili SYSTEM_CONTAINERD e VAR_RUN_ALIAS, con identità di sola validazione scartate. Non adotta un OCI osservato, non firma una policy e non dimostra un container sul VPS.

## Consegna e limiti

Capsula SHA256: e2d2ff9ce2dec348754edf977f911aac987a1d22723368571b26586870d50736.
Launcher SHA256: 596bd594af24775ed5b9107199bb781893391c543624728f820bc4395581e084.
Wrapper: releases/chatbot-file-cohort-prepare-frame-vps-20261015.sh.
Wrapper SHA256: d10694b46d642cf11a2804f618b5124e2c4749e4d84f71f5f0274dbdcdf004e2.

Il comando conserva --prepare-only, riusa lo ZIP già scaricato e si ferma a COMPLETE_PRIVATE_REVIEW_READY_NOT_STARTED con reviewPath/reviewHash. Le autenticazioni richieste restano quelle correnti. Non avvia l'installazione e non azzera budget o claim.

Rimane da dimostrare la preparazione completa sul VPS: compilazione intenti/scope, riletture finali e verifica corrente R12, assemblaggio della review privata. Esecuzione reale e accettazione Teatri/seconda sorgente restano fasi successive non dimostrate. Il numero dei test non viene usato come prova del completamento target.

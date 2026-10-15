# Prossimo passo OUF — preparazione privata, aggiornamento 15 ottobre 2026

## Ultimo stato verificato

Il tentativo sul VPS con912ec9d90015a2742957e49f72bc3a483e759e10 ha superato tutti i15 controlli nativi, incluso retainedEnvironment=true. La correzione dell'opzione storica JAVA_TOOL_OPTIONS è dunque confermata sul target. Si è fermato con UNRESOLVED_TEMPLATE_SLOT prima della review completa.

La causa è riprodotta localmente: la variabile runtime $OUF_APPLICATION_GATE nel comando di attesa esatto veniva confusa con un segnaposto Docker. I test precedenti non collegavano creation e compilazione completa del frame. La correzione è nel wrapper file-only; il comando di attesa e il compilatore generico sono invariati. La lettura del prefisso semantic e quella del bridge precedono questo punto e risultano superate per deduzione dal percorso del codice, non come nuovo report SQL autonomo.

## Versione da usare

Sorgente eseguibile: **951f91c8df3d252c720ffa4f0fc787ff90d91b9e** (PR31).
Capsula SHA256: e2d2ff9ce2dec348754edf977f911aac987a1d22723368571b26586870d50736.
Launcher SHA256: 596bd594af24775ed5b9107199bb781893391c543624728f820bc4395581e084.
Wrapper: [chatbot-file-cohort-prepare-frame-vps-20261015.sh](chatbot-file-cohort-prepare-frame-vps-20261015.sh).
Wrapper SHA256: d10694b46d642cf11a2804f618b5124e2c4749e4d84f71f5f0274dbdcdf004e2.

Eseguire il wrapper che pinna questo sorgente, non il preparatore contenuto nella branch delle evidenze PR30. Le versioni precedenti rimangono come storico, non come istruzioni correnti. Il wrapper usa il client gh portatile esistente e riusa obbligatoriamente lo ZIP già scaricato; non modifica i sei pin applicativi o il pacchetto.

- CI nativa [38685001075](https://github.com/GioNob/ouf-deploy/actions/runs/38685001075), job116257719205: **200 test,26 suite,PASS,nessun test saltato**.
- CI immagine reale [38684997298](https://github.com/GioNob/ouf-deploy/actions/runs/38684997298), job116257708073: PASS della sequenza creation → compile_inputs → compile_policy, con fourMountFramePolicyCompiled=true ed exactRuntimeGatePreserved=true.
- La stessa immagine conserva PASS della verifica Java HTTPS predefinita sulla discovery pubblica Keycloak; è una prova CI, non della rete del VPS.
- Verificatore HUMAN38685001079:PASS.
- Casi negativi: segnaposto in ENV, fonte di directory ripristinata e metadati; comando di attesa alterato; argv OCI diverso dagli argv indipendenti. Tutti respinti.
- I112 membri della capsula sono verificati per hash: rispetto alla precedente cambia un solo sorgente selezionato, compile_file_only_frame_policy.py.

La nuova prova su immagine reale esegue l'intera concatenazione creation → compile_inputs → compile_policy, incluso il gate e la custodia futura del token. Usa valori di test e contesti di validazione scartati; non è accettazione del VPS.

## Operazione e risultato atteso

Il wrapper usa --prepare-only. Possono essere necessarie autenticazioni correnti sudo, amministrativa IAM e browser/device. Non inserire password nella chat. Le sessioni e i device code passati non costituiscono autorità riutilizzabile.

Il risultato atteso è COMPLETE_PRIVATE_REVIEW_READY_NOT_STARTED, con reviewPath/reviewHash, runtimeAuthorityIssued=false e targetApplyAuthorized=false. L'installazione non viene approvata o avviata da questa modalità. Staging privato e sessioni di autenticazione sono previsti; nessun budget viene azzerato.

## Accettazione ancora aperta

La review completa sul VPS resta da dimostrare: intenti/scope, riletture finali, verifica corrente R12 e assemblaggio della review. Restano poi applicazione governata e ciclo CSV Teatri: HUMAN/THS, ingestion, ACK durevole, commit/lineage UDP, ricerca chatbot fresca e seconda sorgente MATCH/NOOP. Gli8 Cinema devono essere preservati.

Il CSV Teatri esistente resta asset6609b245-86ed-4315-8ce0-73f2a8555bf3/profile7984c39c-7396-4248-ab0a-f2efc390b49c, versione1,13 righe/20 colonne. La correzione di distribuzione non prova l'end-to-end e non implica una stima affidabile della durata residua.

Dettagli: [analisi del blocco e correzione](FILE_ONLY_FRAME_GATE_FIX_20261015.md), [evidenza target](../evidence/chatbot-preparation-frame-block-20261015.json), [qualificazione](../evidence/file-only-frame-gate-fix-qualification-20261015.json).

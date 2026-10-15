# OUF: preparazione completa acquisita, prossimo passo esecuzione — 15 ottobre 2026

## Risultato target

La preparazione completa sul VPS è PASS per il sorgente **951f91c8df3d252c720ffa4f0fc787ff90d91b9e**.
Stato riportato: COMPLETE_PRIVATE_REVIEW_READY_NOT_STARTED.
Review SHA256: **b53cc4ba39c8998cdc013098465258f14d927c79b5fbccb645605a76fb214f72**.
Documento privato sul VPS:
`/etc/ouf/deploy-snapshots/chatbot-file-intake-e2d2ff9ce2dec348754edf977f911aac987a1d22723368571b26586870d50736/attempt-f101046b9824be1e37f8879d/full-action-review.json`.

Tutti i15 controlli preflight sono PASS. Sono completati anche intenti/scope, riletture finali, verifica corrente R12 e assemblaggio della review: il preparatore li esegue prima del risultato finale. La ricevuta è stata riportata dall'operatore; il contenuto del documento privato non è stato acquisito dall'agente. È rimasto sul VPS.

runtimeAuthorityIssued=false, targetApplyAuthorized=false, serviceMutations=0, budgetReset=false. Il ciclo CSV end-to-end resta non dimostrato. I device code sono omessi dalle evidenze.

## Prima dell'esecuzione

Una lettura MCP fresca con ouf-admin conferma Teatri asset6609b245-86ed-4315-8ce0-73f2a8555bf3, profile7984c39c-7396-4248-ab0a-f2efc390b49c/versione1:13 righe,20 colonne. I20 nomi corrispondono esattamente al mapping preparato in releases/teatri-reuse-semantic-proposal-20261014.json del sorgente951f91c. Nessun upload o profiling nuovo è stato richiesto.

Una ricerca MCP fresca restituisce gli stessi8 Cinema ACTIVE/revisione1 e gli stessi IRI di proprietà della baseline, partial=false,nextCursor=null. Non è una prova di uguaglianza dei valori di proprietà o una nuova ingestion.

La proposta semantica resta preparata e non registrata: nessun pin pubblicato è inventato, nessun onboarding DRAFT è stato creato. Dopo la disponibilità del cohort, acquisire la review HUMAN e i pin effettivamente pubblicati, poi usare il mapping completo. La seconda sorgente richiede l'input distinto con gli stessi byte previsto dal piano di accettazione.

## Consegna per esecuzione

Wrapper: [chatbot-file-cohort-execute-vps-20261015.sh](chatbot-file-cohort-execute-vps-20261015.sh).
SHA256: **310efbf261d3e767924a6b1cd6a87f22d9bdc7111624c680f88466597bc170f7**.
Sorgente eseguibile: **951f91c8df3d252c720ffa4f0fc787ff90d91b9e**.
Launcher SHA256:596bd594af24775ed5b9107199bb781893391c543624728f820bc4395581e084.
Capsula SHA256:e2d2ff9ce2dec348754edf977f911aac987a1d22723368571b26586870d50736.

Il wrapper conserva il launcher qualificato e i pin. Riusa lo ZIP locale già verificato; il client gh portatile esistente viene controllato prima di sudo. Rispetto al wrapper di sola preparazione cambia il commento esplicativo e viene omesso --prepare-only. Non sono modificati i sorgenti eseguibili e non serve una nuova qualificazione del prodotto: CI200 test/26 suite, frame completo con immagine reale e TLS sono gli stessi già acquisiti, più la preparazione completa target ora riuscita. Il wrapper è verificato per sintassi Bash e hash.

Il programma ricontrolla gli input correnti e produce una NUOVA review. Il ramo prepare-only ha terminato il refresh della sessione HUMAN: il vecchio hash è evidenza della preparazione, non un'autorizzazione riutilizzabile. Usare esclusivamente l'hash mostrato dal nuovo prompt:
`APPROVO <hash mostrato nel terminale>`.
Non inserirlo automaticamente, non usare l'hash b53cc4ba... per approvare una review diversa. È un requisito del preparatore in tools/chatbot_file_cohort/review.py, non un nuovo giro di permessi imposto dalla chat.

Prima di questa conferma il programma prepara la review; dopo può installare il cohort finito. L'azione comprende cinque sostituzioni applicative, backup/migrazioni previsti, Gateway e autorizzazioni IAM, owner policy-token e ritiro delle unità legacy. Se il piano lo richiede, sostituisce APISIX con la stessa immagine e la configurazione revisionata. Per MCP: ruolo audit NOLOGIN e privilegi temporanei selezionati, revocati prima dell'avvio. Nessun restore DB, replay delle claim consumate o rinnovo automatico del mandato.

## Finestra operativa e interazioni

La finestra complessiva è al massimo3600 secondi dalla decisione HUMAN, non un servizio perpetuo accettato. Il primo grant è distinto e ha massimo300 secondi; il worker ha il suo budget finito revisionato. Occorre seguire anche le review browser: l'installazione può attendere HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED con proposalId/approvalPath prima del primo grant.

Il processo viene avviato in una unità systemd finita; il terminale osserva i suoi stati. Inviare gli stati pubblici, in particolare HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED, eventuali PAUSED/BLOCKED oppure COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE. Non rilanciare automaticamente una mutazione dopo un esito ambiguo.

Quando il cohort è pronto, completare dalla chat proposta/review semantica, pin effettivi, onboarding/review sorgente, ingestion e verifica ACK/commit/lineage/ricerca fresca, poi seconda sorgente MATCH/NOOP. Le decisioni applicative HUMAN rimangono nel THS e non sono sostituite dall'approvazione infrastrutturale. L'osservatore del processo può riportare ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED; la ricerca chatbot fresca resta una prova distinta.

## Stato

B01 preflight, B02 confronto storico e B03 preparazione completa: chiusi sul target.
B04 installazione effettiva: non avviata.
B05 CSV Teatri dal chatbot e B06 seconda sorgente: aperti.

Evidenze: [ricevuta target](../evidence/complete-target-preparation-20261015.json), [letture MCP prima dell'esecuzione](../evidence/chatbot-pre-execution-inputs-20261015.json), [correzione frame qualificata](FILE_ONLY_FRAME_GATE_FIX_20261015.md).

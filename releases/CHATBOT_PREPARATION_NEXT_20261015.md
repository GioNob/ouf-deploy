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

## Ultima esecuzione: conferma terminale rifiutata

Una seconda preparazione completa è riuscita con review5cc4b24c718a2ecc303e0184086c4697745dee83629b5ba7e9a8efe2337bf4e3. Il testo riportato dall'operatore coincide con la richiesta, ma il lettore esatto di /dev/tty lo ha rifiutato con FULL_ACTION_NOT_APPROVED. I byte effettivamente letti non sono disponibili: non è dimostrato un errore dell'operatore né una specifica causa dello smartphone.

Il confronto avviene prima di firme, emissione dell'autorità e avvio del processo. Il campo runtimeAuthorityIssued riportato è null; l'assenza di emissione per questo specifico errore deriva dall'ordine del sorgente. La preparazione acquisita resta valida come evidenza; B04 non è iniziato.

Il nuovo lettore elimina l'input precedente prima di mostrare la review, accetta un solo involucro standard di incolla attorno al testo esatto o al solo hash, e offre massimo tre tentativi nello stesso prompt con diagnosi di formato senza riportare l'input. Hash diverso, spazi e trasformazioni Unicode restano rifiutati. Non approva né ripete automaticamente l'azione.

## Consegna per esecuzione

Wrapper: [chatbot-file-cohort-execute-terminal-vps-20261015.sh](chatbot-file-cohort-execute-terminal-vps-20261015.sh).
SHA256: **4164ef0b48b9bd428b5e1b24f95c78c137ecb1f82284f603465d57538c25d343**.
Sorgente eseguibile: **6959b1dbaeb30ca3a838c7d6243a55e9cfc5118a**.
Launcher SHA256:2fae09635e3c8ba6770a267dcc512e143ce5cb4f89ca218ce396d64d9e6a1d77.
Capsula SHA256:f9726cc181ecf6f6e5bc0ab9064e7114a1ec261f0f5284f5e8580996fce47755.

Il wrapper riusa lo ZIP locale già verificato e controlla il client gh portatile prima di sudo. Punta esattamente alla correzione terminale qualificata. Sei sorgenti applicativi, immagini, frame runtime e scope dell'azione restano invariati. L'inclusione esplicita di termios nella closure permette la gestione della coda del terminale; non abilita import arbitrari. La CI del nuovo sorgente38687882912/job116266819989 è PASS:207 test,27 suite,nessuno saltato. Anche la run PR38687887477 e il verificatore HUMAN38687887549 sono PASS. La qualificazione è documentata nell'evidenza terminale; i test della composizione frame con immagine reale e del TLS Java restano quelli del sorgente951f91c, poiché questi percorsi non sono modificati. Il wrapper è verificato per sintassi Bash e hash.

Il programma ricontrolla gli input correnti e produce una NUOVA review. Il ramo prepare-only ha terminato il refresh della sessione HUMAN: il vecchio hash è evidenza della preparazione, non un'autorizzazione riutilizzabile. Usare esclusivamente l'hash mostrato dal nuovo prompt:
`APPROVO <hash mostrato nel terminale>`.
Digitare APPROVO seguito da uno spazio e incollare il solo hash corrente è supportato. Non inserire la conferma automaticamente e non riusare gli hash precedenti b53cc4ba... o5cc4b24c... per approvare una review diversa. È un requisito del preparatore in tools/chatbot_file_cohort/review.py, non un nuovo giro di permessi imposto dalla chat.

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

[Evidenza del blocco terminale e qualificazione](../evidence/chatbot-human-terminal-fix-20261015.json).

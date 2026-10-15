# Conferma browser scaduta: stato e recupero circoscritto — 15 ottobre 2026

Il processo finito è stato avviato alle07:48:03 CEST e al readback delle08:19:47 è ancora active/running, Restart=no. Il mandato termina alle08:48:03 CEST. L'approvazione terminale è stata accettata una sola volta: il ciclo dei tre tentativi esce immediatamente alla prima risposta valida.

La conferma dei ruoli è una decisione distinta nel browser, non un altro device-code login. La propostaadf95413-92b0-460b-a112-2fd80bd208ac è EXPIRED dalle08:08:47 CEST, finalPolicyRef=null. Una lettura MCP autenticata con ouf-admin lo conferma. Il servizio permission-proposal usa900 secondi di TTL e rifiuta la conferma scaduta. L'installatore continua a leggere lo stesso ricevuto scaduto; non è un'attesa che possa risolversi approvando il vecchio link.

Il link obbligatorio era nel campo JSON approvalPath. Le istruzioni all'operatore avrebbero dovuto mostrare un collegamento esplicito e la scadenza di15 minuti: l'assenza di tale indicazione è un difetto del percorso di consegna, non un errore da attribuire all'operatore.

## Recupero

scripts/prepare-chatbot-role-review-recovery-20261015.py prepara una sola NUOVA proposta non vincolante con l'identico roleProposal del bundle privato già revisionato. Legge gli input con le regole di custodia originali, verifica loader e chiusura dei sorgenti esatti6959b1d, riusa i verificatori originali delle firme e del mandato, controlla processo attivo e attesa della proposta scaduta, ruolo baseline e policy corrente. Non aggiorna il processo, i ledger originali, le claim, la scadenza, le password o le configurazioni applicative. Non firma nuova autorità e non conferma/pubblica ruoli.

Usa una chiave nuova e deterministica per la sola nuova review:cohort-role-recovery:adf95413-92b0-460b-a112-2fd80bd208ac. Il servizio owner deduplica eventuali invocazioni ripetute sullo stesso draft senza rinnovarne il TTL. Non viene alterata la proposta scaduta o riusata la sua decisione. Se i ruoli sono già quelli attesi, non crea un'altra proposta. Drift, revoca/rifiuto, processo fermo e scadenza bloccano la preparazione.

Il trasporto e la sessione HUMAN sono quelli verificati del processo esistente; il recupero non avvia un secondo refresh. I token sono letti esclusivamente dal trasporto originale in memoria e non stampati. Nessuna chiave privata viene letta. Il programma non esegue apply, import immagini, DB, IAM o lifecycle container. La mutazione eventuale è la creazione auditata della sola proposta HUMAN.

Solo dopo la conferma manuale sul NUOVO link, il processo originale può rileggere i ruoli, verificarne esattamente policy/lineage e continuare entro la scadenza iniziale. Il recupero non garantisce che tutta l'installazione e il CSV completino nella finestra residua.

## Qualificazione e istruzioni

SHA256:6e8e61edf6f95e4dc62a79dd550f67e0947de4d12a107869a628837a36697cc8. tests/test_chatbot_role_review_recovery_20261015.py:8 test su fixture PASS, nessuna chiamata live. Verifica payload esatto, baseline/policy drift, vecchio stato non scaduto/rifiutato/pubblicato, ruoli già pubblicati e chiave stabile. Le verifiche crittografiche e di import isolato sono quelle del bundle originale, già qualificate; il driver esterno di sola proposta non è stato eseguito sul VPS prima della consegna all'operatore.

Eseguire il driver con python3 -I -B -S e sudo. Alla fine stampa separatamente: APRI ORA QUESTO LINK NEL BROWSER E REVISIONA I RUOLI. Aprire quel link, esaminare il contenuto, confermare nella THS entro la scadenza, senza cercare codici XXXX-YYYY. Riportare ricevuta e nuovo stato; non rilanciare la consegna completa.

La chiarezza UX permanente e il trattamento esplicito delle proposte scadute rimangono difetti da correggere nel percorso ordinario. Questo recupero è mirato al contesto corrente e non cambia il runtime in esecuzione.

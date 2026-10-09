# Recupero specifico del tentativo kanx36_x — R3

Stato: proposta concreta, non autorizzazione. Il nuovo helper rifiuta l'esecuzione prima di qualsiasi accesso ai file finché manca il riferimento all'approvazione umana registrata.

## Problema e correzione

Il chiamante `authenticated_runtime_switch.py` costruiva `VerificationBudget(40)`. La libreria di autenticazione sigillata ammette soltanto interi da 1 a 18: genera quindi `BOUNDED_AUTHENTICATION_BUDGET_REQUIRED` prima di autenticare i profili o osservare il guard. Il vecchio gestore del cambio mascherava quell'eccezione con `GUARDED_RUNTIME_SWITCH_UNPROVEN`. Il test con la catena realmente collegata riproduce il rifiuto prima della correzione e passa dopo. Non è un'acquisizione dello stack storico del VPS: è una riproduzione deterministica del difetto nel codice usato da quel percorso.

La correzione mantiene il limite di 18 secondi della libreria; non cambia la libreria o estende le finestre firmate. Il recupero carica due sole utility di orchestrazione in memoria, con hash controllati:

| Utility | SHA256 |
| --- | --- |
| guarded_runtime_switch | c52889d78ee6c3be80eff56631ddc24cb190b257e1d47152e989d7d4c199035f |
| authenticated_runtime_switch | ce5625aa645b3da470e84b8544adfa82d5bca8665bb88d8e2d49fd3701548d83 |

La prima conserva tipo e motivo simbolico dell'errore senza testo privato; la seconda corregge il budget. Anche il riferimento importato dal consumatore `docker_cohort_activation` viene ricollegato esplicitamente alla nuova factory: altrimenti conserverebbe la vecchia funzione. Nessun file delle utility installate viene sovrascritto. Il precedente intake riparato SHA256 `69e2ef61a7ee3f598286b50d9460a44ceb51acfe016413a9f23cf52bd076b26a` viene riutilizzato in memoria, tramite il bridge già scaricato SHA256 `e3253513c4220a0a506c117e0a535145d14f76fcba3f58fe292ee894c46bfcd4`.

## Stato riportato dall'operatore

`READ_ONLY_CHECKS_PASS`: otto firme già emesse (quattro per ruolo), 81 hash dei file pubblicati corrispondenti, nessun claim/receipt/denial di cambio runtime. L'osservazione nativa attuale conferma set provider vuoti, inode del lock preservato e stati dei due candidati. La diagnosi ha eseguito zero operazioni lifecycle, scritture di configurazione o letture di chiavi private. Questi contatori riguardano la diagnosi: non azzerano i contatori ignoti del precedente tentativo di firma. Ricevuta riportata, non acquisita indipendentemente dal cloud.

## Unica operazione proposta

`tools/semantic_target_review/execute_post_signature_recovery.py` verifica il preciso fallimento pre-switch, claim originale/configurazione approvata, quattro firme per ruolo, tutti gli 81 file e assenza di qualsiasi claim di switch/cohort. Prima di leggere chiavi osserva nuovamente il guard sotto il lock e richiede gli stessi hash di generazione dei due CID riportati dalla diagnosi. Se un fatto è cambiato, si ferma.

Conserva intatti source-ff13uh3n, approved-context-kanx36_x, transaction-kanx36_x, otto firme, claim e diagnosi. Riserva una sola volta `post-signature-recovery-claim.json` nel package originale; crea un nuovo contesto privato, due nuovi mandati root, nuove firme in quel contesto e un nuovo snapshot di pubblicazione. Non cancella né sposta i claim precedenti. Riutilizza i sedici input già accettati tramite le loro binding esistenti: nessuna copia o rigenerazione dei due documenti dependency. La closure runtime/observer `dc87593c5c3b2e4859545de25b92702d93666e8d5c988f03e35fcf2df24c1ae4` rimane immutata.

Le vecchie firme scadute non vengono consumate per concedere avvio. La nuova finestra comune è di 240 secondi e deve stare interamente nella validità delle evidenze dependency già accettate, che termina il 10 ottobre alle 08:33:47 Europe/Rome. Si usano le medesime chiavi locali già installate, senza generarne o esportarne altre. Otto nuove firme, pubblicazione STAGED, cambio wrapper tramite CAS sotto il guard, richiesta coordinata di avvio dei soli due CID già approvati attraverso `ouf-semantic-admitted-v2`, quindi diagnosi/readback conservati. Controlli effettivi OCI completo, rootfs v1, NIC, peer, generazione e guard restano obbligatori.

Non sono compresi retry automatici, rollback, riavvii del daemon, sudo generale, lease/provider grant, chiamate provider autorizzate da questo atto, job Teatri, rollout Semantic/MCP o release acceptance. In caso di nuovo rifiuto il claim rimane e il comando non va ripetuto.

## Verifica e limite

Nove test del bridge: catena fredda → otto firme Ed25519 reali con chiavi CI temporanee → pubblicazione effettiva → tre checkpoint del CAS e due checkpoint cohort con ricostruzione/autenticazione reale. La sola osservazione del kernel in questo test è simulata: i test nativi separati del guard e la diagnosi VPS riportata sono evidenze distinte. Il test rifiuta autorità scaduta e file modificati. Sei test del recupero verificano approvazione mancante prima di qualsiasi accesso, claim vietati, fatti incompleti/ignoti e ricollegamento del consumatore importato. Dieci test del CAS già passano. Nessuno di questi test fornisce autorità target.

Prima dell'esecuzione occorre l'approvazione umana specifica di questo recupero post-firma, richiesta dalla `partialFailurePolicy` dell'ambito operativo già accettato: le precedenti approvazioni non autorizzano un retry automatico dopo emissione delle firme. La domanda riguarda solo questo recupero conservativo e la nuova finestra; non richiede di riapprovare immagini o sedici input. Il witness e l'ora reali devono essere registrati e vincolati al helper prima di fornire il comando privilegiato.

## CI GitHub completata

Run `37898950078`, job `113716742413`: 9 test bridge + 6 recupero, PASS. Run `37898950107`, job `113716742236`: ambito operator, PASS. Il manifest del repository è stato aggiornato alle due utility cambiate (SHA256 `84e4237808a92a8e116e140bb828167257236eaade3bcfe76efdee4d9912be7a`); il manifest target originale `2699c82124b6bfcbd61991f09a96ebb5c6a2d336aaf3384dcae9288101b29de4` è conservato. Il precedente test del loader isolato falliva correttamente con `PRIVATE_INTAKE_HASH_DRIFT` perché il repository aveva utility nuove e hash vecchi. Diagnosi e fallimenti conservati in `evidence/provider-v2-locked-switch-ci-20261009.json`.

Dopo la correzione, run `37899168794` sul commit `672fbf8cf62b1a395c200279ed1a28a20dcf7957`: tutti e quattro i job PASS — profiles `113717436954` (inclusi i 33 test autenticazione), native-frame `113717437138`, native-authenticated-docker-cohort `113717437221`, native-docker-creation-window `113717437368`. Le prove native usano Docker/namespace/chiavi CI, non i CID o le autorità del VPS.

Helper R3 proposto al commit `6046de51f3e683434dfb13a38ce8220c694feba3`, SHA256 `750422fa9ccf1ae5a12ad48d6c525eacfb1a37c72d51552a90a4d8a2b7ec5c20`. Ancora bloccato in attesa del witness umano reale. Non eseguire vecchi comandi. La clausola già approvata è: “Retain claims, wrapper state and both available candidate observations. No automatic recovery; explicit scoped human recovery is required.”

# OUF — Farmacie: profiling completato, lettura profilo da autorizzare

28 ottobre 2026, Europe/Rome. [Evidenza](../../evidence/farmacie-profile-recovery-succeeded-20261028.json). Il miniPET corrente rimane [M2 v1.2](../OUF_M2_MINIPET_v1_0_20261026.md).

## Risultato acquisito

L'utente ha riportato il messaggio di budget concesso e poi la THS con analisi completata, 6 tentativi cumulativi, sessione COMPLETED e 1 tentativo usato su3. Una lettura governata indipendente MCP con account ouf-admin restituisce lo stesso job SUCCEEDED, errorCode null e profileId `f3061699-4fde-4085-89c8-bc8703f65686`.

Asset `9c502da5-b5d8-405e-b3f5-60eb31ecb513`; job `677480c8-3d10-44fd-9dad-f72ddeed20a4`; 13903byte nella schermata. Nessun nuovo upload, job, budget, resume o acquisizione inviati dall'agent. Non inferire sessionId, decisionRef o receipt ownership non forniti. L'identità/tenant browser non sono esposti dalla vista ordinaria.

Questa è prova di completamento del profiling; anteprima, conteggio61righe e catena versoUDP restano da verificare. Nessuna accettazione M2 o G5/G6/G7. Tutti i controller e le authority precedenti restano consumati. Non far premere di nuovo budget/resume.

## Blocco corrente dell'anteprima

Un'unica lettura `source.file.preview` del profilo ha restituito `NO_APPLICABLE_GRANT`, fase MCP_PRE_ADMISSION, policy58, retryablefalse. Non ripetere alla cieca. Il permesso permanente exact-job supporta la lettura operativa, mentre il profilo usa ancora la risorsa MCP generica capability. La lettura non è arrivata all'owner del profilo e non ne ha restituito contenuti.

ROLES corrente:8ruoli/12assegnazioni. Tutti sono stati preservati esattamente nell'[intent](../../evidence/owned-managed-file-preview-permission-intent-20261028.json), salvato prima dell'invio nel commit f68031ef40ca5cbe94f73816918020414cc1b261. Aggiunta proposta: un solo ruolo nominale preview per i file propri, resourceTypecapability, senza cambiare label; ownership tenant+subject e redazione restano controlli owner. Validità proposta entro la scadenza dell'assegnazione admin15settembre2036.

**Invio rifiutato dalla revisione automatica**, perché scope persistente più ampio del singolo job e oltre l'autorizzazione esplicita. [Esito](../../evidence/owned-managed-file-preview-permission-autoreview-20261028.json). Nessuna proposal receipt/proposalId ricevuta e nessuna pubblicazione eseguita. Non aggirare il rifiuto con un comando diverso, un'altra identità o un grant inefficace.

Prima di riproporre serve autorizzazione esplicita dell'utente per preparare quel mandato stabile di sola lettura dei file propri; dopo eventuale creazione, la decisione di pubblicazione rimane nella THS esclusiva utente. In alternativa occorre implementare/qualificare un binding realmente limitato a profile/asset e poi la relativa autorizzazione. Non è una richiesta di ripetere login o il recupero completato.

## Difetto di presentazione da correggere

La THS mostra “Ultimo blocco:UNCLASSIFIED” dopo il successo. In Onboarding source9d19fad3, ManagedProfileJobs.card() deriva lastFailureCategory da last_error/failure_class e usa UNCLASSIFIED quando failure_class è nullo, senza distinguere SUCCEEDED. Il jobread live ha errorCode:null. Correggere la proiezione/UI con regressione pertinente nella prossima tranche applicativa; non inventare una nuova failure o rifare profiling.

## Dopo il permesso e la verifica

1. Rileggere il solo profilo esistente tramite capability governata e verificare parser/dialetto/hash/metadati effettivamente esposti e61righe/10colonne; dichiarare campi non provati.
2. Risolvere semantica dalRegistry, presentare una proposta di mapping/identità/tipi/label ed esclusioni; nessun IRI, CRS o significato inventato.
3. Proseguire i soli delta residui D5/D6/D7, decisioni HUMAN per fonte/acquisizione, rendicontazione di tutte le righeUDP, reimport/fault/dueclient e dossier. Riusare M1/Teatri/typed/ASSETS/LATEST e le prove pertinenti senza riscriverli.
4. Aggiornare lo stato corrente nel piano strutturato. Nessuna terza acquisizioneTeatri, replay, reset, Registryrestart/reinstall, merge, releaseacceptance o Supervisor anticipato.

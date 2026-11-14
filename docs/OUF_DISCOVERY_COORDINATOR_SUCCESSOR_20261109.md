# Discovery: preparazione separata del coordinatore successore

9 novembre 2026. **Staging corretto completato sul VPS alle 10:56 CET. Non ripetere il comando. Non è attivazione.**

[Ricevuta operatore](../evidence/discovery-coordinator-staged-operator-20261109.json): nuovo contesto QUIESCED, guard superato, attivo storico BLOCKED e puntatore invariato. Prossimo passo: [collegamento al boot](OUF_DISCOVERY_SUCCESSOR_BOOT_20261109.md). Le sezioni seguenti conservano la consegna già eseguita.

## Evidenza che consente il passo

La [ricevuta delle 09:48 CET](../evidence/discovery-nft-drift-operator-20261109.json) prova che driver e proprietario installato coincidono, i quattro set sono vuoti e l'output nft ordinario stabile coincide con il footprint di boot. L'impronta esatta del vecchio proprietario differisce da quella corrente. Il formato numerico non coincide con l'impronta attesa e non risolve il problema.

Il [protocollo di boot originale](https://github.com/GioNob/ouf-api-gateway/blob/df103735c1fe75a31e6d4c752360e9368e6aa52d/tools/semantic_provider_boot_coordination.py) mantiene BLOCKED quando rileva una generazione nativa da riconciliare. Questo spiega il percorso previsto dal codice, non prova quale evento abbia prodotto la differenza storica sul VPS.

Il nuovo passo prepara il contesto della generazione successiva. Non riscrive la storia del vecchio proprietario e non rende valido un suo driver consumato.

## Correzione della ricevuta prima del nuovo tentativo

La [ricevuta delle 10:46 CET](../evidence/discovery-coordinator-stage-held-operator-20261109.json) registra `EXACT_DRIFT_RECEIPT_REQUIRED` prima di intento, directory di preparazione, nft o servizi. Il pin precedente era stato calcolato su una copia incompleta del JSON operatore: mancava `installedBoot.retainedPreflightFootprintMatches: false`.

La copia completa, passata alla funzione `encoded` del produttore originale, produce 3.128 byte e SHA-256 `fcea4316cd6daa153c454c6ddab59feedf61ff57ffc5f921eac6eb4e6ac8eeb3`. Togliere quel solo campo riproduce `ac43eb0ab617bb0039cfc431bf427ca88ec5e81f513a540da54ef21bc430fde2`, il pin errato. Sono corretti il documento in Git e il pin del consumatore; il file privato VPS resta intatto. Non si accetta un hash letto arbitrariamente dal VPS e non si normalizza il JSON durante la verifica.

Cinque nuove prove coprono ricevuta completa, omissione riprodotta, rifiuto di campi/byte alterati e ingresso reale di `main`: la ricevuta completa raggiunge la lettura successiva; quella incompleta è rifiutata prima, senza intento o scritture. La versione corretta può essere eseguita dopo questo specifico arresto prima dell'intento. Se un intento esiste nel frattempo, il controllo originale la ferma.

## Consegna e controlli

[Wrapper](../scripts/deliver-discovery-coordinator-successor-20261109.sh), SHA-256 `0f451255903df58b65665ccb3e605772d76789b9ca0ab702aa2f1e402191d039`; sorgenti al commit [c73bcf94e305b1e812088753b38d1a2f176d9724](https://github.com/GioNob/ouf-deploy/commit/c73bcf94e305b1e812088753b38d1a2f176d9724). Verifica tredici file scaricati, poi esegue Python isolato tramite sudo.

Sotto i lock esistenti dei runtime, della coorte e delle lease:

1. Verifica la ricevuta esatta, il driver retained e l'assenza corrente dei processi/task/namespace dei vecchi provider. Conserva i loro frame e journal.
2. Rilegge il puntatore di boot e i profili legati per hash. Richiede gli stessi binding di driver e proprietario, journal attivo BLOCKED senza lease/avvio e footprint atteso.
3. Verifica dieci sorgenti originali del proprietario/boot, oltre al compilatore e al restorer referenziati. Legge due volte le tabelle in formato ordinario; richiede sia il footprint di boot sia l'impronta esatta corrente già ricevuta. Tutti i set devono essere vuoti.
4. Registra un intento separato e crea una nuova directory privata sotto `/etc/ouf/deploy-snapshots/discovery-coordinator-successor-20261109-*`. Copia i dieci sorgenti verificati e scrive cinque file: configurazione owner, configurazione boot, profilo boot e i due journal nuovi.
5. Il nuovo binding usa una nuova transazione e l'impronta corrente. Il nuovo journal è QUIESCED con lease/start false; quello vecchio resta BLOCKED, compresi eventuali metadata storici degli indirizzi.
6. Esegue il controllo di guardia originale attraverso i moduli immutati, sotto il lock comune e con trasporto abilitato soltanto alle letture. Rilegge profili, sorgenti, tabelle, file preesistenti e frame prima di attestare la preparazione.

Il confronto esatto resta attivo: il nuovo hash non viene adottato soltanto perché osservato. Occorrono ricevuta fissata, nuova corrispondenza col footprint legato all'installazione e identità nativa esatta invariata durante il passo.

## Risultato e limite operativo

Esito atteso: `DISCOVERY_COORDINATOR_SUCCESSOR_STAGED_QUIESCED`.

| Campo | Valore atteso |
| --- | --- |
| stagedOwnerGuardPassed | true |
| stagedCoordinationState | QUIESCED |
| activeCoordinationState | BLOCKED |
| stagedLeaseAuthorized / stagedStartAuthorized | false |
| activeInstallationPointerChanged / activationPerformed | false |
| nftWrites / oldRuntimeJournalWrites | 0 |
| providerReady / newGenerationAdmitted | false |

Si creano solo file nuovi di preparazione/evidenza. Nessuna modifica al puntatore attivo, unità systemd, vecchie configurazioni/driver/journal, nft, database, S3 o credenziali. Nessun token, DNS, provider o avvio/stop.

L'intento è `/var/lib/ouf-storage-migration/discovery-coordinator-successor-stage-20261109`. Una directory o un intento parziale restano conservati; nessun replay automatico. Durata massima 180 secondi. In caso di HELD restituire il JSON senza rilanciare.

**Il passaggio successivo è l'attivazione coerente di questo contesto insieme a boot e nuova generazione runtime/provider.** Il comando qui consegnato non modifica il loro riferimento attivo. Il solo collegamento al boot è ora qualificato nel runbook successivo; la nuova generazione provider resta da preparare e qualificare; non riavviare i vecchi CID e non usare STAGED come prova di discovery o E2E.

## Verifiche eseguite

[CI 42596438560](https://github.com/GioNob/ouf-deploy/actions/runs/42596438560), job 129090107145: **11 test unitari e 2 nativi, zero skip**, log letti.

Le prove native ricreano realmente le tabelle in un namespace isolato, preparano file privati e avviano in un processo isolato il comando owner originale in modalità guard. Il nuovo pacchetto passa, il vecchio journal resta invariato; una regola estranea viene rifiutata sia dal confronto di boot sia dal guard esatto. Coperte inoltre sorgenti alterati/aggiunti, riuso di directory/transazione e conservazione di file già esistenti.

Sul VPS il comando di preparazione usa direttamente il nucleo originale del guard con lock già detenuto; non avvia un processo lease o il comando di ripristino del boot. L'intero controller di staging è stato eseguito con successo secondo la ricevuta operatore. [Evidenza](../evidence/discovery-coordinator-successor-stage-qualification-20261109.json). F2–F6 restano aperti.

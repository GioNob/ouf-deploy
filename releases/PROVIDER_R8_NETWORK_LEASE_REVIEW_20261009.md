# Proposta concreta: attivare la lease dei due flussi R8 già previsti

Stato: **preparata, non approvata, non eseguibile sul target**. Il codice mantiene APPROVAL_REF PENDING e tempi zero. La ricevuta operatore delle 21:37:45 Europe/Rome del 9 ottobre, [registrata integralmente](../evidence/provider-r8-post-start-target-20261009.json), conferma entrambi i processi R8 ancora running, stessi PID, zero riavvii e journal STARTED invariati. Stato rete: QUIESCED, autorizzazione lease false, quattro set inet/bridge vuoti, struttura verificata. Nessuna unità lease/coordinated rilevata. L'avvio R8 è concluso e non viene ripetuto.

## Ambito da approvare

| Flusso | Processo esistente | Destinazione già configurata | Limite |
|---|---|---|---|
| Adapter | CID f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67, PID1826443, avvio 19:10:21.87693854Z | https://schema.gov.it:443/sparql | TCP443, lease massima30s |
| Southbound | CID 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916, PID1826422, avvio 19:10:21.846292298Z | https://auth.ouf-lab.it/realms/ouf | TCP443, lease massima30s |

Gli hash degli URL corrispondono esattamente a quelli appena letti; le forme degli URL provengono dagli input conservati della migrazione. Nessuna nuova destinazione, IP fissato, porta o eccezione privata viene introdotta. Owner hash `656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8`, kernel hash `0a646e6109d2dc32aabdbbe26436784de8a83bdeb023a36c5b2712315666f5b5`; journal iniziale `a58f0cb6e011879fc22723356d19926adf8945c38dcdbf2d21ab3fa34dd6f7f1`. Resolver esistenti 46.38.225.230 e 46.38.252.230, timeout2s, budget apply1s, rinnovo15s. Restano applicati i limiti più corti delle risposte DNS effettive.

L'azione operator-only proposta:

1. Rilegge nello stesso flusso i due processi e la generazione QUIESCED, i file/sorgenti già sigillati, i comandi boot caricati e l'assenza della nuova unità.
2. Conserva ricevuta precedente e autorizzazione specifica in un nuovo snapshot `semantic-r8-lease-*`. Crea una claim esclusiva `/etc/ouf/provider-r8-network-lease.claim`; nessun reset o replay.
3. Avvia soltanto l'unità temporanea `ouf-semantic-provider-lease-r8.service`, non abilitata al boot, Restart=no, legata alla vita di docker.service. Nessun daemon-reload o riavvio Docker è richiesto.
4. Il worker verifica l'approvazione, mantiene la versione precedente del journal e pubblica una sola autorizzazione LEASE_READY sotto il lock originale. Verifica gli otto file originali del coordinatore e ne mantiene la custodia. Esegue i moduli esistenti con il solo compilatore lease corretto, separatamente vincolato nella nuova autorizzazione; revoca iniziale, DNS fresco, aggiornamento atomico e readback restano quelli del coordinatore. Nessuna riscrittura delle regole, dei profili, dei container o dei loro journal R8.
5. Restituisce successo soltanto dopo due cicli distinti DNS/apply/readback, servizio attivo con PID coerente e membership corrente di entrambi i flussi. Conserva la causa interna degli errori e tenta l'arresto della sola unità appena creata se la verifica iniziale fallisce.

Durata dell'autorizzazione proposta: vita degli attuali due processi, fino ad arresto, errore del worker o reboot. Ogni ciclo controlla CID, immagine, runtime, PID, StartedAt, zero riavvii e sorgenti di rete. Stop/errore usa la revoca del coordinatore esistente; se la revoca non è dimostrabile, i timeout kernel restano finiti e il risultato lo dichiara. Nessun riavvio automatico o riarmo autonomo. Una nuova generazione richiede una nuova decisione. La finestra per la prima invocazione sarà vincolata al messaggio di approvazione, massimo due ore; non è ancora impostata.

Il worker non effettua chiamate HTTP ai provider. Dopo l'apertura, i workload approvati possono invece raggiungere gli endpoint previsti: non confondere zero richieste emesse dall'orchestratore con assenza di traffico globale. L'azione non concede capability discovery, non pubblica semantica e non esegue il job Teatri. Non è accettazione di release o prova di salute applicativa.

## Implementazione e verifiche

Entrypoint `tools/semantic_lease_activation/activate_r8_lease.py`, nucleo `activation_core.py`. Il lettore già presente `/home/oufadmin/ouf-r8-post-read.Tl08rnjI/read.py` viene riutilizzato con SHA256 ab61835ef55396ddacf4513acc0f21adbaab1b50ac32ad2fdc4c80a23d1835c8; non occorre rifare il suo download o la lettura manuale. Le sorgenti owner esistenti corrispondono ad a10df126d229dfefd9e0a4d716a07f1f535b6cd6; non vengono aggiornate.

I test locali verificano mancata autorità della proposta PENDING, finestra esplicita, drift rispetto all'effettiva ricevuta operatore, claim non sovrascrivibili, conservazione della causa interna e assenza di riavvio/boot automatici. La workflow dedicata verifica gli otto hash e prova il core con systemd, DNS UDP e nft reali in un namespace di rete CI isolato: apertura, rinnovo, errore DNS, revoca e rifiuto del replay. Esito corretto remoto da registrare prima della richiesta di approvazione. Fixture e test non diventano autorità target.

PET consultati: Matrice v1.7, Gateway v1.5 T11.3/GW-NET-01–05, Authorization v1.5 AUTH-05–12. L'unità supervisiona il coordinatore esistente, non introduce un nuovo prodotto. L'approvazione R8 precedente riguardava i container e non conferisce questa separata autorità di rete.

Dopo l'attivazione riuscita: aggiornare l'evidenza dipendenze degli artefatti Semantic/MCP già conservati, procedere con rollout e grant discovery, poi il percorso Teatri già concordato. Nessun ricaricamento asset né fallback locale.

## Difetto trovato nella prova nativa prima del target

La prima prova remota, run37983256268/job113998780301 sul commit17644c1be6a5d47522b05d4e77718efa600d778a, ha rifiutato l’apertura con FRESH_RESOLUTION_UNUSABLE. Il compilatore originale inseriva la risposta del primo flusso nella configurazione completa mentre il secondo era ancora vuoto: la validazione globale rifiutava quindi ogni prima attivazione della coppia. Il test riproduce il problema con il sorgente originale, non con un mock.

La correzione valida ogni flusso risolto separatamente durante il ciclo; restituisce la stessa transazione atomica solo dopo la validazione di entrambi. Un solo flusso invalido mantiene la revoca di tutti e quattro i set. Nessun limite DNS, TTL, destinazione, sorgente, porta o controllo di indirizzo viene allentato.

Il vecchio compilatore SHA256 `1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084` rimane sul VPS immutato. La nuova copia SHA256 `c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079` vive soltanto nel nuovo snapshot privato e deve essere esplicitamente inclusa nell’approvazione di questa azione. La chiusura originale non autorizza i byte modificati. Il worker conserva sia il vincolo vecchio sia quello nuovo nella capsula. Non è stata eseguita alcuna azione sul VPS durante queste prove.

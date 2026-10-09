# Proposta concreta — recupero della verifica finale della lease R8

Stato: **PENDING**, nessuna autorità target. [Lettura operatore22:42:50](../evidence/provider-r8-final-lease-readback-target-20261009.json): cycle-1 e cycle-2 riportano LEASE_ACTIVE, freshDnsObserved=true, indirizzi[1,1], stesso workerPID1847190. Nessun worker-denial. Il worker-status finale è QUIESCED/count2/setsRevoked=true. Entrambi i container restano running sugli stessi PID, senza riavvii. Servizio corrente not-found/inactive, owner QUIESCED, set vuoti, journal hash originale. Tutti i programmi dello snapshot precedente corrispondono alla capsula autorizzata. Sono evidenze riportate dall’operatore, non acquisite indipendentemente da root.

## Diagnosi e limiti

L’attivazione e il rinnovo hanno funzionato secondo le due ricevute conservate. Il verificatore finale ha poi rifiutato il risultato e arrestato il worker. Il vecchio verificatore non conservava i singoli valori: non si può attribuire storicamente il rifiuto a un predicato preciso. Una race reale è però dimostrata: la ricevuta cycle-2 precede l’aggiornamento del riepilogo worker-status. La prova nativa ritarda quest’ultimo di due secondi e riproduce la falsa negazione. Il controllo corretto usa cycle-2 immutabile e proprietà systemd reali. Conserva sempre ricevuta, stato del servizio e tutti e sette i confronti booleani prima di procedere o rifiutare. Nessun controllo viene rimosso: stato attivo/running, Restart=no, stesso MainPID, proprio ExecStart e secondo ciclo completo restano necessari, poi si verificano nuovamente processi e membership nativa sotto il lock.

[CI37989505450/job114019767899](https://github.com/GioNob/ouf-deploy/actions/runs/37989505450) sul commit1d77ecf777aad58bbb7a7f7bff3fd31b9bf5c32f: funzione effettiva di confronto target e lettura effettiva systemctl, con ritardo deterministico; unità assente/presente, due cicli DNS/nft reali, revoca su errore DNS e rifiuto replay. [Ricevuta](../evidence/provider-r8-lease-readback-recovery-validation-20261009.json). Questo verifica la correzione e non promette salute applicativa o successo VPS non osservato.

## Ambito della nuova decisione

Una sola nuova attivazione, sui due processi già approvati:

| Ruolo | PID attuale | Endpoint esistente | Lease |
|---|---:|---|---|
| Adapter f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67 |1826443|https://schema.gov.it:443/sparql|massimo30s, rinnovo15s|
| Southbound 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916 |1826422|https://auth.ouf-lab.it/realms/ouf|massimo30s, rinnovo15s|

Gli hash di owner, struttura, journal QUIESCED, destinazioni e sorgenti sono identici alla precedente proposta. Resolver46.38.225.230/46.38.252.230 e limiti DNS invariati. Nessuna nuova destinazione o porta; nessun Docker lifecycle, firma, chiave privata o discovery grant. Il worker resta Restart=no, non abilitato al boot, vincolato alla vita degli attuali processi fino a stop/errore/reboot. Il rinnovo non supera TTL e lease correnti. Prima invocazione entro massimo due ore dall’eventuale nuova approvazione, ancora non impostata.

La precedente autorizzazione è consumata. La nuova azione **non elimina o resetta** `/etc/ouf/provider-r8-network-lease.claim`; ne verifica contenuto esatto e mantiene tutto lo snapshotao5xt5og. Verifica inoltre la capsula precedente SHA256cb264e411c2e52accb65f756a8c71a7986564df081d5fc3818b8f89fc0c2426a, tutti i programmi, cycle-2 SHA2568cbef68f14c156b1ef078601a440c0735c8a97ccbef1b299372897c167e287e3 e la ricevuta di cleanup. Riserva soltanto una nuova claim esclusiva `/etc/ouf/provider-r8-network-lease-readback-recovery.claim` e un nuovo snapshot. Nessun riuso del vecchio worker o delle sue ricevute come risultato del nuovo tentativo.

## Consegna preparata

Entrypoint PENDING SHA25697b41378fc8bf7339e09968871371107ced63842dea226af874c819d546d92f2. Core51259c988eae4b506f2696ad3f5bf6e954eca9c4396cb36da75e0845ff49e50b e compilatorec3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079 invariati. Launcher `provider-r8-lease-readback-recovery-20261009.sh` mantiene PENDING e rifiuta prima di download/sudo. Dopo l’eventuale approvazione, si vincolano riferimento/tempi e i relativi pin; nessun nuovo scope viene aggiunto.

Riusa il GitHub CLI esplicito, il lettore locale, core e compilatore già scaricati in `/home/oufadmin/ouf-r8-lease.8XKYoqHc`. Scarica solo l’entrypoint corretto sotto un nuovo nome e conserva entrambi i vecchi output. Nessun bootstrap di container, trasferimento di asset o preparazione di immagini viene ripetuto.

PET consultati: Gateway v1.5 GW-NET-01–05, Authorization v1.5 AUTH-05–12; gerarchia Matrice v1.7 invariata. La nuova decisione è necessaria per una nuova azione privilegiata dopo il consumo della precedente claim, non per la modifica/read-only del codice.

Dopo il risultato reale: riprendere Semantic/MCP con evidenze dipendenze aggiornate, rollout e grant discovery; Teatri già caricato, nessun job nazionale ancora eseguito. Nessun fallback locale. Nessuna accettazione release inferita dalla lease.

La lettura attende anche il completamento della scrittura iniziale: O_EXCL rende visibile il nome prima dei byte. Attesa massima90s, solo per file appena apparso, JSON ancora incompleto o identità cambiata durante la pubblicazione. Qualunque errore di custodia distinto resta immediatamente fatale; un documento completo ma invalido viene rifiutato. La prova nativa usa il vero reader root-private del target e forza prima un file vuoto, poi la scrittura completa, quindi un riepilogo ancora precedente. Esito definitivo SUCCESS: la prova usa il reader root-private effettivo, attende il file incompleto e verifica la ricevuta immutabile con il riepilogo volutamente ritardato. Anche verifica servizio, rinnovo, revoca e replay passano. Consegna verificata: PENDING rifiutato prima del download, percorso gh esatto, un solo nuovo file, tre hash e vecchi output conservati.

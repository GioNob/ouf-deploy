# R8 completato: lettura dei prerequisiti di rete dopo l'avvio

I due CID sono avviati. La ricevuta operatore R8 è confermata dalla lettura Docker indipendente del runner VPS `ouf-vps-test`, run [37979230240](https://github.com/GioNob/ouf-deploy/actions/runs/37979230240), job113985199756, intervallo 19:17:47–19:17:52Z: entrambi running, PID positivo, zero riavvii, exit0. I valori Docker health null non provano salute applicativa. R8 è consumato e non deve essere ripetuto.

La lease di rete è un requisito separato. Il codice di avvio non la concede. Il coordinatore installato richiede journal LEASE_READY/leaseAuthorized e non si autorizza da QUIESCED. Non avviare il supervisore né cambiare un booleano prima di un atto specifico e della relativa integrazione. PET Gateway v1.5 T11.3/GW-NET-01–05 richiede egress governato; Authorization v1.5 AUTH-05–12 distingue autorità umana, tecnica e applicativa. Questi documenti non costituiscono approvazione dell'utente.

Il precedente helper privilegiato è deliberatamente limitato a candidati mai avviati: `install_provider_network_guard.observe → inspect_candidates` richiede created/PID0/StartedAt0001. Non modificarlo per aggirare questa condizione. Il runner ha Docker in lettura ma nessun diritto generale sui journal root. Serve quindi una sola esecuzione operatore del nuovo lettore, senza installazione, nuovi privilegi o modifiche applicative.

Il lettore `tools/semantic_target_review/read_r8_post_start.py` è vincolato al contesto R8 `mf9x0eqd`, all'output omonimo, ai due CID e alle immagini già avviate, e al guard `e4repg0a` con owner hash `656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8`. Legge:

- ricevuta di avvio e due ricevute di emissione dei ruoli, per distinguere i conteggi storici reali dagli zeri predefiniti del report esterno;
- stato dei due CID, journal STARTED, corrispondenza ai journal R8 e indirizzi sorgente solo in memoria;
- configurazione/source closure del guard, file e comandi boot caricati, journal lease e set nft inet/bridge sotto il lock esistente;
- nomi di eventuali unità OUF dichiarate per lease/coordinamento, senza dedurne attività o installare servizi.

Non invoca codice installato, broker, signer, supervisore, restore, DNS o provider. Comandi nativi ammessi: inspect dei due CID, nft list delle due tabelle esistenti, systemctl show e list-unit-files. Non legge chiavi, env, mount contents o log applicativi. Restituisce proiezioni, conteggi e hash; errori con fase, motivo, punti di eccezione, hash/exit dei comandi e nome del file se disponibile. Il launcher conserva l'output nella directory utente del download.

Verifica locale: cinque casi sull'intero collector e sui confini nativi, con JSON root-owned e trasporto Docker/nft/systemctl simulato: stato avviato più QUIESCED, membership attiva senza refresh, deriva handle e comandi di mutazione negati, TTL e divergenza fra famiglie, deriva delle sorgenti. I file rimangono byte-identici e gli output non contengono indirizzi/configurazioni private. Questa verifica non prova lo stato root del VPS, che è proprio il dato ancora da acquisire.

SHA256 lettore: `ab61835ef55396ddacf4513acc0f21adbaab1b50ac32ad2fdc4c80a23d1835c8`.

Comando pronto: [provider-r8-post-start-read-20261009.sh](provider-r8-post-start-read-20261009.sh), SHA256 `ba1394dc23b46ccf70d4fcd3b9da1aa61de3110ac604e81b5c69c5bf15cee215`. Pinna il lettore al commit `a5d849de41c11d1218df393d8c8685f1f63e236d`, già riletto da GitHub con corrispondenza dei byte. Usa il gh già presente fuori dal PATH, controlla SHA256 prima del sudo e ricontrolla gli stessi byte in memoria sotto Python isolato. Nessuna nuova approvazione è richiesta per questa lettura già autorizzata; è necessaria soltanto l'esecuzione operatore a causa dei permessi effettivi.

Dopo il risultato: definire l'attivazione concreta della lease con owner esistente e ambito corrente, poi rollout Semantic/MCP e grant discovery. Non ricaricare Teatri, ripetere R8 o ricreare artefatti firmati già conservati. L'evidenza dipendenze Semantic/MCP va aggiornata prima del cutover perché quella precedente è scaduta.

Consegna verificata anche con gh assente dal PATH: il percorso documentato viene riutilizzato. Download fallito o SHA errato non raggiungono sudo; il codice di errore della lettura root resta visibile attraverso tee. Tre test di consegna (quattro scenari), oltre ai cinque del collector. Non è una nuova prova del VPS.

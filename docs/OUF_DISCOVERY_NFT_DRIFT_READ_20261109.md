# Discovery: confronto mirato delle impronte nft

9 novembre 2026. **Lettore qualificato; esecuzione VPS pendente.**

## Fatto e domanda da risolvere

La [ricevuta delle 09:31 CET](../evidence/discovery-coordinator-quiescence-held-operator-20261109.json) riporta NFT_INSTALLATION_STRUCTURE_DRIFT nel controllo di proprietà: due letture nft, zero intento, flush o transizioni. La quiescenza non è avvenuta; il comando precedente non va rilanciato.

Il confronto esatto del proprietario include gli identificativi nativi degli oggetti e metainfo, oltre alle regole. Il footprint di boot esclude handle, metainfo e campi di contatori/scadenza. In una prova nativa, ricreare tabelle con le stesse regole cambia il primo e conserva il secondo. Non conosciamo ancora la causa sul VPS.

## Lettura consegnata

[Wrapper](../scripts/deliver-discovery-nft-drift-20261109.sh), SHA-256 `866263d9273e25c03ab0375d693d0f6ca5b3b9be63fd5643be71c77e7a94f870`; sorgenti al commit [fcc4b80ade8a5d16e44c3e6b60d6305990beec76](https://github.com/GioNob/ouf-deploy/commit/fcc4b80ade8a5d16e44c3e6b60d6305990beec76). Verifica dodici file, poi esegue Python isolato tramite sudo.

Il lettore riusa la ricevuta HELD esatta e il file privato di tabelle conservato prima del diniego. Ricava driver, journal e comando nft dai binding già verificati; acquisisce i lock esistenti dei due runtime, della coorte e delle lease. Legge soltanto le due tabelle del coordinatore, in formato ordinario e numerico, due volte ciascuna: **otto comandi nft di lettura**, nessun inventario generale.

Legge inoltre il puntatore di installazione del boot e segue ricevuta/profilo/configurazioni verificandone gli hash. Confronta questi binding con quelli del driver retained. Sono file installati: non è una lettura della configurazione effettivamente caricata da systemd.

Stampa hash, confronti booleani, conteggi degli oggetti e categorie delle differenze. Regole complete e indirizzi restano nelle evidenze private. Se la baseline di boot è assente o incoerente, lo segnala esplicitamente; il confronto disponibile non viene trasformato in una prova di proprietà.

## Come usare l'esito

| Classificazione | Significato e passo da valutare |
| --- | --- |
| EXPECTED_HASH_MATCHES_NUMERIC_RENDERING_ONLY | La rappresentazione numerica coincide con l'impronta attesa. Valutare la correzione del solo formato di lettura conservando il confronto esatto. |
| INSTALLED_BOOT_OWNER_AND_RETAINED_DRIVER_DIFFER | I binding del proprietario installato e del vecchio driver divergono. Allineare il percorso alla configurazione verificata, senza riscrivere il driver storico alla cieca. |
| BOOT_FOOTPRINT_MATCHES_EXACT_DRIVER_HASH_DIFFERS | Il confronto previsto dal boot coincide, quello esatto no. Compatibile con differenze nei campi esclusi; non prova quando o perché siano cambiati. Qualificare l'eventuale rinnovo del binding prima di intervenire. |
| DRIVER_HASH_AND_BOOT_FOOTPRINT_DIFFER | Anche il confronto del boot diverge. Usare le evidenze per identificare la differenza delle regole/configurazioni prima di qualsiasi correzione. |
| NFT_STRUCTURE_CHANGED_DURING_READ | La struttura cambia durante la lettura. Non trarre conclusioni da uno snapshot instabile. |
| CURRENT_DEFAULT_MATCHES_EXPECTED_PRIOR_FAILURE_NOT_REPRODUCED | Il diniego precedente non si riproduce nella lettura corrente; non attribuirgli una causa inventata. |
| DRIVER_HASH_DIFFERS_BOOT_COMPARISON_UNAVAILABLE | Confronto del boot incompleto, con motivo esplicito nel JSON. Nessuna conclusione di equivalenza. |

Nessuna classificazione attiva automaticamente una modifica. Il lettore non cambia impronte, nft, journal, lease, container o servizi e non chiama DNS, token endpoint, provider, database o S3. Non esegue `Coordinator.quiesce()`. Limite 120 secondi, fino a 32 file di metadata; salva una directory privata `discovery-nft-drift-*`.

## Verifica

[CI 42587680408](https://github.com/GioNob/ouf-deploy/actions/runs/42587680408), job 129061314739: **8 test unitari e 2 prove nftables native, zero skip**, log letti. Le prove coprono byte/hash di boot, driver diverso, rendering, contatori, modifiche a verdetti/ordine/policy, letture instabili e ricreazione reale delle tabelle in namespace isolati. Tutti i dodici sorgenti consegnati sono stati riletti dal commit e confrontati.

La prova nativa copre letture e confronto; non è l'esecuzione dell'intero lettore sul VPS. [Evidenza](../evidence/discovery-nft-drift-read-qualification-20261109.json). F2–F6, quiescenza e nuova ammissione provider restano aperti.

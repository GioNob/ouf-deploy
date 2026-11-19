# R3 v24 — Sorveglianza del lease durante il rinnovo della cache DNS

## Incidente del 19 novembre 2026

Alle 20:18:59 il tick v23 ha registrato `tick → guardEnd → cachePaused → deny`. Il ciclo precedente aveva osservato TTL DNS di 25 e 26 s da SOA negativa, compilato timeout di 22/23 e poi 21/22 s, verificato il nuovo lease e programmato la raccolta a scadenza della cache + 1 s.

Il ramo `[1, 280]` identifica il `return self.r.retry(row, CacheWait(adapter.cache_due))` in `pause_for_cache()` del supervisore v23 emesso. `cache_lease_tick()` confrontava l'orologio con i limiti del **primo** elemento in scadenza. Oltre il limite superiore saltava il readback e chiamava quel ramo. `retry()` invoca `adapter.pause()` prima di calcolare il prossimo risveglio. Con due timeout diversi poteva quindi revocare il secondo flusso ancora valido. La traccia d'esercizio attesta la revoca; l'effettivo residuo del secondo flusso a quel tick non è stato letto. Il test di controllo riproduce lo stesso ramo sulla v23 sigillata con il secondo flusso ancora presente.

## Comportamento al tick

Alla pubblicazione di un lease corto, il supervisore conserva in memoria il digest del `LEASE_READY` e un intervallo di scadenza per ciascun indirizzo, flusso e famiglia. Per l'attesa già ammessa durante un rinnovo con indirizzi invariati usa il campione sotto lock che aveva programmato il rinnovo. Ogni tick ricontrolla autorità, custodia, corrispondenza con il risultato dell'invocazione corrente, journal e ownership delle due tabelle. Rilegge tutti i set sotto il lock comune. Il lock è libero durante DNS e attese.

Per un valore intero nft `n`, la scadenza è compresa fra `inizio lettura + n` incluso e `fine lettura + n + 1` escluso. Il supervisore interseca le riletture con l'intervallo precedente dello stesso elemento. Per un lease appena pubblicato verifica anche la scadenza assoluta dell'evidenza DNS del flusso. Il limite usato per dichiarare il lease attivo e ammettere il commit può solo accorciarsi.

| Riscontro | Azione |
|---|---|
| Tutti gli elementi approvati sono presenti con un residuo positivo dimostrato | Il tick può esporre `ACTIVE`. Il risveglio è limitato da heartbeat, budget, prossimo limite nft e data della raccolta. |
| Un elemento riporta zero nell'ultimo secondo compatibile | Il supervisore sospende la proiezione di disponibilità e continua le letture. Solo il lettore usato per sorvegliare la scadenza accetta lo zero. |
| Uno o più elementi sono scomparsi entro i tempi compatibili | Il supervisore espone `WAITING` e lascia scadere ogni elemento superstite con il suo timeout originale. |
| Entrambe le famiglie risultano completamente vuote | Sotto lo stesso lock, un compare-and-swap registra `QUIESCED` con indirizzi vuoti. Il checkpoint `RETRY_WAIT` punta alla data DNS già programmata. Questa transizione invia **zero transazioni nft**. |
| Un indirizzo scompare troppo presto, ricompare, ha un TTL incompatibile, oppure cambiano journal o ownership | Il supervisore applica la chiusura per difetto. La perdita di autorità e l'esaurimento dei budget mantengono i rispettivi esiti di sicurezza. |

## Raccolta e pubblicazione

Resta valida la data v23, fine del round DNS + minimo TTL limitante + 1 s. La raccolta mirata usa **un solo round** e addebita un tentativo al contatore durevole. L'attesa sorvegliata viene contabilizzata come rinnovo pendente. Si usano gli stessi budget configurati per DNS, lock, tentativo e commit.

Con un lease interamente verificato e tempo sufficiente, la pubblicazione usa il rinnovo ordinario sotto lock, limitato dalla scadenza del lease uscente e dalla deadline di un eventuale rinnovo già ammesso. Se il lease è già scaduto, la raccolta usa il percorso di recovery da quiescenza verificata. Se alla data DNS resta solo una parte dei flussi, o il residuo non permette i due controlli di commit, il DNS parte alla data prevista. La pubblicazione da quiescenza attende il readback vuoto anche dell'ultimo elemento. Ricompila quindi con le scadenze assolute dell'evidenza già raccolta, entro la deadline del tentativo. Questo distingue l'istante della raccolta dal primo istante sicuro di pubblicazione.

Una seconda risposta ancora corta produce `cacheShort` e backoff ordinario. Continuano ad applicarsi readback post-apply, controllo di cancellazione e riconciliazione degli esiti ambigui. Dopo un riavvio, il solo checkpoint `ACTIVE` richiede la riconciliazione prevista per un'altra invocazione.

## Traccia e qualifica

Nella traccia del tick, un `cacheWait` successivo al readback indica attesa sorvegliata. Un `cachePaused` successivo al readback indica la scomparsa osservata di almeno un elemento. Nella frazione con TTL intero zero e membership completa il tick può esporre `WAITING` e registrare `cacheWait`. Al readback interamente vuoto il checkpoint registra `cachePaused`. La raccolta e il suo esito restano visibili tramite `cacheCollect`, `cacheRenewed`, `cacheShort` e `cacheFailed`. I lettori v23 accettano già questi eventi e i loro quattro valori monotoni.

La suite usa il bootstrap emesso, i pacchetti DNS di prova, un clock controllato e quattro set nft simulati. Sul medesimo ingresso 25/26 s verifica il ramo v23, poi sulla v24 controlla che il tick tardivo conservi il secondo flusso fino a scadenza. Conta le transazioni nft, le transizioni del journal e gli ingressi effettivi nel DNS. Copre anche il flusso superstite alla data di raccolta, il TTL persistentemente corto, la deriva di membership e timer, la perdita di autorità e la cancellazione prima di pubblicare `LEASE_READY`. [Suite v24](../tests/test_semantic_provider_r3_v24.py)

## Composizione e upgrade

Per issue, upgrade e operate usare `C.DATA_INPUTS_V24`, `C.SOURCE_INPUTS_V24` e `C.SOURCE_MAP_V24`. Gli input corrispondono a quelli della v23. Al compositore occorre distribuire anche `cache_watch_overlay_v24.py`. L'overlay precede l'unico sigillo dei sorgenti, che riusa i digest per i pin interni, gli alias e il manifest. La qualifica esercita emissione ordinaria, upgrade 23 → 24, golden storici e conservazione degli ancoraggi LF/CRLF. La durata della pausa sul VPS richiede una misura in esercizio.

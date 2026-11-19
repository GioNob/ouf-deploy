# R3 v21 — Tempi del rinnovo del lease (R-022)

La riga `step=supervisor` di `r3-status.py` espone la traccia in `leaseRecovery.lastIncident.timing`. Per la firma `READBACK / DNS_WINDOW_TOO_SHORT` con deadline nulla e residuo di 22.000 ms, partire dal campione del tick corrente e risalire al batch che ha installato il lease. Il TTL DNS può spiegare uno scarto fra flussi. La frequenza e la distribuzione degli stalli in esercizio richiedono una cattura v21.

## Come leggere un incidente

1. In `current.events` cercare la terna `sampleBefore`, `expires`, `sampleAfter` sotto il lock del sito 0. Per ogni flusso sono disponibili due minimi, in ordine `inet`, `bridge`. Il codice calcola `D = before + minimo globale` e `R = D − after`. Confrontare R con il margine di `sampleBefore`. Un residuo di 22.000 ms all'ingresso di `READBACK` può quindi accompagnare un R inferiore a 22 s al termine del campione.
2. In `previous.events` individuare l'ultima `compile` seguita da `applyEnd(true)` e `readyEnd`. I record `timeout` successivi a quella compilazione contengono i secondi per flusso calcolati per il batch. Confrontarli con i minimi `ttl` dell'ultimo `dnsRound` dello stesso tentativo. Un minimo specifico di flusso può limitare il timeout anche con una raccolta rapida.
3. Misurare in secondi `wake − wait − durata richiesta` per il ritardo di risveglio, `dnsEnd − dnsStart` per la raccolta e `compile finale − dnsEnd` per il lavoro successivo. Usare `lockStart → acquired → released` per distinguere l'attesa dal lavoro sotto lock. I dump, la verifica e la pubblicazione delimitano il tempo consumato dopo la compilazione. Il tratto da `readyEnd` precedente a `sampleBefore` corrente comprende anche il lavoro del supervisore tra i due cicli. Le durate annidate si sovrappongono.
4. Leggere `branch` sul sorgente **emesso** della stessa versione. Punta alla riga del diniego anche quando la v20 rimappa più rami nello stesso codice pubblico. Un intervallo lungo localizza il tratto di codice coinvolto. Per attribuirlo a I/O, descheduling o a un altro processo occorrono osservazioni aggiuntive.

Nella prova offline di rinnovo lento, entrambe le compilazioni ricevono lo stesso termine DNS. La prima avviene al secondo 105, la seconda a 111,5, dopo un guard lento sotto lock. Il batch scrive 22 s per entrambi i flussi. Il tick misura `before=111,5`, minimi 22/22, `after=111,75`, `D=133,5` e `R=21,75`. La soglia di 22 s determina il diniego. In una seconda prova una SOA da 8 s sul flusso 1, assieme al tempo di raccolta, produce timeout di 27 s sul flusso 0 e 5 s sul flusso 1.

## Schema di timing

`schema` vale `ouf.lease-renewal-timing.v1`. `current` è il ciclo del primo guasto. `previous` è il ciclo precedente che ha avviato un rinnovo o una pubblicazione di recupero, oppure `null` all'inizio dello scope. Ogni ciclo contiene `sequence`, `events` e `truncated`. La sequenza cresce per tick nello stesso scope, anche in presenza di attese di recupero. Confrontare tempi monotonici soltanto nello stesso scope.

Ogni evento ha la forma `[tag, istanteMonotono, ...valori]`. Tutti i tempi e i TTL sono in secondi, anche frazionari per il clock. Il registro dei flussi segue l'ordine di `providerFlows` a partire da zero. Il produttore conserva soltanto i valori indicati nella tabella.

| Tag | Valori dopo l'istante | Significato |
|---|---|---|
| `tick`, `plan`, `wait`, `wake`, `renew` | Durata per `plan` e `wait` | Inizio del tick, pianificazione conclusa, ingresso nell'attesa, ritorno dall'attesa e inizio del rinnovo. Il fast retry può aggiungere altre coppie di attesa. |
| `guardEnd` | Nessuno | Custodia e scope verificati. |
| `leaseLimit`, `attemptLimit`, `planLimit` | Deadline monotona assoluta | Scadenza del lease uscente, del tentativo di preparazione e del piano compilato. |
| `dnsStart`, `dnsRound`, `dnsEnd` | Conteggio UDP per `dnsEnd` | Ingresso nella raccolta, risultati di un giro fresco, uscita anche per errore. Il conteggio somma i tentativi UDP iniziati entro l'uscita per query, resolver e giri di questa raccolta. |
| `ttl` | Indice flusso, TTL minimo, booleano SOA | Minimo osservato prima del cap e della sottrazione del tempo trascorso. Il flag è vero quando una SOA negativa contribuisce al minimo, anche a pari merito. Un CNAME più corto della SOA dà falso. Un flusso senza risposta completa del resolver può mancare dal giro. |
| `lockStart`, `acquired`, `released` | Sito | Richiesta, ingresso e ritorno dal rilascio del lock comune. Un'acquisizione fallita lascia il solo inizio. |
| `compile`, `timeout` | Per `timeout`, indice flusso e secondi interi | `compile` usa l'istante passato al compilatore. I timeout appartengono all'ultima compilazione e sono disponibili quando il piano ammette il batch. |
| `apply`, `applyEnd` | Booleano di esito per `applyEnd` | Esecuzione di `nft -f -`. Falso indica che la chiamata ha sollevato un errore. L'effetto nel kernel resta da accertare con il readback. |
| `dump`, `dumpEnd` | Famiglia, più esito per `dumpEnd` | Comando di lettura della tabella. Famiglia 0 per `inet`, 1 per `bridge`. |
| `verify`, `verifyEnd`, `ready`, `readyEnd` | Nessuno | Verifica finale di ownership e guard, poi CAS del coordinatore che pubblica `LEASE_READY`. Il marcatore finale richiede il ritorno della chiamata. |
| `sampleBefore`, `expires`, `sampleAfter` | Margine per `sampleBefore`. Indice, minimo inet e minimo bridge per `expires`. R e D per `sampleAfter`. | Campione di `sample_locked` sotto il lock dello scheduler o della verifica del lease precedente. Su errore precoce possono essere disponibili solo i primi eventi. |
| `deny` | Nessuno | Cattura del primo guasto da parte di `Incident.failed`. |

I siti del lock sono 0 per `window`, 1 per `publish_renewal`, 2 per `prove_retry`, 3 per `publish` di recupero, 4 per `pause`, 5 per `quiesce` del coordinatore e 6 per altri chiamanti.

`branch = [indiceModulo, riga]` usa righe a partire da uno. Per un'eccezione il produttore cerca il punto più interno nel codice riconosciuto e risale dal generico `require` al controllo chiamante. Per una decisione diretta usa il sito della chiamata. I moduli da 0 a 8, nell'ordine, sono `adaptive_supervisor`, `continuous_supervisor`, `resilient_lease_adapter`, `dns`, `nft_seconds_backend`, `deadline_backend`, `readback_margin_compiler`, `bounded_recovery` e `lease_recovery_budget`. Seguono `semantic_common_lock_v2` (9, alias di `locking.py`), `semantic_provider_lease_coordination` (10), `lease_supervisor` (11) e `recovery_journal` (12).

Il checkpoint riceve la copia congelata attraverso il CAS di recupero esistente. Le fasi del rinnovo aggiornano due buffer in memoria, fino a 1.024 eventi ciascuno. Al guasto ogni copia usa al massimo 28 KiB per gli eventi, entro il limite storico di 64 KiB del record completo. `truncated=true` indica omissioni per limite o per una misura numerica invalida. In caso di capienza esaurita hanno priorità gli eventi più recenti. Il lettore verifica campi, tipi, intervalli, indici e versione. Un incidente storico privo di traccia espone `timing=null`. Revoca, retry e ripresa possono aggiornare il resto dell'incidente conservando il primo campione.

## Consegna nei runbook v21

- In issue, upgrade e operate selezionare `C.DATA_INPUTS_V21` e `C.SOURCE_INPUTS_V21`. I due insiemi e `C.SOURCE_MAP_V21` coincidono con la v20, incluso il file privato `leaseRenewal` con il suo digest.
- Consegnare `tools/semantic_provider_r3/lease_timing_overlay_v21.py` insieme al compositore e agli overlay precedenti. L'overlay è una dipendenza del compositore esterna a `inputs.json["sources"]`. Fissare i digest LF di overlay e `compose.py` al commit approvato e allineare il `MANIFEST` di autostart alla consegna di operate.
- Seguire l'upgrade ordinario v20 → v21 con provider fermi e coordinatore quiescente. Verificare in issue il successore della testa v20 e in upgrade i binding di wrapper, unità e documenti sotto `versions/21`. Il sigillo finale lega una volta i moduli emessi ai pin del supervisore e agli hash verificati dal bootstrap. Il runtime usa ancora il digest già ammesso.
- Per il lettore, Claude fissa il pin di commit lasciato a quaranta zeri in `r3-readers-install.sh`. Il manifest include il digest LF aggiornato di `r3_common.py`. Dopo la consegna, usare il normale plan/apply del lettore e consultare la riga del supervisore al primo incidente.

Le prove in worktree usano clock, resolver e comandi nft simulati. L'osservazione degli incidenti reali inizia dopo l'upgrade operativo. [Suite v21](../tests/test_semantic_provider_r3_v21.py) · [Upgrade R3](OUF_SEMANTIC_PROVIDER_R3_UPGRADE.md)

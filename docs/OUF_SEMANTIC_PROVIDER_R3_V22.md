# R3 v22 — rinnovo immediato del lease g2

D-054 / R-022. Nell’incidente v21, il kernel ha restituito 20 s su entrambe le famiglie. La lettura ha consumato 42,60 ms, lasciando 19,9574 s. La v22 ammette un rinnovo con questo residuo. Il lease autorizzato dura sempre al massimo 30 s.

## Budget e scelta della fascia

Il documento di installazione `leaseRenewal` v22 contiene `dnsTimeoutSeconds=6`, `lockWaitSeconds=3`, `immediateMinimumSeconds=19` e `renewalMarginSeconds=22`. Il driver usa il proprio `driverBudgetSeconds=12`. Composizione e avvio eseguono lo stesso validatore sigillato. Il profilo DNS derivato viene vincolato nell’autorizzazione, confrontato con il file emesso all’avvio e passato al costruttore di `LeaseOwner`. Il nuovo profilo si applica anche ai template dei due ruoli.

| Componente | Secondi | Motivo |
|---|---:|---|
| max(DNS + lock, driver) | 12 | La raccolta precede l’attesa del lock. Il driver ha un orizzonte indipendente. |
| Apply | 1 | Deduzione del compilatore e limite assoluto del piano di mutazione. |
| Minimo nft | 2 | Timeout intero minimo richiesto dal compilatore. |
| Commit | 1 | Riserva sulla scadenza del lease uscente. |
| Guard | 1 | Margine del validatore di rinnovo. |

Il pavimento vale `max(6 + 3, 12) + 1 + 2 + 1 + 1 = 17 s`. La prima qualifica riserva altri 2 s a scheduling e lavoro residuo. Il validatore richiede `pavimento + 2 ≤ M < margine`, oltre ai vincoli v18 su durata effettiva, tentativo e ritardi. **Il minimo ammissibile è quindi 19 s.** Sono condizioni di ammissione. Il clock monotono, le deadline dei comandi e i controlli prima e dopo la pubblicazione determinano l’esito del singolo tentativo.

| Residuo monotono R | Decisione |
|---|---|
| R ≥ 22 s | Pianificazione v21, inclusi il limite del poll, il heartbeat e il margine di guardia. |
| 19 s ≤ R < 22 s | Attesa zero. All’ingresso di `renew()` si ricalcola il residuo e si ammette un solo tentativo di rinnovo. Dopo aver riservato il commit, anche la deadline limitata da scope e timeout del tentativo deve coprire almeno 18 s. |
| R < 19 s | Diniego e percorso di revoca, anche se lo scheduler aveva ammesso il rinnovo prima del risveglio. |

La deadline originaria deriva dal minimo fra scadenza campionata meno commit, tempo di scope e timeout del tentativo. Il lock può ulteriormente accorciare la finestra in funzione dell’evidenza DNS. Un timeout di acquisizione abbandona il rinnovo. La revoca usa il suo budget indipendente. Sotto lock il supervisore confronta il journal atteso, verifica la membership esatta e i TTL del lease uscente in `inet` e `bridge`, poi ricompila dalle stesse scadenze DNS assolute. Il limite operativo include `mustApplyByMonotonic`. La pubblicazione di `LEASE_READY` richiede readback esatto di entrambe le famiglie, ownership, scope, controllo di cancellazione e tempo residuo. Un errore dal primo CAS di `LEASE_UPDATING` fino al rilascio del lock dopo il CAS finale richiede riconciliazione. Il supervisore tenta la chiusura e registra l’esito della revoca.

## Raccolta e lettura della traccia

Una coda per round distribuisce le coppie flusso/tipo dei resolver selezionati a un massimo di otto worker. Il supervisore condivide il registro dei worker vivi fra i due moduli DNS caricati. Un worker ancora occupato conta anche per il round successivo. Le query dipendenti di una catena CNAME usano in sequenza lo stesso resolver. Il cutoff chiude la raccolta di risultati ed eventi. Per ciascun resolver/flusso servono entrambe le risposte tipizzate. Un errore d’integrità completato entro il cutoff ha precedenza su un resolver mancante. Il TTL usa i minimi di indirizzi, CNAME e SOA negativa, con la consueta sottrazione del tempo di raccolta.

Ogni tentativo UDP ha un socket connesso, un ID nuovo e un massimo di 1 s di attesa, entro la deadline comune. Dopo il ritorno di `recv`, una risposta con ID corrispondente passa alla validazione del protocollo se la deadline comune è ancora aperta. Un ID estraneo richiede un’altra lettura entro il tempo residuo del tentativo. Il flag TC su una risposta validata apre il percorso TCP sulla deadline comune.

In `leaseRecovery.lastIncident.timing`, ogni evento DNS aggiunge al tag e al timestamp monotono gli indici di resolver, flusso e tipo (0 per A, 1 per AAAA), la profondità CNAME (0–8), il tentativo UDP (1–3) e due slack con segno, in secondi. Il primo è relativo alla fine del tentativo UDP, il secondo alla deadline comune dello scambio. Un primo slack negativo su `dnsRecv` permette di individuare il caso C.2. Il timestamp è quello osservato dal worker al ritorno della chiamata.

| Evento | Misura |
|---|---|
| `dnsSend`, `dnsRecv` | Invio UDP riuscito e ritorno di ciascun datagramma. L’ultimo booleano di `dnsRecv` segnala un ID scartato. |
| `dnsTimeout` | Timeout del tentativo UDP. |
| `dnsTcpFallback`, `dnsTcpSend`, `dnsTcpRecv` | Decisione di fallback su TC, invio della query TCP e ritorno del messaggio completo. |

La traccia del primo incidente mantiene i limiti v21 di 1.024 eventi per ciclo, 28 KiB per copia congelata e 64 KiB per record. Per ricostruire uno scambio usare gli indici e la cronologia dei round. Un frame saturo espone `truncated=true`. La traccia contiene solo scalari e indici.

## Pin di consegna dei runbook v22

SHA-256 dei blob LF della worktree. Issue, upgrade e operate selezionano `C.DATA_INPUTS_V22` e `C.SOURCE_INPUTS_V22`. La mappa `C.SOURCE_MAP_V22` mantiene le destinazioni v21. Il nome logico `leaseRenewal` seleziona il nuovo JSON. I due overlay sono dipendenze di consegna di `compose.py`, esterne all’elenco sigillato `inputs.json["sources"]`.

| File | SHA-256 |
|---|---|
| `ops/vps/r3-lease-renewal-v22.json` | `7a53b38d9ecc3f75f1221a637d0c439bc0d31291fdcaedc4daf0414eaa122d53` |
| `ops/vps/r3-driver-budget.json` | `2fc0921fd26cdb69adf6ab7dc683b3fea321bb59c5db24db95428d7ac59a1e16` |
| `tools/semantic_provider_r3/compose.py` | `0f1d56a4165d447d339decefad77e85ed2ff7563e3ddc3b68c39bd99a80e85d9` |
| `tools/semantic_provider_r3/renewal_overlay_v22.py` | `81e6e20760b4ea88aa757a1edee60e4436d23bc90d7504dd0f093690176173a7` |
| `tools/semantic_provider_r3/dns_parallel_overlay_v22.py` | `9a11956689e6bc5263be8a8931b5c99b987f6c61225accbd1e38f518d26260a6` |
| `ops/vps/readers/r3_common.py` | `128e4657197a57db837f1c5a4bfc524ab47a0962fd33530aa5b2f9370a68ec27` |

Claude rigenera i runbook sul commit approvato, compresi il `MANIFEST` di autostart e il manifest di `r3-readers-install.sh`. Il controllo di consegna del lettore confronta ancora il nuovo file con il digest v21 e segnala il disallineamento fino alla rigenerazione. Il sigillo interno calcola una sola volta i digest finali dopo gli overlay e li riusa per i pin del supervisore, il bootstrap e gli alias. Il DNS emesso ha digest `b173ff2fc2f5ac2c89b0256a09ca56756d14f15251de46713dc2421e6a9bfc19`. Il runtime ha il digest già ammesso `90166dcb75ab640dc1ebb536f016f6fdda7fdb49c672d03e8a3c45350c0438c9`.

## Qualifica

La suite offline riproduce due raccolte DNS da 5,05 s, un lease intermedio da 21 s e la successiva lettura a **19,9574 s**. Verifica due pubblicazioni `ACTIVE / RENEWED`, quattro set kernel simulati e zero revoche. Copre i due lati di M, l’ingresso a 22 s, la perdita persistente, il lock occupato oltre 3 s, la cancellazione, il TTL corto, la membership discordante e l’apply ambiguo. Una barriera verifica otto query concorrenti. Il trasporto simulato esercita CNAME, fallback TCP, ID estraneo, ritorno UDP oltre il secondo e scarto dei worker tardivi. Il percorso di upgrade ricompone il successore ordinario della testa v21 con owner g2 e autorizzazione di sequenza 22. [Suite v22](../tests/test_semantic_provider_r3_v22.py)

La qualifica operativa prevista dal report 103 resta la finestra di 60 minuti sul VPS, con almeno un rinnovo rallentato e conteggio delle revoche sull’intero intervallo. Le prove della worktree usano resolver, clock, comandi nft e stato di upgrade controllati.

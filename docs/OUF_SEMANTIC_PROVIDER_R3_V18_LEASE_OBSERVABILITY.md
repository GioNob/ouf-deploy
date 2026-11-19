# R3 v18 — Osservabilità del recupero del lease

D-054, R-022, task-77. Il journal CAS di ciascuno scope conserva il checkpoint
corrente e l'ultimo incidente. L'overlay si applica dopo il rinnovo sugli
stessi percorsi. La composizione sigilla la chiusura dopo entrambi gli overlay.
[Integrazione v18](OUF_SEMANTIC_PROVIDER_R3_V18.md#integrazione-con-losservabilità).

## Checkpoint e cronologia dell'incidente

`lastIncident` è `null` all'apertura dello scope. Il primo guasto che entra in
recupero o chiude lo scope apre un incidente. I retry durante lo stesso
episodio conservano il guasto iniziale e aggiornano il prossimo retry
pianificato. La successiva pubblicazione verificata di `LEASE_READY` chiude
l'incidente. I rinnovi sani lo conservano e un nuovo episodio nello stesso
scope lo sostituisce, incrementando `incidentCount`. Un nuovo scope ha un
riferimento distinto e un contatore proprio.

Il checkpoint `ACTIVE / RENEWAL_RETRY_PENDING` apre un incidente e registra
il retry rapido in `lastIncident.nextRetryAt`. Durante il retry il lease
resta attivo. Il valore `UNPROVEN` indica l'assenza di una verifica di revoca
e copre anche il retry riuscito con lease mantenuto. In quel caso `pausedAt`
resta `null` e `resumedAt` segna il completamento del rinnovo verificato.
Se il percorso passa alla revoca, l'incidente conserva la causa iniziale e
registra `VERIFIED` e `pausedAt` dopo la verifica della quiescenza.

Il record ha schema `ouf.semantic-lease-recovery-incident.v1`. `scopeRef` è il
riferimento opaco del checkpoint. `authorizationSequence` ed `epochs` sono
quelli dello scope all'apertura. `stateAtFailure` è lo stato del checkpoint
in cui è avvenuto il guasto. `code` ammette solo codici espliciti e usa
`UNCLASSIFIED_FAILURE` quando manca una classificazione pubblica.

| Campo | Significato |
| --- | --- |
| `failedAt` | Istante del guasto, prima della revoca quando il guasto la innesca |
| `pausedAt`, `revocation` | Istante della prima verifica riuscita della quiescenza. Con `UNPROVEN`, `pausedAt` è `null` |
| `resumedAt` | Istante della pubblicazione con rilettura di `LEASE_READY`, riportato dal successivo checkpoint `ACTIVE` |
| `nextRetryAt` | Ultimo retry pianificato per l'incidente, conservato dopo la ripresa |
| `leaseRemainingMs` | Residuo conservativo del lease all'ingresso della fase. Vale `null` quando manca un campione utilizzabile |
| `lockWaitMs` | Durata monotona misurata per l'acquisizione osservata, anche se scade. Vale `null` se la fase precede l'acquisizione |
| `deadlineMonotonic` | Deadline assoluta del tentativo, in secondi monotoni, ristretta alla finestra di pubblicazione se già nota. Vale `null` quando non è disponibile |

I quattro orari dell'incidente sono secondi Unix. La deadline monotona si
interpreta nel boot del supervisore. `phase` distingue `PLAN`, `DNS`,
`LOCK_ACQUIRE`, `COMPILE`, `APPLY`, `READBACK`, `COMMIT` e `REVOKE`. Se alla
revoca si arriva dopo un guasto, la fase del guasto resta visibile e l'esito
della revoca ha un campo proprio. Il record contiene solo identificativi
opachi, stati, codici chiusi e scalari. Il checkpoint resta limitato a 64 KiB.

## Lettura operativa

La riga `supervisor` di `r3-status.py` include `updatedAt`, in secondi Unix, e
`leaseRecovery`. L'oggetto mostra lo scope del checkpoint, lo stato, i
tentativi, il retry attualmente pendente e `lastIncident`. Il lettore usa il
selettore privato dello stato per leggere un solo checkpoint sotto
`supervisor/state/recovery` nella root fissa. Verifica il binding alla
configurazione, apre le directory senza seguire link simbolici e controlla
custodia, limite di lettura e stabilità del file. La lettura è senza lock e
la fotografia può attraversare un aggiornamento concorrente.

Con uno stato storico privo del selettore, `leaseRecovery` vale `null`.
Un checkpoint selezionato privo dell'incidente restituisce
`leaseRecovery.lastIncident = null`. I file e i relativi hash di consegna
sono riportati nel [runbook di installazione dei lettori](OUF_R3_READERS.md).

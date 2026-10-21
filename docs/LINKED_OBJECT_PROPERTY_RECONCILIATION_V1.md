# Riconciliazione delle proprietà dopo un collegamento di identità

Policy approvata dall'utente il 17 ottobre 2026. Riferimento: `urn:ouf:policy:linked-object-property-reconciliation:v1`.
La specifica verificabile è in [policies/linked-object-property-reconciliation-v1.json](../policies/linked-object-property-reconciliation-v1.json).

## Effetto del collegamento

Confermare che un record sorgente e un oggetto rappresentano la stessa identità abilita il collegamento della provenienza. Non autorizza la sostituzione indiscriminata delle proprietà dell'oggetto né una fusione di altri oggetti. Ogni contributo resta associato al record sorgente, all'acquisizione, alla versione della mappatura e alla classificazione di accesso.

| Condizione | Risultato richiesto |
| --- | --- |
| Proprietà presente solo nell'oggetto corrente | Conservare il valore. Assenza, null e stringa vuota nel CSV non significano cancellazione. |
| Proprietà presente solo nel nuovo record | Aggiungere il contributo valido e autorizzato. |
| Valori uguali dopo normalizzazione dichiarata | Mostrare il valore una volta; conservare tutte le provenienze e i valori originali. |
| Valori diversi per proprietà singola | Applicare la priorità esplicita delle fonti valide. In assenza di un vincitore autorizzato, aprire un conflitto sulla sola proprietà. |
| Conflitto irrisolto | Conservare il precedente valore con indicatore di conflitto, oppure lasciare il campo non determinato se non esisteva un valore. Le altre proprietà valide possono avanzare. |
| Proprietà dichiarata multivalore | Unire i valori distinti secondo il normalizzatore versionato, conservando provenienza e accesso per elemento. Nessuna divisione automatica di stringhe. |
| Cancellazione | Accettare soltanto un'operazione esplicita prevista dal contratto della fonte e dalla sua autorità; conservare la storia. |

Non esiste una priorità universale della fonte più recente. La priorità va dichiarata per proprietà; l'aggiornamento di uno stesso record richiede un contratto di revisione o validità temporale. Due righe diverse della stessa fonte non possono essere ridotte a una sola scelta solo perché hanno lo stesso `sourceId`.

Il confronto normalizzato non elimina gli originali. Senza normalizzatore dichiarato si usa l'uguaglianza canonica tipizzata; non si inventano sinonimi o equivalenze di nomi, indirizzi o numeri. Una fonte autorevole può prevalere per l'indirizzo e non per il telefono. I tempi di validità hanno un significato diverso dal momento di acquisizione.

## Revisione dell'operatore

La schermata deve distinguere valore corrente, valore in ingresso e risultato previsto. Deve evidenziare aggiunte, provenienza, regola applicata e conflitti. La scelta di identità e l'eventuale scelta di una proprietà controversa restano separate; rinviare una proprietà non equivale a respingere tutta l'identità.

Ogni decisione su una proprietà si lega a oggetto, tenant, proprietà, revisione corrente, insieme di evidenze e versione della policy. Se le evidenze cambiano serve una nuova verifica. La nota facoltativa per la decisione di identità non cambia implicitamente i requisiti di una diversa operazione di override dell'autorità.

## Riscontro del codice installato e limiti di attivazione

Valutazione del sorgente UDP `6a306b0b8235ad1696dff13d5053c5157750752d`, installato dal rollout `resolution-comparison-execution-di_tb213`.

| Regola | Riscontro |
| --- | --- |
| Separazione identità/proprietà | `IdentityGovernanceService` collega l'identità; `CanonicalMaterializer` produce contributi e revisioni. |
| Provenienza e storia | `property_contribution`, `object_revision` e le osservazioni sono append-only; `CanonicalMaterializer.provenance` conserva i riferimenti. |
| Campo assente | `contribute` salta i campi non presenti; il materiale corrente conserva le altre proprietà. |
| Priorità tra fonti e conflitto | `PropertyEvidence.top` usa `authorityOrder`; `selectWinners` registra conflitti tra valori diversi a pari priorità e mantiene il precedente valore. |
| Decisione umana sul conflitto | `PropertyGovernanceService` lega la scelta a revisione, evidenze e policy con controllo di autorizzazione. |
| Valori multivalore, normalizzazione e tutte le provenienze del valore coalescente | Da implementare e qualificare esplicitamente: il profilo attuale non espone una regola di unione o un normalizzatore di proprietà. |
| Null/vuoto distinti da cancellazione | Non sufficiente: un campo JSON presente con null viene attualmente contribuito come valore. La nuova policy richiede trattamento esplicito. |
| Due righe diverse nella stessa fonte | Da correggere: `PropertyEvidence.top` sceglie attualmente un contributo per `source_id`, con ordine temporale. Questo non garantisce la conservazione dei conflitti tra record diversi collegati allo stesso oggetto. |
| Anteprima del risultato per proprietà e indicatore del valore corrente controverso | Da completare nella superficie operatore. Il confronto di identità attuale non equivale a questa anteprima. |

Questa è una **specifica approvata, non ancora attivata nel runtime** e non è un `UdpPorts.MaterializationProfile` nativo. Non va inviata al publisher come se fosse un profilo supportato. L'attivazione richiede implementazione, test e pubblicazione delle regole native per le proprietà interessate. Nessun dato è ricalcolato da questo documento.

## Collaudo richiesto per l'attivazione

1. Collegamento con campi complementari: un oggetto, unione delle proprietà, provenienze conservate.
2. Campo assente/null/vuoto: nessuna perdita del valore corrente senza contratto di cancellazione.
3. Valori equivalenti normalizzati: una presentazione, entrambi gli originali rintracciabili.
4. Valori singoli diversi con priorità: vincitore deterministico secondo fonte e validità; nessuna regola globale di ultimo arrivo.
5. Pari autorità con valori diversi: conflitto sulla sola proprietà, altre proprietà avanzano.
6. Campo multivalore: unione senza duplicati, provenienza e autorizzazione per ogni elemento.
7. Due record differenti della stessa fonte: nessun conflitto nascosto dall'ordine delle righe o dal solo `sourceId`.
8. Ripetizione dello stesso handoff e riacquisizione: idempotenza e storia, nessun duplicato di identità o contributo.
9. Decisione umana su evidenze cambiate: rifiuto della scelta obsoleta, nessuna applicazione su proprietà estranee.
10. Isolamento tenant, classi e classificazioni: nessuna divulgazione o riduzione del livello di accesso durante il confronto o l'unione.

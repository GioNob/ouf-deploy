# R3 v20 — Ritrasmissione delle query DNS del lease (D-054, R-022)

## Causa del ritardo osservato

Il 19 novembre 2026 una cattura in sola lettura sul VPS v19 ha campionato
ogni secondo `provider_0` e `provider_1` nelle famiglie nft `inet` e
`bridge`. In regime normale il rinnovo arrivava ogni 4–5 s, scriveva timeout
di 26–27 s e il residuo campionato restava almeno a 21 s. Alle 15:41 si è
aperto un intervallo di circa 10 s senza rinnovi. Il residuo osservato è
sceso da 22 a 13 s. Il batch successivo ha scritto timeout di 18 s. Sono
seguite chiusura e revoca con `phase=READBACK`, `code=DNS_WINDOW_TOO_SHORT`
e `deadlineMonotonic=null`.

Lo stallo coincide con il budget DNS complessivo di 10 s. In v19 una query
UDP senza risposta può aspettare tutto il budget residuo. `exchange` invia
un solo datagramma per resolver, nome e tipo. Le 50 query di prova ai due
resolver hanno risposto in 26–222 ms, con TTL del record di circa 24 h. Alla
cadenza stimata di circa 53 query/minuto, una probabilità di perdita dello
0,4% darebbe una risposta persa ogni cinque minuti circa. Il tasso è una
stima compatibile con la cadenza degli stalli. La cattura nft misura i
timeout e il residuo dei set, mentre la perdita del datagramma all’origine
del singolo stallo resta inferita.

Nel percorso effettivo dalla v11 il compositore usa `dns_v2.py` sia per
`tools/semantic_provider_dns.py` nel lease owner sia per
`tools/semantic_lease_recovery/dns.py` nel rinnovo e nel recupero. I resolver
sono già concorrenti. Ogni worker interroga A e AAAA in sequenza per ogni
endpoint, con raccolta entro un’unica deadline. Un resolver bloccato può
trattenere la raccolta fino al limite anche quando l’altro ha risposto.
La formula `min(min(ttls), maxLeaseSeconds) - ceil(elapsed)` sconta il tempo
speso nella raccolta anche con TTL di 24 h. Il compilatore sottrae poi il
margine di applicazione e conserva le scadenze assolute. [Client DNS v19](../tools/semantic_lease_recovery/dns_v2.py) · [Compilatore](../tools/semantic_lease_recovery/materialize_southbound_lease_refresh_v2.py)

### Riproduzioni del task-85

La diagnosi conservata nel commit `8406eb75` ha riprodotto due guasti
distinti con clock, DNS e nft simulati. Uno zero nel vecchio elemento
`bridge` durante `prior_lease` ha fatto revocare prima di un nuovo batch.
Uno zero iniettato nel primo readback dopo un batch da 29 s ha causato la
stessa fase e lo stesso codice con revoca verificata. Il caso positivo ha
rinnovato con 22 s residui e prove DNS fresche. Le due riproduzioni
mostrano che `READBACK` copre sia la verifica precedente al batch sia la
rilettura successiva. Con `deadlineMonotonic=null` resta indeterminato dove
sia stato letto un eventuale zero nell’incidente delle 15:41. Il parser
continua a richiedere `0 < expires <= leaseSeconds` e il compilatore
continua a negare un timeout sotto 2 s. [Rinnovo v18](OUF_SEMANTIC_PROVIDER_R3_V18.md) · [Schema di osservabilità](OUF_SEMANTIC_PROVIDER_R3_V18_LEASE_OBSERVABILITY.md)

## Ritrasmissione v20

- Ogni query dispone di al massimo tre invii UDP, incluso il primo. Ogni
  invio ha un secondo dalla partenza del tentativo, ridotto al residuo
  della deadline DNS condivisa. Il client controlla il residuo prima di
  connettere, inviare e ricevere. Scaduto il tentativo chiude il socket e
  riprova con un socket nuovo e un identificativo casuale distinto da
  quelli già usati nello stesso scambio.
- Un datagramma con intestazione DNS e identificativo diverso viene
  ignorato entro lo stesso tentativo. `response(...)` verifica la risposta
  attribuita alla query con gli stessi controlli su intestazione, domanda,
  tipo e record. Una risposta valida con TC passa a TCP sullo stesso
  resolver con la stessa query e la deadline complessiva. Il limite UDP
  di un secondo termina con quel tentativo.
- Il timeout per tentativo e il numero di tentativi sono interi fissati
  nell’overlay. Il compositore verifica che il loro prodotto rientri nei
  10 s del profilo. Questa scelta consente di riusare `leaseRenewal` e il
  suo digest. Più tipi, nomi e flussi condividono sempre i 10 s. L’assenza
  persistente di risposte conserva i percorsi di diniego e revoca e i
  codici già accettati dai lettori.
- Il numero di worker e l’ordine A/AAAA per resolver restano quelli v19.
  Aggiungere concorrenza all’interno dei worker aumenterebbe le query in
  volo e richiederebbe di riqualificare la raccolta delle risposte, inclusa
  la precedenza dei dinieghi di integrità. Restano applicate le regole
  esistenti di aggregazione dei resolver, policy degli indirizzi, TTL e
  tempo trascorso. Il retry UDP avviene fuori dal lock e dentro la stessa
  osservazione DNS.

`lastIncident` conserva schema e codici compatibili. La distinzione tra
deadline esaurita e finestra DNS insufficiente richiede di trasportare la
causa dal client ai punti che classificano l’incidente e qualificare
insieme l’allowlist dei lettori. Il task-85 propone inoltre
`NFT_READBACK_TTL_ZERO` per lo zero intero effettivamente rilevato dal
parser. Entrambe le estensioni restano successive a questa consegna.

## Consegna da fissare nei runbook v20

- Per issue, upgrade e operate selezionare `C.DATA_INPUTS_V20` e
  `C.SOURCE_INPUTS_V20`. Gli insiemi hanno gli stessi elementi della v19,
  incluso `files["leaseRenewal"]` con copia privata e digest di
  `ops/vps/r3-lease-renewal.json`. Anche `C.SOURCE_MAP_V20` mantiene le
  associazioni v19. Il blob sorgente di `dns_v2.py` conserva il pin storico.
- Aggiungere `tools/semantic_provider_r3/dns_retransmit_overlay_v20.py`
  alla consegna del compositore insieme agli overlay v18 e v19. Aggiornare
  il pin di `tools/semantic_provider_r3/compose.py`, calcolare i due digest
  dai blob Git LF del commit approvato e allineare il `MANIFEST` di
  autostart alla consegna di operate v20. Il nuovo overlay è una dipendenza
  del compositore, esterna a `inputs.json["sources"]`.
- Il compositore applica l’overlay agli alias DNS prima dell’unico sigillo
  finale, che rigenera `PINS["dns"]` nel supervisore e `sourceHashes` nella
  configurazione. Il bootstrap esistente verifica i nuovi digest tramite
  la configurazione con la stessa chiusura di percorsi. Il sorgente del
  runtime mantiene i byte v19 e il suo hash resta nell’insieme già
  accettato da `installed_runtime_hashes()`.

### Upgrade ordinario v19 → v20

1. Applicare le verifiche ordinarie con entrambi i CID fermi, epoche
   terminali o assenti, eventuale cleanup preparato provato e coordinatore
   `QUIESCED` con lease e start a `false`.
2. Eseguire issue plan/apply con `--supersede`, verificando `sequence=20` e
   il digest della testa `OPERATE` v19 in `supersedes`.
3. Usare gli stessi input per [upgrade plan/apply](OUF_SEMANTIC_PROVIDER_R3_UPGRADE.md).
   Verificare `SEMANTIC_PROVIDER_R3_UPGRADED_WAITING`, wrapper e unità sotto
   `versions/20` e digest della configurazione del supervisore.
4. Usare operate start plan/apply con la consegna v20 e osservare rinnovi,
   residui nft e incidenti. Tale verifica sul VPS resta da fare dopo la
   consegna dei runbook v20.

Le prove portabili caricano i byte composti, simulano socket, clock e nft
e verificano il piano di upgrade v19 → v20. Nel caso DNS con una perdita,
il primo tentativo impiega 1 s e l’intera osservazione simulata 1,12 s. Il
supervisore pubblica `LEASE_READY` con un batch e resta `ACTIVE / RENEWED`.
I golden v1–v19 coprono la compatibilità storica. [Test v20](../tests/test_semantic_provider_r3_v20.py) · [Workflow R3](../.github/workflows/semantic-provider-r3-integration.yml)

# Inventario VPS e valutazione — 14 ottobre 2026

L'inventario riduce un'incertezza importante: il confronto completo effettuato con
`docker inspect` trova il registro semantic identico al frame storico. Non dimostra
che il percorso CSV via chatbot sia pronto, e non giustifica l'abbandono del
progetto. La contraddizione con il precedente blocco di preparazione deve essere
risolta nel canale di lettura che ha prodotto quel blocco.

## Copia archiviata e provenienza

- [Inventario restituito dal VPS](../evidence/vps-inventory-20261014.json).
- [Valutazione e aggiornamento dei blocchi della baseline](../evidence/vps-inventory-assessment-20261014.json).
- Origine: allegato dell'operatore in questa conversazione; non è telemetria VPS
  firmata o raccolta direttamente da questa sessione.
- Data di riferimento: 2026-10-14. Il rapporto non contiene l'ora esatta di raccolta.
- SHA256 dell'allegato originale:
  `d385fe29039f043bc826712fcf58241f616fa3308a119f0f94fa86d9562a8cd0`.
- Il singolo oggetto JSON è estratto e formattato senza modificarne i valori.
  Le righe del terminale esterne al JSON sono escluse. La valutazione riporta anche
  il checksum dei byte JSON archiviati.
- Revisione prima della pubblicazione: metadati, nomi di chiavi e hash; nessun
  valore grezzo di ambiente/configurazione, contenuto dei plugin APISIX, password,
  bearer o chiave privata nel JSON archiviato.
- Raccoglitore: commit
  `671cbef1f16fec195f8b0095efdf561479a117ed`, SHA256
  `7e61c2477b82411ba7cc97a4b9f5ee1556ad8453d537c51e8abb3c221fa4ec8a`.

Questa registrazione aggiunge esclusivamente evidenze e valutazione. Non modifica
sorgenti applicativi, pacchetto, preparatore, risorse VPS o autorità di esecuzione.

## Fatti acquisiti

| Osservazione | Evidenza | Conseguenza |
| --- | --- | --- |
| Registro semantic uguale al frame storico | `registryHistoricalComparison.equal=true`; nessuna differenza in tutti gli otto campi: ID, immagine, PID, avvio, Config, HostConfig, Mounts, NetworkSettings | La lettura CLI non sostiene l'ipotesi che la generazione corrente sia cambiata rispetto al frame storico. |
| Stabilità dei container selezionati | Otto container riletti; `stableAllContainers.allStable=true` | Nessuna variazione osservata tra quelle letture. Non è una prova di salute applicativa né della stabilità di tutti i 98 container. |
| runc corrispondente | ID/PID corrispondono; `running=true`; doppia lettura stabile; profilo `SYSTEM_CONTAINERD` | Il precedente problema di layout runc non ricompare in questa osservazione. |
| Input Teatri recuperabile | Asset presente, proprietario corrispondente, 13 righe, 20 colonne, profilo v1, `sourceAlreadyBound=false` | Non occorre ricreare alla cieca l'asset per iniziare la prima sorgente. Questo non equivale a una sorgente approvata o a dati già materializzati. |
| Politica attiva osservata | Versione 38, 44 capability, 87 grant; proiezione SQL | È osservabile la configurazione; non sono dimostrati tutti i permessi effettivi, le scope OAuth o il percorso HUMAN. |
| Gateway leggibile | GET APISIX completo: 64 route, hash e nomi dei plugin | È disponibile un riferimento delle route correnti; la lettura non ne dimostra il comportamento. |
| Versioni applicative correnti precedenti al candidato | Revisioni immagine dei cinque servizi nella valutazione JSON | Il nuovo insieme candidato non è quello attualmente in esecuzione. Le sue versioni restano archiviate. |

L'inventario registra 44 chiamate native, 40 aree osservate e 10 aree indisponibili
o non raccolte. Riporta zero scritture applicative, mutazioni DB/IAM/servizi e
operazioni di lifecycle dei container. Nessun reset del budget o autorità runtime.

## Perché il blocco della generazione resta da spiegare

Nel preparatore qualificato, `preflight_retained_runtime()` confronta immagine,
PID e avvio con la review. Il controllo successivo in `creation()` confronta
invece l'intero `Engine.runtime_binding()`, inclusi quattro hash. La baseline B01
resta valida: il controllo iniziale è meno completo del controllo successivo e
può richiedere due autenticazioni prima di scoprire una condizione già leggibile.

Il raccoglitore usa il comando nativo `docker inspect` con ambiente pulito; il
preparatore legge `GET /v1.44/containers/{id}/json`. Entrambi calcolano gli hash
con la stessa serializzazione JSON canonica. Non emerge una differenza
nell'algoritmo di hash; emerge una differenza nel canale di osservazione.

La [documentazione primaria Docker](https://docs.docker.com/reference/api/engine/version-history/)
documenta cambiamenti nel risultato di inspect tra versioni API. Per esempio,
API v1.52 omette `Config.OnBuild` vuoto, rimuove campi deprecati da
`NetworkSettings` e modifica la presenza di `KernelMemoryTCP`. Un hash dell'intero
oggetto dipende anche da queste differenze di rappresentazione.

**Ipotesi circoscritta, non causa VPS dimostrata:** una lettura attraverso API
1.44 può differire da quella CLI, e quindi dal frame storico, senza che il
container sia stato ricreato o riconfigurato. L'inventario non contiene la risposta
1.44 che ha fallito, né la versione API negoziata dalla CLI. Non è lecito dichiarare
il problema risolto, cambiare il frame storico o eliminare il confronto.

La prova discriminante è leggere lo stesso ID nei due canali in una finestra
stabile, confrontare entrambi col frame storico immutabile e riportare soltanto
nomi dei campi diversi e hash. Prima di un'altra consegna, il confronto completo
deve essere verificato all'inizio della preparazione e deve avere una prova
representativa della preparazione completa.

## Lacune del raccoglitore e lacune dell'ambiente

| Area | Cosa sappiamo | Classificazione |
| --- | --- | --- |
| Elenco completo container | Il limite del raccoglitore è 64; Engine dichiara 98 container, 14 in esecuzione. I container previsti sono letti separatamente. | Limite del nostro raccoglitore; non un guasto Docker. L'inventario completo promesso non è stato ottenuto. |
| Quattro storie Flyway | Il validatore accetta soltanto lettere, cifre, `_`, `.`, `-` per `script/type/version`. Respinge il marker SCHEMA con script quotato che il planner della release accetta esplicitamente. Le quattro letture restituiscono `MIGRATION_METADATA_UNSUPPORTED`. | Incompatibilità del validatore dimostrata nel codice; il campo preciso respinto sul VPS non è esposto. Non è prova di migrazioni fallite. |
| Selettore DB MCP | Un solo errore combina host, porta e presenza di qualunque query string. Il preparatore ammette parametri non identificativi limitati; il raccoglitore li respinge tutti. | Condizione esatta non identificata. Non sono dimostrati un DB guasto o un nuovo problema di ownership. |
| Catalogo IAM | `NATIVE_METADATA_READ_FAILED`, senza distinzione di causa. | Non possiamo distinguere scadenza della sessione, diniego o altro errore del comando. Non prova dei permessi effettivi. |
| Gateway control plane | Metadati non disponibili. Il codice di preparazione documenta già che le route operative del control plane sono fuori dalla selezione file. | Da riconciliare col perimetro; non dichiararlo automaticamente un blocco del CSV. |
| Ledger corrente | Non raccolto: selezione esatta necessaria. La storia conservata è soltanto storica. | Autorità, claim consumati e contabilità corrente restano aperti; nessun reset implicito. |
| Lettura MCP da questa conversazione | Non raccolta per instradamento del connettore indisponibile. | Ricerca fresca di Teatri/Cinema ancora da dimostrare. |

La qualificazione CI del raccoglitore aveva 16 test e un test Docker/PostgreSQL
reale con cinque storie sintetiche. Non copriva questi formati e questa dimensione
del VPS. Questa insufficienza di copertura appartiene allo strumento di diagnosi
che abbiamo preparato; non va trasformata in una lista di regressioni applicative.
Il precedente output DB fornito dall'operatore resta evidenza storica, senza
diventare automaticamente una verifica corrente.

## Lavoro già previsto per la consegna

La proiezione attiva osservata non include le tre nuove capability selezionate:
`ouf.managed-source.onboarding.review.prepare`,
`ouf.managed-source.onboarding.read`, `ouf.semantic.proposal.read`.
Il modulo di autorizzazione del candidato le dichiara già in `NEW`.

Nessuna delle quattro route candidate `semantic-proposal-create`,
`semantic-proposal-validate`, `semantic-proposal-review`, `semantic-proposal-read`
compare tra i 64 ID correnti. La preparazione Gateway del candidato le prevede
già. Le route correnti comprendono funzioni file, ricerca ed alcune decisioni
HUMAN precedenti; non bastano a dichiarare pubblicata la nuova funzionalità.

Queste assenze sono coerenti con una consegna non applicata. Non sono nuovi
requisiti da inventare o ragioni per riscrivere i sei microservizi. Restano da
qualificare insieme migrazioni, pubblicazione route, governance delle capability,
scope IAM, TLS e percorso browser/HUMAN effettivo. L'elenco selettivo di capability
dell'inventario non consente conclusioni su quelle non richieste dal raccoglitore.

Il source lock del candidato è conservato: semantic `eccef11a…`, onboarding
`84828f74…`, ingestion `c48ee4b1…`, UDP `b49c0d6f…`, Gateway `bf179e96…`, MCP
`f249b3dc…`. La baseline mantiene i primi cinque identici al pacchetto del mattino;
MCP conserva l'adattamento della storia delle migrazioni specifico di questo VPS.
Questa valutazione non altera nessuno di questi pin. Il lavoro composto del mattino
resta una prova utile in CI, con identità/Gateway/browser in fixture; non diventa
per questo una prova end-to-end sul VPS.

## Aggiornamento della baseline e decisione

| Blocco | Stato dopo questo inventario |
| --- | --- |
| B01 — preflight incompleto | Aperto: difetto identificato nel preparatore. |
| B02 — differenza generazione sconosciuta | Ridotto: confronto CLI interamente uguale; differenza nel canale API e causa del precedente errore ancora aperte. |
| B03 — consegna completa | Aperto: manca la prova completa in ambiente rappresentativo. |
| B04 — migrazioni e autorizzazioni reali | Aperto: nuove osservazioni di DB/IAM incomplete, percorso reale non qualificato. |
| B05 — primo Teatri via chatbot | Aperto: input presente; approvazioni, ACK durevole, commit/lineage, ricerca fresca e preservazione degli otto Cinema non dimostrati. |
| B06 — seconda sorgente e riuso | Aperto: identità canoniche riutilizzate e provenienze distinte non dimostrate sul target. |

**Decisione:** proseguire con analisi e verifica delimitate; mantenere sospesa
la consegna sul target. Questo rapporto non mostra un'impossibilità strutturale
del progetto e non giustifica raccomandarne l'abbandono. Non permette però di
affermare che la distanza dalla demo sia breve o di garantire il completamento
entro un mese. La stabilità osservata e l'input recuperato sono acquisizioni
concrete; il risultato applicativo finale manca ancora.

Il prossimo risultato deve essere la spiegazione verificata della contraddizione
CLI/API e una preparazione completa rappresentativa, prima di chiedere un'altra
esecuzione della consegna. Poi serve una prova integrata della stessa release
attraverso governance e percorso CSV, con riconciliazione di tutte le righe,
ricerca chatbot e Cinema preservati. Ogni avanzamento deve citare la prova che
chiude un blocco; ogni regressione deve confrontarsi con questi riferimenti.

Non ripetere tentativi che non aggiungano evidenze discriminanti. Se il percorso
obbligatorio non si qualifica in un ciclo di lavoro delimitato concordato con il
proprietario, rivalutare investimento e supporto operativo con i risultati in mano.
Questo documento non fissa di propria iniziativa un nuovo budget, non autorizza
rollout o decisioni HUMAN, e non equivale ad accettazione della release.

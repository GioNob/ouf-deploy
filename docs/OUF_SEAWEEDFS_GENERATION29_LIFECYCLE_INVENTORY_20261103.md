# SeaweedFS — inventario lifecycle dei 262 moduli compilati

L'inventario riguarda esclusivamente il binario generazione 29 `a0c74718…`,
prodotto dal run 41696541570 sul commit `041992ea…`. I 262 moduli del build-info
sono riconciliati con il grafo produttivo di 1.811 pacchetti, Go 1.27.3,
linux/amd64 e CGO=0. Ogni modulo ha almeno un pacchetto compilato e un percorso
di dipendenza osservato. La generazione 30 combinata non è qualificata qui.

Sono interrogati tutti i 181 repository ricavati dai module path GitHub,
risolvendo cinque spostamenti tramite uguaglianza dell'ID repository. Per i
module path non GitHub si conservano gli Origin del module cache fissato e le
associazioni dichiarate nei sorgenti primari. Metadati GitHub sono disponibili
per **250/262 moduli**. Per dieci moduli `golang.org/x`, `google.golang.org/protobuf`
e `modernc.org/b` lo stato GitHub resta UNKNOWN: gli Origin dei primi undici
puntano a Googlesource, l'ultimo non espone Origin nella versione fissata.
UNKNOWN non significa abbandonato né mantenuto.

## Dieci moduli compilati con repository archiviato verificato

| Modulo | Importatore compilato rilevante | Conseguenza tecnica da esaminare |
|---|---|---|
| `github.com/boltdb/bolt` | `hashicorp/raft-boltdb/v2` | Helper legacy inutilizzato; adapter locale in sviluppo separato |
| `github.com/envoyproxy/protoc-gen-validate` | Pacchetti xDS/Envoy | Descriptor/extension `validate` compilato attraverso dipendenze di rete |
| `github.com/facebookgo/clock` | `weed/util/httpdown` | Percorso di shutdown HTTP, non soltanto test |
| `github.com/facebookgo/stats` | `weed/util/httpdown` | Statistiche del medesimo percorso |
| `github.com/google/btree` | `weed/storage/needle_map` | Struttura dati nel core storage |
| `github.com/mitchellh/colorstring` | `schollz/progressbar/v3` | Dipendenza di output/progressi |
| `github.com/mitchellh/mapstructure` | LDAP, Vault API, parseutil | Tutti gli importatori vanno risolti, non solo quello SeaweedFS diretto |
| `github.com/rcrowley/go-metrics` | Shopify Sarama | Un passaggio a IBM Sarama da solo non dimostra la rimozione |
| `go.opencensus.io` | Pub/Sub v1 | Migrazione del client o qualificazione di un profilo che lo escluda |
| `gopkg.in/yaml.v3` | `apache/iceberg-go/config` | Vecchio parser distinto da `go.yaml.in/yaml/v3` già presente |

Gli ID verificano anche gli spostamenti a `facebookarchive/clock`,
`facebookarchive/stats` e `bufbuild/protoc-gen-validate`.

Per PGV la pagina primaria GitHub riporta archiviazione **27 maggio 2026**.
Il grafo prova la presenza del package di descriptor/extension
`github.com/envoyproxy/protoc-gen-validate/validate`, non l'esecuzione del
generatore o di specifiche chiamate Validate. Questo audit non attribuisce
CVE, vulnerabilità sfruttabile o validazione runtime attiva a quella presenza.

## Versioni deprecate e casi distinti

- MongoDB driver **v1.17.9** è deprecato nel go.mod. Il README della versione
  fissa limita gli aggiornamenti critici all'inizio del 2026; al 3 novembre
  2026 tale finestra annunciata è trascorsa. Il repository attivo per v2 non
  rende automaticamente supportato v1. Importatore: `weed/filer/mongodb`.
- Il detector GCP `opentelemetry-operations-go/detectors/gcp` **v1.38.0** dichiara
  esplicitamente fine della manutenzione; l'alternativa upstream è già
  distinta nel grafo. Va controllato l'importatore effettivo.
- L'exporter metriche dello stesso progetto è deprecato, ma l'archiviazione
  annunciata dopo **1 gennaio 2027** è futura: non viene etichettato EOL oggi.
- Pub/Sub v1 e `github.com/golang/protobuf` hanno deprecazione esplicita nel
  go.mod. Questo dato rimane separato da `archived` e da una data EOL.
- Shopify Sarama e armon/go-metrics hanno repository trasferiti a IBM e
  HashiCorp. Il repository canonico non archiviato non certifica il vecchio
  module path/versione; restano i rilievi dei rispettivi importatori.
- `syndtr/goleveldb` risulta **non archiviato**. L'ultimo push del 2024 è un
  indizio temporale, insufficiente a provare abbandono o supporto corrente.
- `google/wire` è archiviato, ma è **assente** sia dai 262 moduli del binario
  sia dai 1.811 pacchetti del grafo: non si presenta come dipendenza compilata.
- Maintenance mode con correzioni critiche/security dichiarate, come nel
  client Google API, non equivale a nessuna manutenzione. Le semplici occorrenze
  lessicali di “deprecated” nei README sono conservate come indizi grezzi e non
  promosse automaticamente a conclusioni sul modulo.

## Copertura, prove e limiti

`evidence/lifecycle262/compiled-module-inventory.json` contiene tutte le righe,
versioni, h1, campi archived/disabled, branch, pushed_at, importatori e un percorso
dal programma. Gli oggetti JSON pubblici delle API sono conservati nei cinque
batch e nei readback dei redirect; le risposte di redirect non sono trattate
come repository verificati. Nessuno dei moduli osservati ha `disabled=true`.
Non si verifica una firma crittografica di queste risposte HTTP.

Le policy primarie conservano URL, digest/dimensione del documento letto e un
estratto limitato. I marker nel module cache sono legati alla versione del
build-info; una frase riferita a una singola funzione non basta a dichiarare
deprecato l'intero modulo. `pushed_at` e branch sono soltanto metadati, non SLA.

Le correzioni locali dei primi fronti non chiudono questo inventario né G1.
Serve rivalutare il grafo e il binario risultanti, decidere i profili ammessi
in base ai binding reali e qualificare l'eventuale nuova immagine. Nessun tag
opzionale viene escluso in questo audit, nessuna API o componente viene rimossa.
Il candidato resta non ammesso per il target; non viene dichiarato “tutto
mantenuto” perché la scansione vulnerabilità è verde.

Fonti primarie: API GitHub indicate nelle singole righe;
[PGV](https://github.com/bufbuild/protoc-gen-validate),
[MongoDB v1.17.9](https://github.com/mongodb/mongo-go-driver/blob/v1.17.9/README.md),
[detector GCP](https://github.com/GoogleCloudPlatform/opentelemetry-operations-go/blob/detectors/gcp/v1.38.0/detectors/gcp/README.md),
[YAML storico](https://github.com/go-yaml/yaml/tree/v3).

Zero modifiche GitHub o operazioni target in questo lotto. MinIO resta attivo;
scope17/52, Teatri/M1 e Farmacie rimangono invariati.

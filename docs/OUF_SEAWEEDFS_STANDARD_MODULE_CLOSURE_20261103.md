# SeaweedFS 4.52 — chiusura modulo del profilo standard OUF

Stato: **qualifica locale PASS, hosted PENDING**. La patch 28 seleziona esplicitamente il profilo standard OUF senza integrazioni opzionali `elastic` e `rclone`. Il binario standard rimane identico alla coorte qualificata a 15 patch. Questo documento non dichiara la bonifica dell'intera distribuzione upstream o di tutti i suoi moduli indipendenti.

La [patch](../patches/seaweedfs/4.52-ouf-standard-optional-closure.patch), SHA256 `b8387b32bfcb1f8bb7f4cb30d781c5035a6a46b1a82c6a655e318cf794f2bf79`, si applica dopo le 27 patch esistenti, a partire dal commit upstream `984eac6a790be89e2a11de175a7413e1e3e32dd3`. La [ricevuta locale](../evidence/seaweedfs-ouf-standard-module-closure-local-20261103.json) conserva risultati e hash delle prove. Il [workflow dedicato](../.github/workflows/storage-ouf-standard-module-closure.yml) ricostruisce la sequenza esatta; i sei workflow SDK a 27 patch mantengono il loro significato storico.

## Perché è un profilo esplicito

Il MiniPET §3 propone un filer locale persistente, candidato `leveldb2`, e il contratto S3 usato da OUF. Non richiede un filer Elasticsearch né il remote tier rclone. Il §3 vieta di eliminare una funzione necessaria per ottenere la migrazione: questa selezione riguarda soltanto la generazione candidata standard già qualificata senza quei tag. Un binding effettivo che richiedesse tali integrazioni bloccherebbe l'ammissione di questo profilo e richiederebbe una generazione diversa. Nessuna osservazione target è dedotta dal prototipo.

Matrix 1.7 §1/4/5 mantiene ownership, confini HUMAN/THS e distinzione tra prove di integrazione e binding reali. La policy di resilienza v3 impone un diniego esplicito quando configurazione o integrità non sono verificabili e vieta successi fittizi. La patch non modifica retry, budget, credenziali, runtime OUF o autorità operative.

## Integrazioni escluse e comportamento

| Tag | File eliminati | Funzioni escluse |
|---|---|---|
| `elastic` | `weed/filer/elastic/v7/elastic_store.go`, `elastic_store_kv.go`; `weed/command/filer_meta_tail_elastic.go` | Registrazione filer `elastic7`/`elastic8`; destinazione Elasticsearch di `filer.meta.tail -es` |
| `rclone` | `weed/storage/backend/rclone_backend/rclone_backend.go`, `rclone_progress.go`, `rclone_backend_test.go` | Backend remote tier `rclone`, inclusi provider importati da `backend/all` |

Il nuovo file `weed/command/ouf_unsupported_optional_tags.go`, attivo con `elastic || rclone`, impedisce la compilazione con l'identificatore diagnostico `OUF_STANDARD_PROFILE_DOES_NOT_SUPPORT_ELASTIC_OR_RCLONE`. Tutte e tre le combinazioni `elastic`, `rclone`, `elastic,rclone` falliscono esplicitamente. Non sono aggiunti stub runtime o risultati no-op. I file default preesistenti `doc.go`, `dummy.go` e `filer_meta_tail_non_elastic.go` restano intatti.

I target upstream `make full_install` e le build/test con l'insieme completo di tag non sono supportati da questa generazione. L'opzione Docker `TAGS` non aggira il diniego. Il messaggio runtime ereditato per `filer.meta.tail -es` suggerisce storicamente una ricompilazione con `-tags elastic`: **quel suggerimento non si applica al profilo OUF standard**. La stringa è conservata per mantenere l'identità esatta del binario; questo profilo nega quella ricompilazione. Non si deve configurare un filer elastic o un remote tier rclone per questa candidata.

## Chiusura dipendenze e prove locali

Prima della patch, `olivere/elastic/v7@v7.0.32` introduceva SDK v1.43.21; `rclone@v1.75.1` introduceva `feature/s3/manager@v1.22.34`. Il modulo root richiedeva inoltre SDK v1.55.8 e manager1.22.34. Questi archi non entravano nel server standard, ma rimanevano nel modulo root.

| Misura | Prima (27 patch) | Dopo (28 patch) |
|---|---:|---:|
| Requisiti nel `go.mod` root | 497 | 386 |
| Archi del grafo modulo root | 5.902 | 4.624 |
| Moduli SDK v1 / manager nel grafo root | presenti | 0 / 0 |
| Moduli elastic / rclone nel grafo root | presenti | 0 / 0 |
| Versioni cambiate tra moduli mantenuti | — | 0 |
| Pacchetti del server standard | 1.811 | 1.811, identici |

`go mod tidy` rimuove 113 requisiti e rende espliciti due helper già transitivi di test: `github.com/onsi/gomega v1.37.0` e `github.com/zeebo/assert v1.3.1`. Nessun pin mantenuto cambia. Un secondo `go mod tidy -diff` restituisce exit 0 e diff vuoto. La patch completa si riapplica su una copia fresca della baseline 27: l’inventario completo di 4.533 file, escluso soltanto `.git`, coincide byte per byte con il prototipo testato, senza file aggiunti inattesi. La review ha corretto i metadati Git di cancellazione/creazione mancanti nel primo confezionamento, che produceva un file spurio `dev/null` nel solo replay. Il prototipo su cui sono stati eseguiti i test non era interessato; il confronto dei soli percorsi modificati è stato sostituito dal confronto dell’intero albero.

Il requisito root esplicito `gomega` rende ridondante la stessa riga indirect nel modulo Kafka, che usa `replace` verso root: la patch 28 elimina quella sola riga, senza cambiare versioni o `go.sum` Kafka. I due lockfile IAM restano identici. Il rientro root policy/normal/IAM supera 16 test principali + 8 sottocasi; il modulo IAM separato supera 14 principali + 4 sottocasi. Il modulo Kafka torna a `tidy -diff` vuoto e tutti i suoi sei package compilano con `-mod=readonly -run ^$` (quattro PASS, due senza test).

La suite qualificata standard completa supera **5.591 eventi test PASS, 5 test skip, 20 package PASS**; sei ulteriori package sono senza test. I conteggi includono sottotest e non rappresentano altrettanti criteri di accettazione MiniPET. Il grafo ordinato ha SHA256 `cb2536b10d73bc04e587c257a75a622c6b3cf855f1d232f26dba246b43b03f4a`.

La build Go 1.27.3, linux/amd64, CGO disabilitato, `-mod=readonly -trimpath`, con VCS upstream esatto e `vcs.modified=true`, produce ancora SHA256 `85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033`. Non si sostituisce l'immagine OCI né il candidate lock. Il pruning del modulo non altera il comportamento del server standard né estende la qualifica agli altri tag opzionali.

## Alternative e limiti

Un modulo nested per ciascuna integrazione, ancora importato da file con build tag del modulo root, non elimina le dipendenze dal grafo root: `go mod tidy` considera i tag. Il semplice aggiornamento delle versioni non costituisce una migrazione provata: il modulo rclone esaminato mantiene manager; la sostituzione di olivere con il client ufficiale Elasticsearch richiede una riscrittura delle API e nuove prove dei contratti. Conservare tutte le integrazioni avrebbe quindi costo e rischi maggiori della selezione del profilo esatto già compilato. Le funzionalità upstream rimangono disponibili attraverso il sorgente upstream, ma richiedono una diversa generazione e qualifica prima di qualsiasi impiego OUF.

Questa prova riguarda il modulo root e il binario standard. I moduli test IAM/Kafka qualificati hanno una propria chiusura; i moduli Kafka ulteriormente annidati non sono dichiarati bonificati da questa patch. Non è una scansione universale di ogni dipendenza non mantenuta, una certificazione licenze o un'ammissione a produzione.

Restano **circa 35% ±10**, **0/8 gate**, **0/21 AT**, **0/120 oggetti reali**: l'identità binaria e la chiusura del modulo eliminano un residuo tecnico, ma non provano binding, migrazione, recovery e accettazione target. MinIO resta attivo; licenze/redistribuzione e custodia durevole restano OPEN. Scope17/52 Engine GET, Teatri/M1 8/8 tecniche e 6/6 funzionali, Farmacie61/10OPEN/STRING restano invariati. Nessuna operazione target, reset/replay/grant o nuova autorità HUMAN/THS.

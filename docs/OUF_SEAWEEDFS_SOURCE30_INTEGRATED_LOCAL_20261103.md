# Generazione 30: integrazione sorgente locale, qualifica corrente ancora 29

La patch integrata `4.52-maintained-dependency-closure.patch` applica sette fronti alla sequenza esatta delle 29 patch precedenti: metriche Raft, LDAP/mapstructure, adattatore Raft bbolt locale, esclusione esplicita Kafka, esclusione OpenBao/Vault, rimozione dell'adattatore B-tree inutilizzato e semplificazione HTTP shutdown con la libreria standard. Il replay con indice Git produce l'albero `13b3de2f130667ed060e94291fcf64b37b7f037a`; patch SHA256 `78b2f5462c2d283b0a0d6d79dc5d620bfe9e3ca6dabac559faa55830aa1fb422`.

Il nuovo binario Linux amd64 CGO=0, Go 1.27.3, ha SHA256 `5b7e3dcf61d6b3b7b2b44135dd0db980e43e3d96e5e7e87210c543f790448b02`. Non è il binario della generazione 29. Questa ricevuta prova sorgente, compilazione e test locali: non qualifica una nuova immagine, scansione CVE, SBOM, provenienza publisher o runtime distribuito. La vista tecnica corrente rimane la generazione 29; non si trasferiscono le sue prove al nuovo binario.

Il binario ricompilato dal replay indicizzato ha lo stesso SHA256 e la stessa dimensione di **219.516.458 byte**. Il confronto `sha256sum` è stato eseguito direttamente su entrambi i file; stdout/stderr della build replay sono conservati. Non è disponibile la trascrizione esatta del comando di quella build: non viene ricostruita come fatto osservato e il registro originale degli 11 comandi resta invariato.

## Verifica dell'integrazione

| Esecuzione effettiva | Risultato | Limite |
|---|---|---|
| Regressioni del profilo, CGO=0 | 6.371 eventi PASS, 5 test skip; 30 pacchetti con test, 4 senza test | I cinque skip di integrazione già dichiarati restano tali |
| Preflight server e metriche reali | 7 eventi PASS | Test selezionati, non intera suite server |
| Storage/compaction/indice | 54 eventi PASS, 2 skip ambientali | `/proc` non disponibile e permessi ignorati come root |
| Race detector, CGO=1 | 25 eventi PASS, HTTP shutdown e raftstore | Verifica separata, non prova di assenza universale di race |
| Database vecchio adattatore v2 ↔ locale | 3 PASS | Formato file e interoperabilità locale, non crash/recovery target |
| Compilazione dei sei profili negati | 6 rifiuti previsti, nessun binario prodotto | elastic, rclone, kafka, openbao, vault e combinazione Kafka/OpenBao/Vault |

Le prime tre esecuzioni sommano **6.432 eventi PASS**. I 25 eventi race e i tre casi database sono indicati separatamente; non costituiscono un conteggio di test unici. I log originali restano integri: quello principale, 8.142.593 byte, è conservato con gzip deterministico e doppio hash del contenuto originale e dell'archivio. La lettura per righe fisiche verifica tutti i record JSON, inclusi gli output contenenti separatori Unicode.

Il registro `execution-record.json` conserva gli 11 comandi effettivi riportati dall'esecuzione principale, directory, soli override ambiente controllati, percorsi degli output e codici di uscita. Non pretende di catturare tutto l'ambiente ereditato o un transcript di shell. Il confronto moduli verifica nessun cambio dei pin mantenuti e degli hash h1 condivisi. `go mod tidy -diff` è vuoto; `go mod graph` termina con 4.448 archi e l'elenco root comprende 789 moduli. La presenza nel grafo root non equivale a compilazione nel binario.

## Riduzione verificata e residui

Il binario passa da **262 a 234 moduli**, senza moduli aggiunti o versioni cambiate; il grafo produttivo passa da **1.811 a 1.740 pacchetti**. Dei dieci moduli compilati il cui repository risultava archiviato nell'audit 29, sei non sono più compilati: boltdb/bolt, mitchellh/mapstructure, rcrowley/go-metrics, google/btree, facebookgo/clock e facebookgo/stats. Sono rimossi anche i vecchi percorsi Armon e Shopify.

Restano compilati i quattro moduli archiviati mitchellh/colorstring, go.opencensus.io, gopkg.in/yaml.v3 ed envoyproxy/protoc-gen-validate. Restano anche MongoDB v1 con finestra annunciata di fix/aggiornamenti critici trascorsa e il detector GCP dichiarato non più mantenuto. Le dodici origini non risolte dall'audit metadata 29 rimangono UNKNOWN finché non vengono qualificate; nessuna inferenza di mantenimento deriva da un repository non archiviato. Il controllo complessivo del lifecycle e G1 rimangono OPEN.

Kafka e OpenBao/Vault sono esclusi dal profilo candidato con rifiuti espliciti prima degli effetti; non si afferma compatibilità funzionale con target che li richiedano. Il binding dei requisiti effettivi dei target è OPEN.

## Sorgente locale MPL e nuova coorte

`weed/util/raftstore` deriva da `github.com/hashicorp/raft-boltdb/v2@v2.4.2`. I sei file, compresi LICENSE MPL-2.0, UPSTREAM.md, implementazione e test, sono conservati in un archivio sorgente deterministico con manifest e hash per file. L'adattamento omette l'helper inutilizzato di migrazione da Bolt e il relativo test; non converte il formato database. Il test di interoperabilità usa il vecchio adattatore soltanto come oracolo esterno al modulo candidato.

La conservazione del sorgente modificato e delle notice non sostituisce review legale, obblighi di redistribuzione o custodia durevole. Il dossier e il binding MPL della nuova coorte 30 sono **PENDING**; le decisioni della coorte 29 non vengono riutilizzate automaticamente.

## Stato del miniPET

Avanzamento invariato: **circa 38% ±10**, stessi **17,5/46** crediti, nessun credito aggiunto per il prototipo. Rimangono 0/8 gate, 0/21 AT e 0/120 oggetti reali. MinIO resta attivo. Scope consumati 17, Engine GET cumulativi 52, Teatri/M1 8/8 tecniche + 6/6 funzionali e Farmacie 61 righe / 10 OPEN / STRING preservati. Nessuna operazione target, ammissione, merge, deploy o nuova autorità HUMAN/THS.

Prova integrata: [ricevuta locale](../evidence/seaweedfs-source30-integrated-local-20261103.json). Occorre completare nuova qualifica immagine/coorte e relativo binding prima di modificare la vista tecnica corrente.

# Metriche Raft: provider Hashicorp condiviso

La patch sorgente proposta dopo la generazione29 sostituisce i due import di `github.com/armon/go-metrics` con `github.com/hashicorp/go-metrics v0.7.0`, già presente. Raft1.8.0 e raft-boltdb/v2 2.4.2 usano questo secondo provider: configurare il globale Armon lasciava disconnesse le loro emissioni dal sink Prometheus SeaweedFS.

Il blocco di inizializzazione del sink è estratto in un helper privato chiamato nello stesso punto del costruttore. Registry `stats.Gather`, namespace `SeaweedFS`, runtime metrics disabilitate e testi degli errori rimangono identici. Il test usa esattamente questo helper e il vero BoltStore: persiste e rilegge un log, quindi verifica nel registry tre famiglie con un campione ciascuna, incluso `logsPerBatch=1`. Il subprocess dedicato ha budget15secondi; non avvia un server Raft e non contamina globali di altri test.

## Prove

- RED con i due vecchi import: le tre famiglie non raggiungono il sink; roundtrip dati riuscito.
- GREEN con Hashicorp: prova reale PASS con CGO0 e CGO1; PASS anche applicando la pulizia moduli separata.
- Profilo standard CGO0 Go1.27.3: **6.156 PASS,5skip,21pacchetti PASS**, più il nuovo test metriche separato PASS.
- Esplorazione estesa CGO1 con tutti i test server: **7.126 PASS,7skip,1FAIL**. L'unico errore è il DNS pubblico di `TestBuildGuardedRemoteStorageClient`; riprodotto identico sulla generazione29 immutata. Questa esecuzione resta FALLITA e non è presentata come qualifica positiva.
- Grafo produzione CGO0: **1.811→1.810 pacchetti**, rimossi entrambi i pacchetti Armon, aggiunto Hashicorp Prometheus; zero AWS SDKv1 e manager S3 deprecato.
- Riapplicazione indipendente delle due patch e confronto byte per byte PASS. Nessun file della generazione29 modificato.

## Pulizia moduli separata e residuo

La seconda proposta rimuove il requisito diretto Armon, promuove il pin Hashicorp esistente senza cambiarne versione e applica il risultato di `go mod tidy`. Il fixed point è vuoto. I due checksum Armon rimangono necessari per i test transitivi upstream: `raft-boltdb/v2.test → raft-boltdb → armon/go-metrics`. Esiste inoltre un arco storico del grafo moduli da raft1.7.0, distinto dalla versione1.8.0 selezionata. Non si dichiara l'intero grafo moduli privo di Armon.

La futura integrazione dell'adapter Bolt locale deve aggiornare anche l'import del test metriche e ripetere il vero StoreLog/GetLog sul nuovo adapter; la prova RED/GREEN upstream resta storica. La pulizia combinata dei moduli viene ricalcolata dopo l'integrazione, senza eliminare checksum a mano per forzare un risultato.

## Limiti

Non sono stati costruiti o qualificati un nuovo binario e una nuova immagine. La coorte29, il suo lock e le sue prove restano invariati. Sono ancora necessari integrazione, regressioni del profilo combinato e nuova qualifica immagine/SBOM/scansione/licenze/provenienza. Nessun gate/AT chiuso, target operation, merge, deploy o autorità runtime. Scope17/52GET, Teatri/M1 e Farmacie preservati; MinIO rimane attivo.

La [ricevuta](../evidence/seaweedfs-raft-metrics-local-20261103.json) conserva hash delle patch, prove selezionate, tutti gli eventi terminali della suite CGO0 e hash/dimensioni dei log completi trattenuti nel workspace.

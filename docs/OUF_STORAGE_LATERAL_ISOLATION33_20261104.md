# Isolamento laterale SeaweedFS — laboratorio33, 2026-11-04

## Confine della prova

Quattro servizi e un client in cinque namespace di rete distinti, su un bridge Docker interno con indirizzi IPv4 statici e nessuna porta pubblicata. Un piccolo launcher statico montato read-only attende un marker esatto prima di exec del binario weed fissato; il controller installa nftables in tutti i namespace prima di aprire i marker. I servizi non hanno capability e non possono modificare le regole. L'immagine OCI33 resta invariata; il launcher è un ausilio del laboratorio, non una nuova immagine qualificata.

Policy INPUT/OUTPUT/FORWARD default deny, risposte established/related e loopback locale consentite. DNS TCP/UDP53 bloccato in OUTPUT prima del DNAT Docker, inclusa la risoluzione embedded127.0.0.11. Il traffico avviato verso il gateway della rete su443 è negato. Le prove si svolgono solo nei namespace del laboratorio; nessuna modifica al firewall host o VPS.

| Origine | Destinazione | TCP consentiti |
|---|---|---|
| Client | S3 | 18333, TLS |
| S3 | Filer | 18888, 28888 |
| S3 | Master | 29333 |
| S3 | Volume | 18080 |
| Filer | Master | 29333 |
| Filer | Volume | 18080, 28080 |
| Volume | Master | 29333 |
| Master | Volume | 28080 |

La matrice copre i 32 collegamenti tra namespace diversi verso otto listener effettivi: 10 consentiti e22 negati. Ogni diniego richiede errore di socket e incremento del contatore nft dedicato, dopo aver provato che il listener di destinazione è attivo. Sono aggiunti15 dinieghi DNS/host gateway. Una porta chiusa o un timeout da soli non sono PASS.

## Coerenza e sorgenti

Un seed S3 firmato su TLS crea bucket e oggetto binario; GET/HEAD/LIST completo, hash e MIME devono coincidere prima/dopo tutti i probe. Nessun retry mutativo o traffico di test verso Internet. I ruoli interni usano i protocolli della fixture esistente. La topologia deriva dal sorgente upstream esatto `984eac6a790be89e2a11de175a7413e1e3e32dd3`, in particolare [S3 startup](https://github.com/seaweedfs/seaweedfs/blob/984eac6a790be89e2a11de175a7413e1e3e32dd3/weed/command/s3.go), [S3 server](https://github.com/seaweedfs/seaweedfs/blob/984eac6a790be89e2a11de175a7413e1e3e32dd3/weed/s3api/s3api_server.go) e [Filer](https://github.com/seaweedfs/seaweedfs/blob/984eac6a790be89e2a11de175a7413e1e3e32dd3/weed/filer/filer.go), applicata alla coorte33 già fissata. La qualifica nativa decide se la matrice è sufficiente per questo percorso sintetico.

## Stato

32 test locali PASS: 10 nuovi, inclusi compilazione statica e barriera reale di processo, e22 regressioni credential/TLS. CI nativa PASS; archivio originale verificato. Il workflow conserva configurazioni nft, contatori, identità namespace/container, probe, versioni del toolchain, fonti e report S3, anche in caso di errore.

## Esito nativo e rilettura

- Producer `57c9959eda87542c8ac327467e0c30c74718c4ee`; [run 41812944892](https://github.com/GioNob/ouf-deploy/actions/runs/41812944892), job `126516457297` SUCCESS, artifact `13312992543`. Tutti i 32 test hosted PASS.
- Cinque namespace distinti e non host, con cinque container non privilegiati e avvio gated. Regole registrate prima dell'apertura delle barriere, contatori iniziali a zero e struttura delle regole invariata a fine prova. Il launcher statico del laboratorio e la sua versione di compilatore sono legati tramite digest/evidenze; non si tratta di una nuova immagine OCI qualificata.
- Otto listener reali raggiungibili localmente; 10 collegamenti tra ruoli consentiti e22 negati. Altri15 dinieghi: DNS TCP/UDP sul resolver Docker e accesso TCP443 al gateway del bridge, da ciascun ruolo. Tutti i37 dinieghi hanno contatori dedicati in aumento e errore di socket (errno1 o113); nessun timeout conteggiato come successo. Contatore other_denied a zero in tutti i ruoli nel periodo osservato.
- Un bucket e un oggetto sintetico da50 byte creati con firma S3 e TLS verificato. GET/HEAD/LIST, hash, MIME e fingerprint TLS identici prima/dopo i probe; nessun retry mutativo. Cinque arresti puliti e bridge rimosso.
- ZIP originale [storage-lateral33-41812944892.zip](../evidence/artifacts/storage-lateral33-41812944892.zip), 49933 byte, SHA256 `8fd5ba9e63be4564e3375f2f7f32110bce6471172efdcdff7acea2ca4f29843d`; verificati49 membri,48 checksum e18 sorgenti esatte. [Receipt di rilettura](../evidence/storage-lateral33-readback-20261104.json).
- Rilettura locale di originali, source hash, namespace/container, policy nft e contatori, listener/probe e report S3 hosted. Nessuna seconda esecuzione nativa locale o verifica crittografica locale della firma publisher dichiarata; publisher della coorte verificato hosted con source commit esatto. Nessuna chiave privata TLS nell'archivio.

## Prossimo singolo passo

Arresto forzato del ruolo volume nel laboratorio isolato e ripresa, verificando l'oggetto già confermato e il ripristino delle regole di rete prima del servizio. Il test deve conservare evidenze del guasto senza trasformare una semplice ripartenza in una garanzia RPO/RTO o power-loss produttiva. Non eseguito in questo checkpoint.

## Limiti

Isolamento di connessioni IPv4 in una topologia singolo master/volume/filer/gateway; non autorizzazione dei metodi nelle porte ammesse, mTLS interno, isolamento da host compromesso, IPv6, replica multi-nodo o profilo produttivo. Le connessioni interne ammesse restano fidate: non si dichiara che un ruolo compromesso non possa usare metodi amministrativi sulla stessa porta. MiniPET invariato18,3/46, circa40% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali. Nessuna operazione VPS, migrazione, merge/deploy, grant o replay.

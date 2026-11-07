# Passaggio UDP corrente a SeaweedFS

**ESEGUITO CON SUCCESSO** il 7 novembre 2026 alle 17:59:28 UTC / 18:59:28 CET. [Ricevuta](../evidence/udp-seaweedfs-ready-operator-20261107.json): 110 oggetti/181.364 byte coincidenti, stessa immagine, readiness e TLS verificati, vecchio container spento, proprio diagnostico rimosso, zero extra target. Non rilanciare il cambio. Onboarding resta su SeaweedFS. La procedura sotto è conservata come storia dell'esecuzione; lo stato corrente è in [STATE](STATE.md).

## Evidenza acquisita

La [ricevuta operatore](../evidence/udp-seaweedfs-client-success-operator-20261107.json) del **7 novembre 2026, 17:39:37 UTC / 18:39:37 CET** riporta `UDP_INSTALLED_CLIENT_PUT_HEAD_GET_MATCH`: factory e adapter originali nell'immagine `ae78f604…`, Java 21.0.12.1 e AWS SDK 2.54.17 hanno eseguito PUT, HEAD e GET verso SeaweedFS HTTPS. Corpo di 33 byte, SHA-256 e metadati coincidono. Spring non è stato avviato; il servizio UDP originale è rimasto invariato. Nel JSON dichiarato non risultano proprietà storage selezionate. Questo non è un dump della configurazione effettiva di Spring.

## Effetti del comando

1. Controlla immagini, classi installate, binding sorgente, prova precedente, readiness originale, rete privata e CA. Prepara il truststore unendo i certificati del JDK corrente con la CA privata e il profilo credenziali target.
2. Ferma soltanto UDP e disabilita il riavvio automatico del vecchio container. Legge il bucket corrente `ouf-udp` da MinIO con l'identità di manutenzione esistente; nessuna modifica a permessi o oggetti sorgenti.
3. Confronta corpo completo e metadati degli oggetti già presenti, copia solo quelli mancanti con condizione di assenza e verifica il risultato. Differenze su chiavi esistenti fermano il passaggio, senza sovrascrittura. Ricontrolla che la sorgente non sia cambiata mentre UDP è fermo.
4. Rimuove solo l'oggetto diagnostico di questa prova, chiave `diagnostics/seaweedfs-client/3d9691ec-db79-4567-8c25-ed1695dea208`, dopo verifica di dimensione e hash; un'assenza già verificata è accettata. Altri oggetti presenti soltanto a destinazione sono conservati e contati.
5. Conserva il container originale spento; crea il sostituto con **la stessa immagine**, configurazione non storage, mount, indirizzo backend e alias conservati. Aggiunge la rete SeaweedFS, endpoint HTTPS e truststore; sostituisce le vecchie credenziali AWS statiche con il file del profilo target. Le quattro proprietà storage sono fissate anche negli argomenti di avvio.
6. Avvia UDP, verifica readiness e TLS dalla sua rete, salva il marker `udp-seaweedfs-current.json` e il risultato. Il riavvio dell'applicazione può accedere al DB: lo script non esegue query dirette.

La fermata dura fino al completamento della copia e della ripartenza. Il budget interno è 600 secondi, con 90 secondi riservati al tentativo di ripristino precedente al primo avvio del sostituto. Non è una previsione della durata.

Limiti intenzionali per questa installazione: massimo 512 oggetti, 64 MiB per oggetto, 256 MiB totali, listing non troncato e sorgente non vuota. I tag di oggetti già presenti non sono confrontati nuovamente; un oggetto mancante con tag ferma la copia. [Preparazione e prove locali](../evidence/udp-seaweedfs-switch-preparation-20261107.json).

## Comando unico sul VPS

Sorgente fissato al commit `c5957208114803ade86630d0a8ff1d653c77b117`, 47606 byte, SHA-256 `e9f7235e4f46bfb0e0d9bf789120bff0f8363951c745c396f0460d7c860363a3`. Nessun aggiornamento immagine o build necessario.

```bash
sudo /usr/bin/timeout 800 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib
import urllib.request

url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/c5957208114803ade86630d0a8ff1d653c77b117/scripts/switch-udp-to-seaweedfs-20261107.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(47607)
if len(raw) != 47606 or hashlib.sha256(raw).hexdigest() != 'e9f7235e4f46bfb0e0d9bf789120bff0f8363951c745c396f0460d7c860363a3':
    raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
exec(compile(raw, 'switch-udp-to-seaweedfs-20261107.py', 'exec'), {'__name__': '__main__'})
PY
```

Incollare il JSON finale. Risultato atteso: **`UDP_SEAWEEDFS_READY`**, con `readinessUp`, `containerNetworkTlsVerified`, `sameApplicationImage` e `originalRetainedStopped` veri. Controllare anche conteggi, manifest e `additionalTargetObjectsRetained`.

## Se l'esecuzione si ferma

Prima dell'invio del primo avvio del sostituto, lo script tenta di ripristinare il vecchio UDP; il JSON indica se il tentativo è riuscito. Dopo l'invio dell'avvio, **non torna automaticamente al writer MinIO**: potrebbero già esistere nuove scritture su SeaweedFS. Un esito incompleto va letto e risolto a partire dal JSON e dalle evidenze private, senza riavviare il vecchio container o rilanciare alla cieca il cambio. Un marker esistente blocca una nuova esecuzione.

Per le ripartenze successive usare l'[avviatore aggiornato a questo commit](https://github.com/GioNob/ouf-deploy/blob/c5957208114803ade86630d0a8ff1d653c77b117/scripts/ouf-runtime-20261107.py), che risolve separatamente i marker Onboarding e UDP. Le vecchie copie contengono l'ID UDP precedente. [Istruzioni di ripartenza](OUF_RUNTIME_RESTART_20261107.md).

## Criterio successivo

Readiness e TLS non completano F2 né l'E2E. Dopo il cambio verificare una normale operazione applicativa lake e proseguire da asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94` e profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`: semantica locale, eventuale OntoPiA governata, Ingestion, riconciliazione e lettura del grafo. Non ricaricare il CSV per ricominciare. F1 resta PASS, F2–F6 aperti.

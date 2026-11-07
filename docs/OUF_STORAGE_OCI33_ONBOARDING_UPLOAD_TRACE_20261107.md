# Upload isolato con Flight Recorder dopo HTTP 502

Il VPS ha confermato che il primo output ha raggiunto il limite di 96 MiB e che il JSON inline misura 1.780.674.822 byte. Il wrapper ha terminato il decoder in streaming al proprio limite. La registrazione da 4.415.319 byte ha conservato lo stesso digest. I contatori delle eccezioni nella ricevuta sono valori iniziali, perché nessuna lettura è stata completata. [Ricevuta VPS](../evidence/storage-oci33-onboarding-jfr-stream-limit-operator-20261107.json).

Il decoder ha restituito `DOCKER_START_FAILED` ed è stato rimosso. La registrazione rilevata prima dell'avvio misura 4.415.319 byte, SHA-256 `d01733a50c074e82e614c4124f37d1e987fe7d0087a65ecbfeebaae76fe389dd`. La decodifica e il controllo finale del file sono pendenti. Il codice di errore del wrapper copre anche un'uscita anomala dell'utility dopo l'avvio. [Ricevuta VPS](../evidence/storage-oci33-onboarding-upload-jfr-decoder-held-operator-20261107.json).

Il VPS ha confermato `ONB_STAGING_WRITE_FAILED` con HTTP 502 dopo un solo POST del nuovo intento. La lettura S3 pre-upload è riuscita. Flight Recorder ha conservato il file, mentre il riepilogo incorporato non l'ha decodificato. I contatori di eccezioni e handshake pari a zero in quella ricevuta sono valori iniziali del riepilogo. Tutti e tre i container sono stati rimossi. [Ricevuta VPS](../evidence/storage-oci33-onboarding-upload-trace-held-operator-20261107.json).

La [lettura del tentativo precedente](../evidence/storage-oci33-onboarding-upload-readback-operator-20261107.json) ha trovato un intento `DISPATCHED` senza ACK, asset o oggetto riservato. I log conservati non spiegano il 502.

1. Clonare le copie PostgreSQL V41 e SeaweedFS del primo avvio riuscito in `upload-proof-v1/instrumented-upload-v1`. Avviare i tre container in isolamento e inviare un solo POST Teatri tramite l'immagine esatta di Onboarding, con un intento e una firma locali nuovi. Flight Recorder osserva eccezioni e handshake TLS del JRE.
2. Su HTTP 201 verificare ACK PostgreSQL e SHA-256 dell'oggetto SeaweedFS. Su errore conservare risposta, registrazione JFR e log privati. Il JSON riporta solo codice applicativo, categorie di eccezioni, indizi di trasporto e conteggi nel periodo del POST. Rimuovere i container temporanei.

Il tentativo precedente rimane conservato. La nuova operazione riguarda esclusivamente le copie. Durata massima 12 minuti. La scrittura e decodifica del file JFR sono state verificate localmente con il JRE dell'immagine esatta. Il tentativo VPS si è fermato sul 502.

## Blocco streaming eseguito

1. Verificare lo SHA-256 della registrazione e leggere le dimensioni e gli indizi del primo decoder. Provare a riusare gli eventi già conservati, anche se il file supera il limite del primo riepilogo.
2. Se il JSON conservato è incompleto o assente, avviare solo il decoder dell'immagine esatta con rete isolata e input in sola lettura. Leggere gli eventi in streaming, senza creare un nuovo file JSON espanso. Conservare la sola sintesi redatta e verificare il digest della registrazione a fine lettura.

Il limite del primo output è una causa possibile, da verificare sul VPS. Il nuovo blocco riporta la dimensione effettiva, il raggiungimento del limite e, se serve un nuovo decoder, il suo codice di uscita. Esecuzione VPS pendente, durata massima quattro minuti. Verificati localmente la lettura a blocchi, UTF-8 e il rifiuto di un JSON troncato.

```bash
sudo /usr/bin/timeout 240 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/98dd534673a2843438cab1b5da8679fd6d1db11e/scripts/read-oci33-onboarding-upload-jfr.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(19366)
if len(raw) != 19365 or hashlib.sha256(raw).hexdigest() != '28c0232cd3005095b4c257bcbbf4ed76c9778c82bb56063689f4324b03e14b79':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
exec(compile(raw, 'read-oci33-onboarding-upload-jfr.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare solo il JSON finale.

## Blocco della prima decodifica eseguita

1. Montare la registrazione esistente in sola lettura nel container dell'immagine esatta, avviando solo l'eseguibile `jfr` con rete `none`.
2. Filtrare le eccezioni e gli handshake nella finestra fra intento e risposta del POST. Conservare il JSON dettagliato sul VPS e restituire solo categorie, classi, codici riconosciuti e conteggi. Verificare il digest della registrazione prima e dopo.

L'esito atteso è `ONBOARDING_UPLOAD_JFR_READ_BACK`. Il blocco non avvia l'applicazione e non invia richieste di upload. Durata massima tre minuti. Verificati localmente il filtro temporale, la redazione e il percorso dell'eseguibile nell'immagine. Il primo tentativo di decodifica è stato sospeso.

```bash
sudo /usr/bin/timeout 180 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/bab2f31c08bb05a31534234a62669400548186c9/scripts/read-oci33-onboarding-upload-jfr.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(12715)
if len(raw) != 12714 or hashlib.sha256(raw).hexdigest() != '3d3fa8c0b36db2268d29b7e3225ebfbd56b3b9783a78f885f8fc159e62fe9dea':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
exec(compile(raw, 'read-oci33-onboarding-upload-jfr.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare solo il JSON finale.

## Blocco del tentativo VPS eseguito

```bash
sudo /usr/bin/timeout 720 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/6a557a0236b841b2a40c4ebcd84ea9b13dc1e125/scripts/boot-oci33-onboarding.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(44510)
if len(raw) != 44509 or hashlib.sha256(raw).hexdigest() != '79fc2303851f09f805ad6c7919571113c98ed6d9b24bd7eaabf5faf375a354bf':
    raise SystemExit('HELD: SHA-256 o dimensione non corrispondente')
module = {'__name__': 'onboarding_upload_trace'}
exec(compile(raw, 'boot-oci33-onboarding.py', 'exec'), module)
raise SystemExit(module['main'](upload=True, trace=True))
PY
```

Riportare solo il JSON finale.

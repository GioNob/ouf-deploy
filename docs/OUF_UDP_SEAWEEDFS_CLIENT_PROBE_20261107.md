# Prova UDP installato → SeaweedFS

La lettura corrente ha identificato UDP `sha256:ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52`, JAR `/app/app.jar` e AWS SDK `2.54.17`. Il target già preparato è `https://ouf-seaweedfs-stage:9002`, bucket `ouf-udp`, path-style true, us-east-1. [Ricevuta](../evidence/udp-current-storage-bindings-operator-20261107.json).

## Azione concreta

Il comando legge dall'ambiente corrente solo le proprietà storage consentite di `SPRING_APPLICATION_JSON`; non emette il resto o le credenziali. Questi valori sono dichiarazioni, non un dump della configurazione effettiva Spring. La [documentazione Spring Boot](https://docs.spring.io/spring-boot/reference/features/external-config.html) colloca il JSON dopo le variabili d'ambiente e gli argomenti command line dopo il JSON; il cambio successivo dovrà tenerne conto.

Poi crea un container temporaneo della stessa immagine su rete SeaweedFS privata, importa la CA nel suo truststore e usa il profilo credenziali già preparato. Senza avviare Spring, chiama la factory `S3LakeConfiguration.lakeS3Client` e l'adapter `S3LakeObjectStorageAdapter` originali dopo confronto degli SHA osservati.

Su una chiave UUID nuova in `diagnostics/seaweedfs-client/`: HEAD deve indicare assenza; un PUT logico del piccolo CSV sintetico, HEAD dell'adapter e GET completo, con verifica di corpo, hash, dimensione e metadato hash. I retry SDK originali restano attivi. L'oggetto diagnostico viene conservato e identificato nel risultato; nessun oggetto applicativo preesistente viene selezionato per scrittura. Il container temporaneo e la copia delle credenziali vengono rimossi, con esito esplicito della pulizia.

UDP originale resta avviato e invariato. Nessun avvio Spring, accesso applicativo DB, fermata servizi, cambio binding o PUT MinIO. Questa prova non è ancora il passaggio UDP o un E2E.

## Blocco unico VPS

Commit `ad27a0ac6417e4c36599e3f1eb94f6ced71bd7dc`; 25198 byte; SHA-256 `612c796478c4c18a8ac1c21ba3a4890e17fbd3c77c266a4a521c2b381cde26f9`. Massimo cinque minuti per l'intero blocco.

```bash
sudo /usr/bin/timeout 300 /usr/bin/python3 -I -B -S - <<'PY'
import hashlib, urllib.request
url = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/ad27a0ac6417e4c36599e3f1eb94f6ced71bd7dc/scripts/probe-current-udp-seaweedfs-20261107.py'
with urllib.request.urlopen(url, timeout=25) as response:
    raw = response.read(25199)
if len(raw) != 25198 or hashlib.sha256(raw).hexdigest() != '612c796478c4c18a8ac1c21ba3a4890e17fbd3c77c266a4a521c2b381cde26f9':
    raise SystemExit('STOP: dimensione o SHA-256 non corrispondente')
exec(compile(raw, 'probe-current-udp-seaweedfs-20261107.py', 'exec'), {'__name__': '__main__'})
PY
```

Riportare il JSON finale. Successo atteso: `UDP_INSTALLED_CLIENT_PUT_HEAD_GET_MATCH`, `metadataMatches:true`, `bodyMatches:true`, container temporaneo rimosso e originale invariato. Su errore non rilanciare alla cieca: il JSON conserva fase e classi/codice HTTP/S3 quando disponibili, senza messaggi raw. La directory privata conserva intento e risultato.

## Stato delle prove

Compilazione Java 17 PASS (compatibile con JVM 21); bytecode incorporato verificato. Controlli locali Python PASS: redazione/allowlist JSON, chiavi duplicate, successo simulato, target cambiato prima del create, errore di trasferimento e timeout cleanup con rimozione della copia delle credenziali. Le fixture non eseguono AWS SDK né SeaweedFS: questo risultato resta da ottenere sul VPS. [Preparazione verificabile](../evidence/udp-seaweedfs-client-probe-preparation-20261107.json).

Se il test passa, confrontare/allineare gli oggetti UDP correnti e cambiare il binding a writer fermo, conservando immagine e identità applicativa. Proseguire poi dal CSV già profilato; non ricaricare.

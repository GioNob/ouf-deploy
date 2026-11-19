# Confronto minimo curl / client Java su SeaweedFS

## Contesto verificato

Il readback VPS del 7 novembre, 15:29 UTC, conferma Onboarding sull'immagine `7b9d3e91…`, rete `ouf-backend`, endpoint `http://ouf-minio:9000` e bucket `ouf-managed-files`. SeaweedFS `d23a50eb…` è attivo su `ouf-seaweedfs-private`, senza porte pubblicate. Non condividono reti Docker; questo non è una prova di raggiungibilità o irraggiungibilità.

[Ricevuta operatore](../evidence/storage-current-bindings-operator-20261107.json).

## Prova pronta

[Programma](../scripts/compare-current-seaweedfs-clients-20261107.py). SHA-256: `d4cd5ffc303f77923f73e89e17f922c90380f1f2a6c96501fd2fa0fd17143ca3`.

Una sola esecuzione crea un container temporaneo dalla stessa immagine Onboarding, sulla rete privata già esistente. Usa CA e identità Onboarding già preparate per SeaweedFS. Non avvia Spring o database, non modifica reti/binding dei servizi esistenti, non riavvia la vecchia prova isolata.

1. Verifica immagini, configurazione target e supporto SigV4 di curl.
2. Importa la CA in un truststore temporaneo; carica dal JAR installato l'adapter e il client MinIO, verificando i metodi necessari prima di scrivere.
3. curl esegue PUT e GET di un CSV sintetico di **29 byte**, su una nuova chiave UUID nel prefisso managed-files.
4. Lo stesso client MinIO costruito dall'adapter installato esegue PUT e GET, con identità, endpoint, contenuto e chiave identici. La chiamata diretta al client evita il catch dell'adapter che nasconde la causa tecnica. Gli argomenti stream, contentType e bucket corrispondono al codice scelto.
5. Confronta i corpi; emette solo esiti, classi di errore e codice/stato S3 quando disponibili. Rimuove il container temporaneo e le copie temporanee delle credenziali. La chiave diagnostica è conservata nel risultato; non è un asset applicativo e non va adottata come upload di Giovanni.

curl usa regione us-east-1; Java conserva la scelta dell'adapter installato, compresa l'eventuale discovery della regione. Non si altera il client per far passare il confronto. Il driver non aggiunge retry; il client Java conserva quelli propri dell'immagine.

Limite del driver: 220 secondi più la breve rimozione finale del container. L'intento con chiave/hash è conservato prima del primo PUT. In caso di timeout il risultato non presume che l'oggetto sia assente.

## Interpretazione

- **Entrambi PASS:** trasporto e client dell'immagine scelta funzionano sul target configurato. Il passo successivo è collegare e provare il percorso applicativo; F1/F2 non sono ancora chiusi.
- **curl PASS, Java FAIL:** leggere fase, classi dell'eccezione e codice S3. Confrontare la differenza dimostrata; non attribuire automaticamente la causa all'SDK.
- **curl FAIL:** il confronto Java resta utile. Né un errore curl né il vecchio 502 identificano da soli filer, proxy, CA o policy S3.
- **Preflight fallito:** nessun PUT iniziato da questo programma; correggere soltanto il problema indicato, senza avviare un nuovo laboratorio.

## Validazione e limiti

Java compilato per Java 17, caricabile dalla JRE 21 dell'immagine; Python analizzato sintatticamente; digest della classe incorporata verificato. Una fixture HTTP locale ha validato la firma SigV4 dei due comandi curl e l'identità dei byte PUT/GET. Non prova TLS, SeaweedFS o il classpath del JAR target: questi controlli avvengono sul VPS.

[Evidenza di preparazione](../evidence/storage-client-comparison-prepared-20261107.json) · [Sorgente del piccolo invocatore](../scripts/diagnostics/StorageClientProbe.java).

Spring Boot documenta il caricamento delle librerie annidate con [PropertiesLauncher](https://docs.spring.io/spring-boot/specification/executable-jar/launching.html). Il client non avvia il main applicativo. [curl documenta SigV4](https://curl.se/docs/manpage.html); la fixture verifica anche la firma del contenuto.

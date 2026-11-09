# UDP 1024: sostituzione qualificata, esecuzione VPS attesa

9 novembre 2026, Europe/Rome. Ingestion, Onboarding, MCP e Semantic aggiornati sono già pronti: non ripetere i loro installer. UDP usa ancora SeaweedFS con il codice precedente. Questo passo sostituisce soltanto il container UDP mantenendo configurazione, reti e dati.

## Risultato acquisito

La [ricevuta delle06:27CET](../evidence/udp-wide-preflight-operator-20261109.json) conferma il CID ab0ce29e e la storia V1–V36 esatta. Alla lettura:34 handoff PROCESSED,34 job SUCCEEDED,110 oggetti lake VERIFIED; una manutenzione READY non dovuta, nessuna lease non scaduta o piano shadow. Sono osservazioni a quell'istante, ricontrollate dall'installer prima dello stop.

Gli argomenti storage puntano a https://ouf-seaweedfs-stage:9002, bucket ouf-udp, path-style=true. Truststore e file credenziale montati correttamente; due reti, vecchio writer MinIO spento. Queste dichiarazioni non sono una lettura completa della configurazione Spring effettiva.

## Candidato esatto e qualifica

[PR49](https://github.com/GioNob/ouf-udp-object-resolution/pull/49), source c0cf1702b2eb971718996a959414caee004af494, alza da32 a1024 il limite dei segnali di identità. Nessuna nuova migrazione. [Archivio originario](https://github.com/GioNob/ouf-deploy/actions/runs/42527648108), artifact13635797332, contiene l'immagine usata per tutte le prove e per la consegna.

I byte ZIP, gzip, blob OCI, JAR,36 migrazioni e YAML sono stati riletti e verificati. Factory/adapter S3 e motore identità selezionati hanno hash uguale all'installato; PublishedIdentityPolicy cambia. Non è un confronto di tutte le classi/librerie con il vecchio JAR. [Record del pacchetto](../evidence/udp-wide-downloaded-package-20261109.json).

[CI42568440028](https://github.com/GioNob/ouf-deploy/actions/runs/42568440028), source 2a9e90cfb4a18d8a221ece1cde1019257684bdf5: Docker29.8.1 classic e containerd, sette test guard più due cicli nativi per backend, zero skip, log letti. Entrambi i profili richiedono legacy MAC realmente presente prima dello stop. Detach privato prima/backend ultimo, rename e nuovo avvio conservano IP/MAC/alias di entrambe le reti. Non si esclude globalmente MacAddress.

Il candidato archiviato raggiunge readiness200 con utente10004:10004 e ruolo DB ordinario su PostgreSQL17/PostGIS3.5, storia V36 e59 tabelle sintetiche invariate. Spring JSON, argomenti e mount sono conservati; recovery API abilitata, polling manutenzione/shadow configurato con lavoro non dovuto. Probe JVM HTTPS con CA privata riuscito. Il predecessore della fixture usa la stessa immagine candidata; il vecchio pacchetto VPS è vincolato separatamente da frame e hash. Nessuna prova S3 PUT/GET o normale operazione lake è inclusa in questa qualifica. [Prove e limiti](../evidence/udp-wide-upgrade-qualification-20261109.json).

La prima esecuzione CI42568313188 falliva durante la preparazione PostGIS usa-e-getta: controllo socket locale prima del listener TCP definitivo. Corretto solo il controllo della fixture; nessun effetto VPS.

## Comando sul VPS

Delivery b9fa2199e22dadfd75957f773d5324228e1da4ff; wrapper SHA256 f9ded8b27edcd212557c50976d6bc09634c52bb794dd530718dd2c864264d225. Otto sorgenti/helper riletti e verificati; wrapper riletto e sintassi Bash verificata. Download pubblico per run/nome provato e identico allo ZIP GitHub. Il precedente URL per solo artifactID restituiva404: non è usato nella consegna.

```bash
(
  set -euo pipefail
  ouf_udp_install=$(mktemp /tmp/ouf-udp-wide-install.XXXXXX)
  trap 'rm -f -- "$ouf_udp_install"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/b9fa2199e22dadfd75957f773d5324228e1da4ff/scripts/install-udp-wide-public-archive-20261109.sh' \
    -o "$ouf_udp_install"
  printf '%s  %s\n' 'f9ded8b27edcd212557c50976d6bc09634c52bb794dd530718dd2c864264d225' "$ouf_udp_install" | sha256sum -c -
  bash "$ouf_udp_install"
)
```

Il wrapper accetta anche il percorso di uno ZIP locale come unico argomento, verificando lo stesso hash. Non richiede GitHub CLI.

L'installer verifica lo stesso frame API1.44 del preflight, JAR e truststore; importa il pacchetto, ricontrolla attività e storia con sessioni READ ONLY, quindi ferma il vecchio UDP e conserva entrambi gli endpoint nel sostituto. Richiede assenza di lavoro incompleto e manutenzione non prevista nei successivi10minuti. Il poll di manutenzione non modifica righe quando non trova un lavoro dovuto, secondo il codice del repository. Non introduce tolleranze sui campi o scritture alle pianificazioni. Confronta storia e impronte delle59 tabelle prima dello stop, dopo lo stop e dopo l'avvio; i payload rimangono nel database.

Conserva ENV (incluso Spring JSON), argomenti Java, file credenziali, truststore e mount; cambia soltanto immagine/metadati di provenienza e dichiarazione della versione Java dell'immagine. Nessun migratore esplicito, replay, nuovo upload o richiesta business. Il normale avvio applicativo può accedere a DB/S3 secondo la configurazione esistente. Vecchio UDP e vecchio writer MinIO restano spenti.

Esito atteso: **UDP_WIDE_1024_READY**. La ricevuta deve attestare readiness,59 tabelle e storia invariati, reti e storage conservati. Se HELD, conservare il JSON e le prove private; non rilanciare o riavviare il vecchio. Un tentativo già iniziato non viene ripetuto automaticamente.

## Dopo la ricevuta

Readiness non dimostra UDP funzionale1024 né E2E. Seguono verifica funzionale dei moduli, credenziale/trasporto/delega/grant e attivazione discovery, associazione delle colonne Teatri a proprietà OntoPiA, review THS→Ingestion→UDP→grafo. Conservare asset/profilo Teatri. F2–F6 restano aperti.

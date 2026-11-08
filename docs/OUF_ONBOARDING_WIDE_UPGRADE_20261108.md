# Onboarding 1024: sostituzione preservando SeaweedFS

8 novembre 2026. **Controller qualificato, esecuzione VPS ancora attesa.** Semantic V12 e MCP V14 sono già pronti; non rieseguire i loro installer. Il prossimo intervento riguarda soltanto Onboarding.

## Prerequisiti acquisiti

La [ricevuta delle 20:58 CET](../evidence/onboarding-wide-preflight-operator-20261108.json) conferma il container d4f22ff3 sulla doppia rete backend/SeaweedFS, JAR installato e storia Flyway V1–V38 uguali alle risorse del candidato. OID database 21552, ruolo applicativo non superuser. Argomenti storage del processo e hash del truststore corrispondono allo switch SeaweedFS; file credenziale montati read-only e coerenti con host, senza leggerne i contenuti. Configurazione dichiarata non equivale alla configurazione Spring effettiva completa. Vecchio writer MinIO spento.

Candidato Onboarding `cc6c7869b308c695460d8491a121084893a3c323`, publisher CI `cddc891e6e528b6558469f68d549ae574db3d512`: stesso albero Git. Si usa l'archivio originale 13592211485, senza nuova build. Download pubblico integrale e SHA256 verificati. [Record pacchetto](../scripts/onboarding-wide-candidate-package-20261108.json).

## Effetto e verifiche

Il comando importa l'immagine archiviata, ferma il solo Onboarding corrente, stacca prima la rete privata e poi backend, conserva il vecchio container spento e crea il sostituto con gli stessi indirizzi, MAC e alias delle due reti. Mount e argomenti Java restano quelli osservati. Cambiano immagine, label di provenienza e il metadata ENV JAVA_VERSION coerente con il JDK dell'immagine; l'entrypoint di attesa esegue poi gli stessi argomenti Java. Interruzione temporanea di Onboarding: evitare operazioni concorrenti durante il comando.

Prima dello stop richiede frame esatto, JAR vecchio esatto, readiness, storia V38 esatta, asset/profilo Teatri presenti e file storage coerenti. Prima del rilascio dell'avvio verifica JAR candidato e truststore. Alla fine richiede readiness HTTP 200/UP, stesso processo Java, endpoint conservati, storia V38 e impronte private delle due righe Teatri invariate. Le impronte non espongono i contenuti delle righe.

Nessun migratore esplicito, upload/profilazione, richiesta S3 o business, grant, modifica Gateway o scrittura credenziale. Il normale avvio Spring può accedere al database ed eseguire i job già presenti. Le due sessioni SQL emesse dal controller sono READ ONLY. I vecchi writer MinIO rimangono spenti. Provider/worker Semantic e strumenti MCP non vengono attivati da questo intervento.

Journal privato: `/var/lib/ouf-storage-migration/onboarding-wide-upgrade-20261108`. Esito positivo: marker separato `/var/lib/ouf-storage-migration/onboarding-wide-current.json`. Le vecchie prove dello switch SeaweedFS restano storiche e non vengono riscritte: dopo il successo, il marker wide identifica il nuovo container corrente.

## Qualifica e limiti

[CI 42518570091](https://github.com/GioNob/ouf-deploy/actions/runs/42518570091), source e5bec2ee, job classic 128846853225 e containerd 128846853003: per backend quattro test mirati e due cicli native, zero skip, log letti. Docker 29.8.1; due reti reali; entrambi i profili EXPLICIT_LEGACY_CONFIG e ENDPOINT_ONLY_COMPAT_CONFIG devono avere Config.MacAddress presente inizialmente.

Il ciclo prova: avvio → stop → detach privato (legacy invariato) → detach backend (legacy assente) → rename → nuovo container → avvio del JAR archiviato. IP/MAC/alias di entrambe le reti conservati, vecchio container fermo, stessa generazione/mount/HostConfig; ruolo applicativo non superuser, storia V38 e righe sintetiche invariate. Una richiesta HTTPS della JVM verifica la CA privata senza bypass TLS. [Evidenza completa](../evidence/onboarding-wide-upgrade-qualification-20261108.json).

Il predecessore CI usa lo stesso candidato; il vecchio binario VPS non è eseguito nella fixture. I dati, le credenziali e la CA sono sintetici; la preparazione del solo database usa temporaneamente privilegi poi revocati prima di entrambi gli avvii. IAM e S3 sono configurazioni fittizie: non sono una prova del trasferimento target o dell'E2E. Il primo run 42518460282 si fermò nel setup PostgreSQL su rete interna, prima di qualsiasi test native; corretto l'indirizzo della fixture senza cambiare il controller.

## Unico comando corrente

Consegna `a924345385c863246fc597bbe1321965e4f93173`; controller e dipendenze fissati a e5bec2ee e verificati tramite SHA256 prima dell'esecuzione privilegiata. Non richiede gh sul VPS.

```bash
(
  set -eu
  ouf_install=$(mktemp /tmp/ouf-onboarding-wide-install.XXXXXX)
  trap 'rm -f -- "$ouf_install"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/a924345385c863246fc597bbe1321965e4f93173/scripts/install-onboarding-wide-public-archive-20261108.sh' \
    -o "$ouf_install"
  printf '%s  %s\n' \
    'bc2e5318f33737be0fd8e0d28559b5ea24293340259938b2705955cd89cb1dd1' \
    "$ouf_install" | sha256sum -c -
  bash "$ouf_install"
)
```

Restituire il JSON finale. L'esito atteso è `ONBOARDING_WIDE_1024_READY`, con storia e righe Teatri invariate, reti/mount/truststore conservati e readiness UP. `wideProfileFunctionalTested:false` resta corretto: la readiness del pacchetto non è una nuova profilazione né l'E2E.

In caso di HELD, conservare journal e output e non rilanciare il comando né riavviare il vecchio container. Nessun rollback o replay automatico. Dopo l'esito positivo: Ingestion/UDP 1024, percorso provider e attivazione strumenti, analisi sul profilo Teatri conservato, review THS → Ingestion → UDP → grafo e ripetizione.

# Onboarding 1024: sostituzione preservando SeaweedFS

8 novembre 2026. **Aggiornamento completato sul VPS alle 21:16 CET. Non ripetere l'installer.** Semantic V12 e MCP V14 sono già pronti; non rieseguire i loro installer. Il prossimo intervento riguarda soltanto Onboarding.

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

## Esito acquisito

La [ricevuta operatore](../evidence/onboarding-wide-ready-operator-20261108.json) conferma `ONBOARDING_WIDE_1024_READY`, nuovo container `d0b9ff8400f802645e12e72a8e921826253f4934582a0201070da4f9f1a6e3b5`, immagine containerd `sha256:880bbf92867a19c0bf45ad918e7cf85c4f5ea07ed57b462c10fcea96a4af2544`, readiness200. Tutte le verifiche di preservazione sono riuscite: storia V38, righe Teatri, due reti/IP/MAC/alias, mount/truststore e argomenti Java. Il metadata JAVA_VERSION è allineato all'immagine. Vecchio Onboarding SeaweedFS trattenuto spento; writer MinIO sempre spento.

Nessun migratore esplicito, scrittura credenziale, grant, route, richiesta S3/business da script. Il normale avvio applicativo può accedere al database e ai job esistenti. `wideProfileFunctionalTested:false`: non è stata ripetuta la profilazione e non è una prova E2E.

Consegna eseguita `a924345385c863246fc597bbe1321965e4f93173`; il comando è conservato nella [versione storica](https://github.com/GioNob/ouf-deploy/blob/358eed3266ad8fed1d6ecd7ae3498399bfab622c/docs/OUF_ONBOARDING_WIDE_UPGRADE_20261108.md). Non rieseguire. Prossimo componente: Ingestion; asset e profilo Teatri restano quelli in STATE.

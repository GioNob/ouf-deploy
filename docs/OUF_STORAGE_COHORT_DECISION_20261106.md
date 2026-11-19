# Coorte storage — origine ricostruita e delta di qualifica

Base fb2a85df397c4ebb043dd4d7ba26e13a8f0659e7. [Ricevuta riproducibile](../evidence/storage-cohort-retained-reconciliation-20261106.json). Nessuna operazione target; non è ammissione né prova live.

## Correzione della lettura precedente

Tutti i13native image ID della raccolta G0 coincidono con la riconciliazione delle origini del1novembre. Le prove selezionate config/layer/diffID erano già state verificate sul target e sono riutilizzate, non rieseguite. Questo ricostruisce la catena conservata; non esclude modifiche di mount/configurazioni o del layer scrivibile successivamente.

Onboarding image7b9d3e91 è legata all'artifact12836316286 e al sorgente testato73498c17596ae155a3ed9ab36acfd6bb69da9846. La consegna V38 del28ottobre riporta la stessa immagine e il sorgente revisionato9d19fad3dd750dd5b9e77253d3e7e82029c1aca7. Lettura indipendente dei due commit Git: **stesso tree091a10a53da04ed46759f345e877a69e8db87021**. JAR conservato SHA256152159de758ead299d53eaf9cf113c01445b7e1d6fa86590ba0a1248bf4ef681. La dichiarazione container194b5865 non è la fonte da usare per identificare il codice dell'immagine. Non si conclude però che il JAR in esecuzione oggi sia stato letto o verificato.

MinIO14cea493 è il root/native image ID;69b2ec20 è la configurazione del manifest selezionato a1a8bd4a. La rehearsal usa esattamente69b2ec20. **Ritirata l'affermazione del precedente runbook che le due stringhe provassero immagini sorgenti diverse.** Rimangono i limiti reali: rehearsal sintetica, publisher originale non autenticato, sicurezza del MinIO legacy HELD, nessuna prova di parità/rollback applicativo target.

Fonti: [custodia V38](../releases/managed-file-owner-v38-image-custody-20261028.json), [consegna V38](../evidence/managed-file-owner-v38-update-target-20261028.json), [origini](../releases/m2-current-core-artifact-origins-20261101.json), [riconciliazione](../releases/m2-retained-runtime-origin-reconciliation-20261101.json), [byte proof](../evidence/m2-selected-runtime-target-20261101.json), [join](../evidence/m2-runtime-origin-join-target-20261101.json).

## Scelta tecnica per lo sviluppo già autorizzato

Confermata la candidata già indicata nella richiesta G0 del5novembre: SeaweedFS OCI33, Onboarding **d5155899**, UDP **0d40da05**, Ingestion **4165b9e1**. Non cambiare il source-lock storico e non considerare questa scelta un deploy. Per Onboarding qualificare il modulo completo: non innestare putReserved nell'immagine V38 con interfaccia put.

La scelta evita di qualificare come definitiva la vecchia sequenza PUT prima dell'intento, già identificata nella mappa writer come rischio di esito ambiguo e transazione mantenuta durante I/O. d515 introduce prenotazione durevole e chiave stabile, I/O fuori transazione e riconciliazione senza secondo PUT. Queste implementazioni sono già qualificate nelle prove native conservate; non ripeterle per dichiarare avanzamento.

[Confronto Git73498→d515](https://github.com/GioNob/ouf-source-onboarding/compare/73498c17596ae155a3ed9ab36acfd6bb69da9846...d5155899b09dda298494b68cefa7e1f281167652):58file,20Java di produzione, nuove migrazioni V39/V40/V41; pom.xml invariato. Non è un cambio del solo endpoint storage.

| Delta | Già provato | Residuo concreto prima del passaggio |
|---|---|---|
| Upload d515 |Intento, fence, crash/esiti PostgreSQL e API nella qualifica conservata |Modulo/image esatto con configurazione e dipendenze finali sul binding SeaweedFS rappresentativo |
| V38→V41 |Migrazioni e guard nel codice qualificato |Backup coerente prima di startup, migrazione controllata sull'insieme target e ritorno compatibile; non eseguire downgrade distruttivo |
| Autorizzazione locale |SDK/adattatori qualificati come componenti |Non installare o concedere capability recovery per implicazione; HTTP/HUMAN necessario solo per comandi realmente usati |
| Client UDP |Adapter0d40 nel test client33 |La fixture usa httpclient5.6.5/httpcore5.4.4; POM servizi non aggiornati da quella prova. Risolvere dipendenze della coorte finale, senza dichiarare già qualificato il servizio |
| MinIO→OCI33 |Rehearsal già sul configuration ID coerente con sorgente osservata |Dati/configurazioni/TLS/accessi/capacità target e rollback DB/oggetti; nessun rerun per una falsa differenza di ID |

V39 inizializza il controllo locale ACTIVE. L'isolamento esterno e il fermo dei writer devono quindi restare applicati durante startup/migrazioni: quell'ACTIVE iniziale non autorizza traffico, non dimostra drain e non riammette una generazione. V40/V41 non pubblicano capability né grant operativi. I10tenantNULL legacy restano tali e le prove di proprietà vanno preservate.

## Uscita di questo passo

Origine dell'immagine Onboarding ricostruita, label distinta da sorgente, falsa differenza MinIO eliminata, candidata di sviluppo e delta espliciti. Non sono risolti membership live, piena compatibilità dei servizi o G1/G2.

Il [pacchetto operativo](OUF_STORAGE_OFFLINE_CUTOVER_RUNBOOK_20261106.md) usa queste identità e la [matrice writer](../releases/storage-offline-writer-containment-20261106.json). Un'unica lettura locale preparata identifica l'immagine del container attivo fuori roster e le eventuali mount che coprono /app/application.jar dai due documenti già sigillati. Non rilegge corpi/DB, non interroga provider, non risolve da sola il censimento esterno o la membership live.

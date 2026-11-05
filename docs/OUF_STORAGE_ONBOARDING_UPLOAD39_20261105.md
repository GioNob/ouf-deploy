# Onboarding: intento durevole e qualifica nativa V39

## Due passi richiesti

1. Integrare nell'owner esistente l'intento persistente prima del PUT, con chiave stabile e I/O fuori dalla transazione.
2. Verificare il codice applicativo con PostgreSQL e storage reali, includendo crash, risposta persa e cambio di generazione.

La preferenza dell'utente del 2026-11-05 è procedere **due passi per volta**. Non costituisce autorizzazione runtime o promozione del candidato.

## Implementazione candidata

[PR Onboarding54](https://github.com/GioNob/ouf-source-onboarding/pull/54), branch `feat/storage-upload-intent-20261105`, sorgente `9d8a1ecea00ac5f614c8e3d6fed61d3d1df85e5f`, tree `b6734fba1befe90033fd49585ca4b034569ec226`. Parte dall'esatto candidato `73498c17596ae155a3ed9ab36acfd6bb69da9846`, senza sostituire il source-lock deploy né la sorgente riportata installata. PR draft; nessun merge o deployment.

V39 aggiunge intento owner-local e controllo monotono di generazione/fase. Le due API upload conservano autenticazione, tenant, verifica del contenuto e forme di risposta. L'intento è committato prima del PUT, con riferimento `object://managed-files/<intent UUID>`; l'ACK registra asset, ricevuta delegata e completamento nella stessa transazione, soltanto nella generazione ACTIVE originale. Nessun lock o transazione resta aperto durante il PUT o la lettura di riconciliazione. Un chiamante con transazione esterna viene rifiutato prima dell'effetto.

Un intento può essere inviato una sola volta. Dopo un esito ambiguo si leggono e verificano i byte dello stesso oggetto, senza secondo PUT; oggetto assente, accesso negato e contenuto differente non autorizzano reinvio. Il budget persistente consente massimo128 letture in24ore, senza scheduler, rinnovo o reset implicito. Un crash dopo la prenotazione ma prima del PUT conserva prudentemente un intento irrisolto: non si presume che un oggetto assente autorizzi una seconda scrittura.

L'upload diretto accetta `Idempotency-Key` opzionale. Senza chiave, richieste distinte continuano a identificare upload distinti: non si dichiara deduplicazione fra richieste prive di identità stabile. Namespace DIRECT/DELEGATED e proprietario tenant/subject sono separati. Ricevute V31 esistenti restano valide; l'upgrade V38→V39 ne conserva integralmente la riga.

## Prove eseguite

- Primo producer `36704cb0eeb24e8752a28c8e22e5882b8dae4045`: [run41989241682](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41989241682), job127117246135 SUCCESS;12scenari nativi e8test API/store PASS. Artifact13397452441,55372byte, SHA256 `7983d7d2ecacfa0fffc82d323c42ff7dfab0db83ea179c378f553d961c5c214c`, conservato senza sostituzione.
- Producer finale `9d8a1ec`: [run41989631975](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41989631975), job127118496112/attempt1 SUCCESS. **15scenari nativi +8test API/store =23test PASS, zero skipped/error/failure**. PostgreSQL17.11 e stesso candidato OCI33 `sha256:5bfda2ef577b3c33216b82fb3eb1bed3ad76842ed13fc0a114ef94084b20da4d`, binario `c301b4f487f17f4d9b8dfe1b26885ec4ea6141e1ace73b8dfaadff70bd714dfc`.
- Quattro processi JVM separati terminati bruscamente con `Runtime.halt(86)`: uno dopo PUT e prima dell'ACK, tre prima del PUT per i casi assenza, contenuto alterato e budget esaurito. Nessun finally o shutdown hook del processo owner eseguito. Al riavvio l'intento resta in PostgreSQL; la riconciliazione post-PUT produce un solo asset senza nuova scrittura.
- Altri casi: risposta applicativa persa dopo PUT reale, retry concorrente durante I/O, ACK tardivo respinto dopo cambio generazione, drain/freeze, mismatch byte,128letture persistenti, scadenza24ore, transazione esterna, immutabilità della storia, isolamento dei proprietari/route, richieste dirette senza chiave distinte, divieto di regressione del controllo. Upgrade V38 con ricevuta precedente riprodotta senza accesso storage.
- Artifact finale13397423414:61920byte, SHA256 `91b7f31c4e73510a0d58aefd7408ec6a91c988db404db2baa9aac753cacca37a`, custodia Actions fino2027-02-03. **39membri/38checksum,258binding SHA256 e446blob Git** verificati localmente. `evidence/onboarding-upload39-local-readback-20261105.json`; verificatore `scripts/readback-onboarding-upload39.py`. ZIP originali mantenuti anche nel workspace; nessuna custodia Git dei ZIP dichiarata.

Il riscontro su secondo runner è predisposto in `.github/workflows/onboarding-upload39-readback.yml`; diventa prova solo con esito terminale e confronto byte-per-byte della ricevuta locale. La CI completa Onboarding è distinta: test/build PASS osservati, scansione e conclusione globale da registrare separatamente. Sul precedente head deploy `783f883e66403a860d913e0c72f036b9dd37f7c4` tutte50CI sono SUCCESS, compresa la suite del clock precedentemente corretta; il vecchio fallimento e le esecuzioni cancellate restano conservati.

## Limiti e prossimo incremento

Il fence protegge l'ACK dell'owner; non revoca credenziali S3 già in uso né impedisce un PUT già in volo. La perdita di risposta è iniettata nel confine applicativo dopo un PUT reale: non è un proxy che interrompe la risposta HTTP. Non sono provati rolling rollout misti, tutti i writer reali, rotazione fisica delle credenziali insieme a questo owner, common-cut/PITR di queste nuove tabelle, RPO/RTO rappresentativi o power-loss. I test di compattazione e backup precedenti rimangono acquisiti, senza estensione automatica della loro portata.

Prossima coppia delimitata: collegare il ciclo di drain/fence/riconciliazione di questo owner al taglio coordinato PostgreSQL/S3 della fixture; verificarne recupero e rifiuto dei writer obsoleti usando le prove fisiche già acquisite. Restano da integrare gli altri owner UDP/Ingestion prima di affermare un blocco globale degli scrittori.

MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali. MinIO invariato; nessun target, admission, replay, reset, grant o riacquisizione. Le nuove prove qualificano codice candidato e fixture, non l'installazione corrente.

### Blocco della CI completa e correzione candidata dell'immagine

Le esecuzioni complete41989641231 (PR)/41989631999 (push) sono FAILED alla scansione dell'immagine, dopo test/package/build riusciti. Maven:380test censiti,365eseguiti senza errori/fallimenti e15nativi saltati in quella suite perché eseguiti separatamente nel workflow dedicato. Trivy segnala CVE-2026-109518 HIGH in apt3.2.0 e libapt-pkg7.0 3.2.0 della base Ubuntu26.04, fix dichiarato3.2.1ubuntu0.1. Non è una regressione dimostrata dell'upload; i pacchetti sono ereditati dalla base eclipse-temurin:21-jre. Artifact13397389168,669468byte SHA256c681a51dfee58a1e23a7d18099cf94c2d40f0593c5302b075031269c93129b66 e diagnosi evidence/onboarding-upload39-image-scan-failure-20261105.json preservati.

Correzione candidata b64e8b5bc514223aa562719d31eb027e7f27b7b9: cambia soltanto Dockerfile, aggiornando i due pacchetti prima del passaggio all'utente non-root. Java, SQL, pom, test e soglia HIGH/CRITICAL/UNKNOWN restano identici al producer nativo9d8a1ec. Nuova CI avviata; esito non presunto. Il readback indipendente continua a verificare l'originale qualificato9d8a1ec, non a fingere che il suo artifact appartenga al nuovo commit.

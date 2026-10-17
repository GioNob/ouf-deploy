# Riconciliazione delle proprietà: rilascio integrato

Tecniche **8/8**; funzionali **2/6**. L'integrazione e la CI non avanzano da sole l'accettazione sul VPS.

UDP [PR43](https://github.com/GioNob/ouf-udp-object-resolution/pull/43) e Onboarding [PR44](https://github.com/GioNob/ouf-source-onboarding/pull/44) sono integrati nel ramo `feat/resolution-object-comparison-20261017` dei rispettivi repository. Il lock di questo rilascio fissa i merge commit, non un ramo mobile.

| Modulo | Commit del rilascio | Qualifica del codice integrato |
| --- | --- | --- |
| UDP | `4660b08fdf982f7f7ecc35a378fd8fcad30aa273` | [75 test mirati](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39061279849), [CI completa](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39061279845), [CRS/grid](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39061279855) |
| Onboarding | `cc7766e6348f9ed2e66ec04018ebb63a904d202d` | [CI completa](https://github.com/GioNob/ouf-source-onboarding/actions/runs/39061946307), [browser](https://github.com/GioNob/ouf-source-onboarding/actions/runs/39061946299) |

Le prove citate qualificano gli head delle PR; i merge devono avere gli stessi alberi di sorgenti. Il workflow `linked-property-candidates.yml` costruisce i due commit integrati, controlla le immagini con Trivy, esporta sorgenti/immagini/inventari e firma l'indice del pacchetto con Sigstore. Usa il packager esistente, con un lock separato; non modifica i precedenti pacchetti o le selezioni del VPS.

## Distribuzione

La migrazione UDP V35 aggiunge `property_value.reconciliation_evidence` e la tabella append-only `handoff_property_profile`. Onboarding non aggiunge migrazioni. Il vecchio executor Resolution Comparison ha `databaseMigrationsAllowed=false` e pretende alberi di migrazione identici: **non è un executor utilizzabile per questo rilascio**. Non cambiare soltanto il flag o gli hash per superarne il controllo.

Prima della distribuzione occorrono una lettura corrente della generazione UDP/Onboarding e della storia Flyway, backup verificabile, qualifica della transizione V34→V35 con il ruolo realmente usato e un piano di aggiornamento che includa espressamente la migrazione. L'inventario del runner, se disponibile, è una verifica dei container e non una prova del database o dell'autorità runtime. La disponibilità di GitHub Actions non equivale alla disponibilità del trasporto privilegiato sul target.

L'aggiornamento del codice conserva i profili precedenti. L'attivazione richiede pubblicazione owner di `extractionProfile.runtime.udp.materialization.properties[*].reconciliation`, secondo il [contratto nativo](https://github.com/GioNob/ouf-udp-object-resolution/blob/4660b08fdf982f7f7ecc35a378fd8fcad30aa273/docs/LINKED_PROPERTY_RECONCILIATION.md). Cardinalità, normalizzatore, validità, priorità delle fonti e contratto di revisione devono derivare dalla configurazione approvata. I nomi e le priorità degli esempi non sono configurazione dell'installazione.

Lo stesso motore opera su handoff canonici da API, scheduler/delta, file, GeoPackage e layer dinamici. Geometrie e CRS mantengono il percorso nativo dedicato. Non si presume un ordine temporale o una revisione assenti dal contratto della fonte. Non vengono ricalcolati automaticamente gli oggetti esistenti, rigiocate le undici decisioni già confermate o ripreso il caso lasciato in quarantena.

## Esiti verificati

Il [pacchetto CI 39062596949](https://github.com/GioNob/ouf-deploy/actions/runs/39062596949) è completo: build, scansione delle due immagini, controllo degli hash e firma/verifica Sigstore riusciti. Il [test di upgrade 39062821776](https://github.com/GioNob/ouf-deploy/actions/runs/39062821776) applica V35 su V34 popolata, confronta integralmente valori/revisioni/contributi precedenti, verifica append-only e seconda migrazione con zero effetti. Un test nativo passato, zero errori o skip; qualifica il database CI, non i privilegi del ruolo sul VPS.

Il [runner VPS 39062665870](https://github.com/GioNob/ouf-deploy/actions/runs/39062665870) ha letto due volte generazioni stabili: UDP `3bc856dd…`, Onboarding `9d7b64cb…`, entrambi in esecuzione. La successiva [lettura delle migrazioni 39062922689](https://github.com/GioNob/ouf-deploy/actions/runs/39062922689) si è fermata **prima di eseguire Python/SQL**: `sudo: a password is required`. Questo è un limite del trasporto privilegiato disponibile al runner, non un fallimento del test V35. Non vengono modificati sudoers o privilegi e non viene usato Docker per aggirare il blocco.

L'operatore può eseguire `scripts/read-linked-property-migration.py` dal commit `ff5aa359ea8ef0e131505e3a7286a1579ba99b67`, previa verifica SHA256, con `sudo /usr/bin/python3 -I -B -S`. Il lettore verifica il bootstrap conservato e il binding esatto PostgreSQL, apre una sola transazione READ ONLY con timeout, legge storia Flyway e presenza delle nuove strutture, non stampa credenziali. Questo sblocca la verifica del punto di partenza; non applica migrazioni né costituisce un'approvazione di distribuzione.

Riferimenti e limiti sono registrati in [linked-property-qualified-20261017.json](linked-property-qualified-20261017.json). Distribuzione e pubblicazione dei profili restano da eseguire. Il riscontro operatore precedente riporta undici retry accettati, undici oggetti distinti materializzati e undici job SUCCEEDED; non è una nuova lettura dei dati del VPS durante questo rilascio.

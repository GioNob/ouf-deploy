## Checkpoint 2026-11-05 — copia MinIO → OCI33 e ritorno dopo scritture

- Due passi completati: percorso reale isolato MinIO→OCI33 con inventario/compilatore/core esistenti; ripresa dopo crash/503 e ritorno su MinIO vuoto anche dopo ADD/REPLACE_BODY/REPLACE_METADATA/DELETE. Nessuna modifica al core, a Onboarding o al target.
- Candidato `4555f7dc2be2e44aa25277a22a35d7e2597c80ea`; run42068964202/job127391244238 **SUCCESS, 12 esiti nativi PASS inclusi subtest**. 120corpi sintetici/203743byte,10senza hash annunciato;360riletture condizionali finali sui tre provider. Tre crash reali e risposta503 riconciliati senza secondo PUT. Retry-After usa clock virtuale.
- Archivio13435386238:369047byte,SHA256 `6d7b2953ad6e432b9a73c013593cfa679d488e2bd888092f767c308a6a6a596b`; readback locale PASS,27membri/26checksum/137sorgenti Git esatti. Tre stop puliti, rete solo loopback, scan moduli/eseguibili zero rilievi. MinIO legacy conserva gate HELD e publisher originale non autenticato. Custodia Actions fino3febbraio2027, non custodia durevole.
- Tre tentativi falliti conservati: UID root incompatibile con ancestry inventario; cache root del reporter Go; InvalidTag MinIO per il tag speciale storico. Corretti runner/reporting e fixture di compatibilità, senza allentare guard o alterare il test SeaweedFS storico. Il diniego tag è ora asserito senza mutazione; tag supportati/gzip/metadati copiati integralmente.
- MiniPET **18,3/46=39,78%;0/8gate,0/21AT,0/120oggetti reali**. AT14 manca dopo-checkpoint/versioni applicabili; AT15 tutti i writer/delta; AT16 riferimenti/corpi reali; AT17 DB/ritorno operativo. Il successo del rehearsal non chiude questi criteri. Nessun merge/deploy/grant/riapertura/reset/source-lock.
- Prossima coppia: consegna unica e concreta per completare raccolta G0 corrente (corpi/ACL/writer/DB/capacità/finestra), e ricomposizione della matrice prove sulla coorte finale per G2–G4; usare le implementazioni già disponibili e individuare gli input solo operatore. Valutare prima fermo completo: fixture3,207s andata inclusi inventario/compilatore,2,273s ritorno, non RTO/throughput VPS. Non ripartire da altro recovery isolato o HTTP/HUMAN salvo dipendenza dimostrata.
- Dossier `docs/OUF_STORAGE_MINIO33_REHEARSAL_20261105.md`; ricevuta `evidence/storage-minio33-rehearsal-qualified-20261105.json`; reader `scripts/readback-storage-minio33-rehearsal.py`. Stato corrente nel sidecar `releases/minio-seaweedfs-closure-status-20261105.json`; JSON storico congelato invariato. Source PR54 d5155899 draft/open; deploy PR54 draft/open. Verificare CI del nuovo checkpoint documentale separatamente dalla qualifica nativa.

Le sezioni sottostanti conservano lo storico; le precedenti prossime coppie sono superate da questo checkpoint.

# Ripresa OUF2: completare MinIO → SeaweedFS

Obiettivo generale M2: file → onboarding → semantic registry locale/eventuale Ontopia → ingestion → merge/reconciliation → UDP. Priorità attiva: chiudere sostituzione storage, poi il resto M2. Due passi alla volta, sequenzialmente, senza subagenti. Sviluppo GitHub e ouf-admin autorizzati; runtime HUMAN, merge/deploy/grant/riapertura non impliciti.

## Stato e due passi completati

1. [Riesame di G0–G7 e tutti i21 AT](../OUF_STORAGE_CLOSURE_REVIEW_20261105.md), contro PET/Matrix e prove conservate. Distinti implementazione, qualifica e passaggio operativo. Corrette le indicazioni correnti in AGENTS, MiniPET, registro JSON e vecchio handoff: il collegamento HTTP/HUMAN è condizionale alla procedura di migrazione, non il prossimo lavoro obbligatorio.
2. [Piano delta finale offline](../OUF_STORAGE_DELTA_PLAN_20261105.md), codice nel modulo storage_planning esistente, 22test locali PASS e workflow dedicato. Confronta due raccolte metadata complete e hash calcolati da tutti i corpi locali; classifica aggiunte/overwrite/metadati/rimozioni/cambi osservativi. Nessuna rete o effetto, nessuna inferenza di autorità o parità target.

Repository deploy `GioNob/ouf-deploy`, PR54 draft/open, branch `feat/m2-discovery-complete-profile-20261029`: usare il commit che contiene questo handoff e verificare HEAD/CI prima di modificare. Base esaminata `41431adaac06a85d9deeb31da70c156b3f955141`, 50workflowSUCCESS/84check-runSUCCESS. Source Onboarding PR54 draft/open, branch `feat/storage-upload-intent-20261105`, invariato `d5155899b09dda298494b68cefa7e1f281167652`, 8workflowSUCCESS. Nessun run attivo nelle ultime100 restituite per repository; controlli ripetuti e expected SHA prima della scrittura. Processi esterni non sono osservabili tramite GitHub.

[Preflight](../../evidence/storage-closure-preflight-20261105.json), [ricevuta nuova qualifica](../../evidence/storage-delta-plan-qualified-20261105.json). CI del nuovo commit distinta da quella delle basi: consultare run/check sul suo SHA. Non dichiarare un PASS hosted dal solo esito locale.

## Blocchi residui e prossima coppia

G0: writer/consumer/DB completi, ACL/publicAccessBlock, capacità e binding correnti, credenziali custodite, finestra e obiettivi. G1: lifecycle complessivo, review licenze/redistribuzione, custodia durevole e scansioni valide del candidato/client/tool. G2–G4: contratti sulla coorte finale, recovery e prestazioni rappresentativi, migrazione e ritorno completi. G5–G7: pacchetto unico ammesso, passaggio con writer unico e osservazione ≥48h proposta.

Prossima coppia concreta: (1) comporre rehearsal con MinIO isolato e OCI33 esatta, cattura condizionale/autenticata e planner; (2) qualificare gli effetti necessari della procedura scelta e la riconciliazione dopo guasti/ritorno. Prima valutare copia con fermo completo rispetto a precopia+delta, usando misura corrente e finestra: il vecchio inventario di120oggetti/203743byte non autorizza assunzioni sul target oggi. Il planner non esegue replace/delete; il core Go è ancora copy-new, destinazioni non versionate e fixture SeaweedFS storiche. Non promuovere un piano offline a esecuzione.

Il ramo HTTP/HUMAN prosegue solo se è dipendenza della procedura selezionata. Un fermo completo può ridurre le integrazioni richieste ma deve provare quiescenza e assenza di owner incerto; non cancella latch o budget. Preparare i residui G0/G1 in consegna unica, senza microdiagnostiche o replay di scope consumati.

## Prove storiche da riusare

OCI33: binario `c301b4f487f17f4d9b8dfe1b26885ec4ea6141e1ace73b8dfaadff70bd714dfc`, manifest OCI `sha256:5bfda2ef577b3c33216b82fb3eb1bed3ad76842ed13fc0a114ef94084b20da4d`. Le tre ricevute immagine/coorte/runtime sono state confrontate coi SHA256 del piano corrente; non sono stati rieseguiti i relativi laboratori o riletti tutti gli archivi binari.

Recovery Onboarding:116PASS=103nativi+8API/storage+5HUMAN;12SDK separati. Run42049204934; regressione fisica42049204791. Adapter HUMAN qualificato come componente, non endpoint/bean/IdP/UI/MCP/Gateway completo. Resolver PostgreSQL su pool separato con timeout finiti; firma RSA/Nimbus e policy OUF reali nei test. Fencing policy solo JVM, non revoca distribuita. Driver fisico precedente non integra adapter/resolver. [Handoff storico](OUF_STORAGE_ONBOARDING_RECOVERY_HANDOFF_20261105.md), [ricevuta](../../evidence/storage-human-approval-qualified-20261105.json).

Restore dai soli export33 run41976132880 già riuscito; rotazioni/isolamento/compaction qualificati nei rispettivi dossier. Non ripetere prove riuscite senza modifica o motivo documentato. Le scadenze Actions restano quelle dichiarate nelle ricevute (qualifica HUMAN3febbraio2027); nessuna nuova custodia durevole degli artifact storici attestata.

## Invarianti e avanzamento

- Mai cancellare owner.database/latch, usare altra connessione per catturare xid owner o inferire l'esito dalle righe business.
- Approved/Prepared sempre chiusi; nessun fence locale durante query/attese; riconciliazione termina REVOKED, nuova ammissione distinta.
- Niente retry cieco di esiti ambigui, reset budget tramite restart/sessioni o riammissione automatica dopo restore.
- MiniPET **18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali**. Nessun credito dalla nuova qualifica offline.
- MinIO e source-lock invariati; nessun merge/deploy/target/grant/riapertura. Teatri e stessa Farmacie preservati.

Descrizioni PR precedenti conservate in [archivio](OUF_PR54_STORAGE_HISTORY_BEFORE_CLOSURE_REVIEW_20261105.md). I checkpoint storici che propongono altre prossime coppie non prevalgono sulla priorità qui fissata.

### Esito CI e correzione del registro storico

Planner `747c4772075e8c0c36ad4b906cecacd494d02ab3`: 22test hosted PASS, run42060454823/job127360334434. Archivio13432675036 verificato localmente:1948byte,4membri/3checksum/4hash sorgenti esatti, SHA256 `4024a5cd4798087166b9f7a8b6294bf0715d402e712b1ab33fcdb82a11bcf3ce`. Custodia Actions fino3febbraio2027, nessuna nuova custodia durevole attestata.

Il run42060454629/job127360334387 del registro storico è FAILED con `ALL_PRE33_HISTORY_AND_PROGRESS_IMMUTABLE`: il primo commit aveva modificato nextPlannedWork/currentHandoff e aggiunto stato corrente nel JSON congelato. Ripristinato il file originale byte per byte; stato e prossima azione sono ora in `releases/minio-seaweedfs-closure-status-20261105.json`. Verificatore, hash di riferimento, codice planner, punteggi e gate non modificati. Il fallimento resta conservato; Per la CI della correzione fanno fede i check del commit contenente il ripristino, riportati nella PR54.


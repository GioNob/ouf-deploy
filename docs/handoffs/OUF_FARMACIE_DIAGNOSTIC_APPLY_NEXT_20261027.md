# NEXT — sola riconciliazione dei file conservati, nessun nuovo APPLY

Il precedente APPLY è consumato in STOP pre-review. Il nuovo reader è qualificato: source b1618031d8c1d7ab10efd9c9742bc5c1b96131e8/SHA cd89338de4dcdbb55930981f05a446c3b5184648945b9f5e6f8060ca215e932a; delivery5b91c2eb9302b8aaeb3a60cf45f26ce7b7951a1e/wrapperSHA2138066add8c89fec929b448f7dc8cf1205c2daa9ac400b49dbfb69b10af12e6. CI40467119923/jobs122065105823+122065106399 PASS:12test senza skip, consegna pubblica reale curl/sudo/root0400/checksumroot/log0600; entry esatta rifiuta hash privato sintetico errato, file originali invariati. Log diretti letti. [Prova](../../evidence/onboarding-transport-stop-reader-qualified-20261027.json).

Legge sette file conservati (due input/plan, claim, tre tentativi, log) e verifica21fonti+manifesto del controller fermato senza eseguirlo. Massimi60s/8MiB. Zero Engine/SQL/OAuth/letture configurazione/credenziali/chiavi; nessun APPROVO, modifica originale o autorità nuova. Confronta separatamente schema, Enginebinding e runtimebindingprofile; stampa soltanto campi/tipi/hash dei delta, mai valori privati. Non osserva lo stato runtime corrente e non autorizza alcuna continuazione.

Serve il terminale owner perché i due profili e le claim sono privati sul VPS e non disponibili via GitHub/chat. UNA esecuzione della sola lettura:

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_transport_read_bootstrap=$(mktemp -d "$HOME/ouf-onboarding-transport-read-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/5b91c2eb9302b8aaeb3a60cf45f26ce7b7951a1e/releases/read-onboarding-diagnostic-transport-stop-20261027.sh" \
    -o "$ouf_transport_read_bootstrap/run.sh"
  printf '%s  %s\n' '2138066add8c89fec929b448f7dc8cf1205c2daa9ac400b49dbfb69b10af12e6' "$ouf_transport_read_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_transport_read_bootstrap/run.sh"
  /usr/bin/bash "$ouf_transport_read_bootstrap/run.sh"
)
```

Restituire JSON finale e log. SeSTOP, conservare e non rilanciare. Dopo il risultato correggere soltanto il delta realmente dimostrato e qualificare fixture non identiche per profili storici/correnti; eventuale recupero richiederà review concreta nuova e budget cumulativi, nessun riuso/replay. Il comando APPLY più sotto è solo storia, NON rilanciarlo. M1 acquisito e FAILED Farmacie conservato.

# STOP VPS — confronto trasporto PostgreSQL, PRIMA della review; NON RILANCIARE

27 ottobre 2026. Ricevuto STOP_RECONCILE/EXACT_RETAINED_NATIVE_DATABASE_TRANSPORT_REQUIRED, Exit2/DeliveryExit2. Delivery /home/oufadmin/ouf-onboarding-diagnostic-apply-delivery.V220onbW; log /usr/local/lib/ouf-onboarding-diagnostic-update-687aefc7514bbe7b/operator.log e bootstrap.log nella delivery. Tutti21checksum/copia root0400 verificati dall'operatore. Il comando sotto è STORICO E CONSUMATO, non più un NEXT eseguibile.

Il guard aggrega schema del profilo storico, uguaglianza dell'intero binding Engine storico/corrente e tipo runtime binding. La causa precisa non è ancora osservata. Nel codice pinned è prima di Engine/review/autorità/chiavi/SQL/lifecycle; nessun consenso ricevuto. Zero dispatch è dedotto dall'ordine del codice, le claim conservate devono ancora essere riconciliate. Non chiamare questo STOP una deriva server o un errore PostgreSQL già provato. La fixture CI costruiva entrambi i binding dalla medesima cattura: non qualificava la combinazione storica reale.

[Ricevuta](../../evidence/onboarding-diagnostic-transport-stop-target-20261027.json). NEXT: qualificare ed eseguire UNA nuova lettura dei soli file conservati, con checksum/copia root/log; zero Engine/SQL/OAuth/configurazione/credenziali/chiavi. Non allentare il confronto, non sostituire hash, non resettare contatori o rilanciare il controller. M1 resta acquisito; causa Farmacie/M2 restano aperti. Nessun nuovo job/upload/acquisizione o riavvio di worker.

# Farmacie — primo APPLY diagnostico minimo

27 ottobre 2026, Europe/Rome. Questo checkpoint sostituisce il NEXT del [precedente handoff immagine/input](OUF_FARMACIE_DIAGNOSTIC_IMAGE_INPUTS_NEXT_20261026.md). I suoi riferimenti a prove, handoff precedenti e al checkpoint documentale iniziale rimangono validi. Non ripetere le preparazioni.

## Ultimo risultato effettivo VPS

`ONBOARDING_DIAGNOSTIC_IMAGE_INPUTS_PREPARED_NOT_AUTHORIZED`, complete=true, Exit0/DeliveryExit0. [Ricevuta conservata](../../evidence/onboarding-diagnostic-image-inputs-target-20261027.json).

- Capture consumato: `5909d1003e88231c1d41a799a12539127d27386f79a04ed345ad9d29eaaddb6d`.
- Preparazione immagine/input consumata: `c22586172070809d414d3654f3e002b7e1d84d749daae9b31dac8d1d14cbd0c0`.
- Input privati: `/etc/ouf/deploy-snapshots/onboarding-diagnostic-image-inputs-5909d1003e88231c-v1/execution-inputs.json`.
- Log: `/home/oufadmin/ouf-onboarding-diagnostic-image-delivery.ABE90yAu/bootstrap.log`.
- Una ZIP CI, un archivio native, due letture metadata; zero Engine/import/lifecycle/SQL/OAuth/chiavi/credenziali. Non era APPLY e non ha emesso autorità.

NON è stato ricevuto alcun risultato del nuovo APPLY, alcuna review umana o autorità runtime nuova. La chat non dispone di un executor root sul VPS. Il primo APPLY richiede il terminale dell'owner.

## Immagine scelta e prove

Si installa soltanto la diagnostica minima PR52. Source reviewed `a5ed8b05c264a8221783a6e323ba00117aed891d`; checkout CI testato `692277b1bf5def4a2b5b1ba4fb6770c16b136fb5`: unica differenza workflow CI, applicazione identica. Non installare il candidato M2 più ampio per ottenere la diagnosi.

Immagine native `sha256:074bd16ec8ebd98cbf1ee085af9767a5f7e322072a541e85bd37925002fa5df2`; archivio `87585bd8d50f8d955ef1abc26c43df52a481ac89df2ed2722ace3765aad1b071`, 441989120 byte. Tutti gli strati e le 35 risorse SQL sono stati confrontati con la prova originale e il source installed194b586. Nessun rebuild/relabel. [Custodia completa](../../evidence/onboarding-diagnostic-image-inputs-qualified-20261026.json).

Controller nuovo `e1597e00ca069a33700fe1132b0cdf9658deacd1`; wrapper delivery `15b2bef894b9c5e6434999e3cae69c803e236f63`, [release script](../../releases/apply-onboarding-diagnostic-update-20261027.sh). Manifesto di 21 fonti `687aefc7514bbe7b8c25a7e88cb5621d510d617529576dae46902ba762b1dccf`. Wrapper SHA256 `b99cbeafc72ce65c48e452365ddcb4e654ff380773d9259aa7a7a9a2955bf291`. I 21 blob sono stati verificati esatti sul commit pinned.

Il registro di qualificazione è [evidence/onboarding-diagnostic-apply-qualified-20261027.json](../../evidence/onboarding-diagnostic-apply-qualified-20261027.json). La qualificazione CI è distinta dal risultato VPS: workload HTTP e autorità nelle prove native sono sintetici, PostgreSQL e lifecycle Docker sono reali. Non è prova della causa Farmacie né dell'E2E M2.

## Perimetro della nuova review

Un solo Onboarding sostitutivo, stessa configurazione e User/Env/launch, mount e policy risorse esistenti, stesso nome pubblico, MAC/IP e porte conservati. Il vecchio viene fermato, scollegato e rinominato; resta fermo. Nessun rollback automatico. Registry, MCP, worker, due READ, Gateway e altri peer correnti sono vincolati e non modificabili dal lifecycle.

L'unico YAML owner esistente viene verificato in memoria contro il binding dei byte già classificati; nessun valore stampato e nessun altro file credenziali aperto. Non si interpreta l'errore di profiling via SQL.

La nuova review autorizza al massimo **quattro nuove sessioni SQL tecniche in sola lettura** sul PostgreSQL nativo vincolato. Il profilo V35 è usato soltanto come identità/trasporto: nessuna vecchia autorità o budget viene riusato. Prima di qualsiasi lifecycle occorrono assenza di profiling/readiness pendente, stesso job FAILED/tentativi5 e identiche 35 migrazioni. Fingerprint di nove tabelle e job devono rimanere identici prima dello stop, prima del nuovo avvio e alla fine. SQL non restituisce eccezioni, campioni o contenuti di dominio.

Massimi nuovi: 512 GET Engine, 10 scritture lifecycle/import incluse le sole quarantene previste, 1 import immagine, 96 readiness GET, 64 letture metadata configurazione, 1 lettura contenuto YAML owner, 4 SQL read-only, 1 quarantena del proprio candidato; zero Admin GET/PUT e zero letture di file credenziali di servizio. Tre firme installazione esistenti dopo consenso, massimo15 aperture chiave. Storico conservato separatamente, nessun reset.

Review concreta: 900 secondi con input canonico visibile/editabile, riga errata correggibile senza estendere la finestra; la sola ricezione di un incolla non conferma. Esecuzione: 900 secondi più30 di sola quarantena negativa del proprio candidato non committed. Watchdog effimero, stop solo candidato verificato. Se STOP o risposta ambigua, conservare prove e non rilanciare; il vecchio non viene riavviato automaticamente.

## Comando STORICO — eseguito in STOP, NON RILANCIARE

Il wrapper verifica i checksum come utente, copia tutte le fonti in root0400 e le riverifica come root. Il controller resta direttamente collegato al terminale; conserva il proprio log0600. Il bootstrap mantiene log e exit separati. Non passare APPROVO al wrapper, non usare pipeline per l'esecuzione interattiva.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_diag_bootstrap=$(mktemp -d "$HOME/ouf-onboarding-diagnostic-apply-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 65536 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/15b2bef894b9c5e6434999e3cae69c803e236f63/releases/apply-onboarding-diagnostic-update-20261027.sh" \
    -o "$ouf_diag_bootstrap/run.sh"
  printf '%s  %s\n' 'b99cbeafc72ce65c48e452365ddcb4e654ff380773d9259aa7a7a9a2955bf291' "$ouf_diag_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_diag_bootstrap/run.sh"
  /usr/bin/bash "$ouf_diag_bootstrap/run.sh"
)
```

Solo se approvi la review privata effettivamente mostrata, inserisci **la riga isolata `APPROVO <hash fresco>` prodotta dal controller e premi Invio**. Non copiare spiegazioni o hash storici. Non simulare il consenso. I test CI usano decisioni esclusivamente sintetiche e non trasferiscono alcuna autorizzazione al VPS.

Nuovo context unico: `/etc/ouf/deploy-snapshots/onboarding-diagnostic-update-c22586172070809d-v1`. Codice protetto/log: `/usr/local/lib/ouf-onboarding-diagnostic-update-687aefc7514bbe7b/operator.log`. Delivery log nel nuovo `ouf-onboarding-diagnostic-apply-delivery.*` sotto HOME.

Atteso, soltanto dopo prove reali: `ONBOARDING_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED`, complete=true e Exit0/DeliveryExit0, quattro sessioni readonly, stato operativo invariato e readiness provata. Non presumere l'esito prima del JSON finale.

## Dopo il risultato

Se STOP: prima riconciliare le prove esatte, senza replay, nuovo upload/job, reset o ripristino automatico. Gli effetti ambigui restano CLAIMED.

Se riuscito: registrare JSON e percorsi log su GitHub, poi ottenere la diagnosi minimizzata dello stesso asset `9c502da5-b5d8-405e-b3f5-60eb31ecb513` / job `677480c8-3d10-44fd-9dad-f72ddeed20a4` tramite owner/API governata. Handoff upload esistente `4da5410e-98de-472c-89b6-bc1cdae8ecf1`. Policy54 è scaduta: questa manutenzione non la rinnova e non autorizza letture di dominio tramite SQL. Nessun rinnovo/grant automatico; serve un mandato READ finito valido prima della lettura applicativa.

M1/G4 resta acquisito sul caso conservato; M2/G5/G6/G7 aperti. Farmacie resta FAILED/causa non osservata finché la lettura owner non la dimostra. CSV locale valido non prova byte server o parser Java. D2/D3 composti in CI restano separati/non installati; D4–D7 non accettati. Nessuna nuova stima oraria inventata, terza acquisizione Teatri, fonte/attivazione, merge o release acceptance. Supervisor dopo E2E completo. Lavorare sequenzialmente, senza subagenti o automazioni.

## Continuità del lavoro già riuscito — mandato owner del 27 ottobre

L'E2E M1 percorso manualmente è la baseline obbligatoria. Un criterio finale M2 aperto non rende mancanti i motori o i passaggi già dimostrati. Prima di introdurre lavoro, recuperare per ogni passo commit/artefatto, contratto, prova CI e ricevuta target esistente; confrontarli con la generazione selezionata/installata e correggere soltanto il delta osservato. Non chiedere un nuovo ciclo manuale completo per ricostruire prove già conservate.

| Passaggio | Prova da riusare | Implicazione operativa |
| --- | --- | --- |
| Acquisizione, ACK, intake, materializzazione, lineage/proprietà | [M1 target](../../evidence/csv-m1-f5-f6-owner-verification-20261026.json): 26 join, 13 identità, 20 proprietà, 8 Cinema preservati | M1/G4 resta PASS; nessuna terza Teatri o ripetizione del ciclo per riscoprire queste prove |
| Upload Farmacie | [STAGED e job persistente](../../evidence/new-csv-staged-profile-retry-wait-20261026.json), poi [FAILED conservato](../../evidence/new-csv-profile-terminal-failure-20261026.json) | Il caricamento è già riuscito; non ripetere upload/picker/job per aggirare il problema successivo |
| Typed, proprietà e ripresa ASSETS/LATEST | [Audit](../OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md) e [composizione](../../evidence/csv-m2-typed-recovery-composition-20261026.json) | Recuperare e comporre il codice esistente; niente nuovo parser o motore UDP equivalente |
| Discovery job e browser | [Checkpoint successivo](../../evidence/csv-m2-job-discovery-input-capture-20261026.json): Onboarding976c478d, 296 test modulo, browser4 PASS/0skip | La voce browser pending della composizione precedente è storica; il piano corrente è corretto. Codice qualificato non implica installazione |

Un 403 inatteso richiede identificare il punto e il componente che lo emette e confrontare il percorso già riuscito: account/client, token/scopes, validità della policy, rotta e owner selezionato. Non attribuirlo al parser o proporre nuovi grant alla cieca. Un'autorità scaduta resta scaduta e va gestita nel percorso guidato, preservando il lavoro durevole. Non è stata osservata una nuova risposta403 in questa registrazione e non viene assegnata una causa non provata al FAILED Farmacie.

Il risultato di prodotto richiesto è caricare un file e proseguire in modo autoguidato fino a UDP e search, riusando i componenti già pronti. Terminale e copia manuale degli identificativi non sono il normale percorso CSV. Questa precisazione non esegue o riavvia APPLY, non rinnova autorizzazioni e non cambia il comando pinned sopra.

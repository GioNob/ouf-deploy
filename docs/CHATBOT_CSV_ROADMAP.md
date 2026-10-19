## Current checkpoint — Ingestion owner rollout preparation; functional4/6

> **Checkpoint aggiornato — preparazione input COMPLETATA (z048j_zr), tecniche8/8 e funzionali4/6.** Ricevuta target: [ingestion-read-owner-input-target-20261019.json](../evidence/ingestion-read-owner-input-target-20261019.json). Input SHA256 `7b5d811ba31ab5899f969759eb5140c586785b1a17bdfe9287b6666ba788b314`; immagine51a514d8 già conservata e non importata. **Non rilanciare la preparazione input né alcun apply/readback completato.** Manca il riferimento owner dedicato e l'ambiente Gateway richiede una nuova variabile. Il delta comprende quindi un riferimento FILES, cinque binding Ingestion e un mount in sola lettura, due aggiornamenti container (Gateway con immagine invariata) e due funzioni Lua; le altre80rotte restano identiche. Il compilatore finito genera un DRAFT privato e verifica immagine/rootfs/JAR e uguaglianza SQL con il JAR installato; nessun login, import, file attivo o effetto runtime. Qualifica root CI39308998478/job118253412183:14test PASS. **Questa CI non qualifica un esecutore di rollout e il confronto SQL non prova l'ammissione DB.** Nuovi consensi HUMAN/THS, ACTIVE/ETag corrente, ammissione DB e qualifica esecutore restano aperti. Budget272/finestra7200s sono soltanto una proposta non autorizzata, con259 consumati conservati e vecchia scadenza1792436155 mai estesa. Catalogo corrente letto con ouf-admin: ruolo admin nominale e quattro capability installation presenti. Procedura corrente: [INGESTION_READ_OWNER_DRAFT_PREPARATION_20261019.md](../releases/INGESTION_READ_OWNER_DRAFT_PREPARATION_20261019.md).


> **Correzione auth Ingestion qualificata, 19 ottobre 2026:** JAR target58199f4b letto; i due hash IAM68edae63/818f36a6 coincidono con il build sorgente. La precisa catena401 live non è ancora provata, ma manca un contratto autenticato per trasformare la delega Gateway in principal SDK. Implementata ricevuta owner distinta, vincolata a metodo/percorso/capability/body/identità/audit/TTL30s; 18test Java con Lua reale e zero skip PASS. DraftGatewayPR81/source6bcb2890, IngestionPR43/source663faa03. Immagine candidata51a514d8, CI39304976681 e artifact12214420297, scanner HIGH/CRITICAL PASS e0cambi migrazioni. **Non ancora installata.** La successiva preparazione input è ora COMPLETATA in z048j_zr (ricevuta e checkpoint più recenti sopra); non rilanciarla. Prima del rollout servono delta concreto e nuove decisioni native: il precedente APPROVO copriva solo i2PUT conclusi. Non riusare né rinnovare automaticamente quella autorità/finestra. Ultimo259/264, scadenza precedente20:55:55 italiana; tecniche8/8,funzionali4/6.


> **Diagnosi401, lettura ambiente completata:** capsula w8nfc1ko SHA2564b21a573/closure1191c381 verificata, generazioni correnti verificate. Variabili OUF_ING_IAM_ENABLED/ISSUER/AUDIENCE non abilitate/configurate; il conflitto bearer ipotizzato non è provato. Nessun OAuth o effetto. Non modificare rotte o IAM per deduzione da questi soli flag. La successiva lettura JAR /app/app.jar è COMPLETATA: vedere la qualifica auth più recente; non ripetere questo storico come fase operativa. Classi sul disco non provano da sole le classi caricate dal JVM; causa401 e accettazione restano aperte. Tecniche8/8,funzionali4/6,ultimo259/264. Ricevuta completa: evidence/ingestion401-auth-contract-target-20261019.json.


> **TARGET COMPLETATO — 19 ottobre 2026, contesto w8nfc1ko:** riconciliazione journal e2PUT Gateway complete; owner6/gen6, proiezione10b378c05 e80altre rotte conservati. Mappa82rotte SHA256ed619aa9415b2e70f61689c3830b3fc89135bc9ab72fc90f24daeba1e7bed8c7. Vecchio journal7x21g1fg riconciliato versione5, scadenza1792429299 preservata.255→259/264, scadenzaHUMAN20:55:55 italiana invariata. **Non rilanciare alcun launcher di applicazione/riconciliazione completato.** Letture correnti dal clientouf-admin: MCP HEALTHY; fonte APPROVED/lock3 e attivazione NOT_STARTED; Ingestion status/history401. Tecniche8/8, funzionali4/6. Il401 è un incidente distinto: nessuna nuova autorità o mutazione è implicata; proseguire con sola diagnosi del contratto auth. Ricevute: evidence/installation-route-reconciliation-target-20261019.json e evidence/installation-route-post-client-read-20261019.json.


> **Consegna corretta dopo riconciliazione STOP, 19 ottobre 2026:** target219 autenticato, HUMAN SHA256305c7804b084b02f0bf7d6c1521c3c5a4f8e7f4e2fb0a15e27f5886a2a685dcc; nuova claim assente. Il guard conserva il ramo MCP storico. La nuova preparazione controlla l'intera sorgente esatta, indipendentemente dal formato ast.dump di Python3.13. Sorgente `6e36d6f5faa8c0c8e129aac7d843fcf9e7d535e4`, consegna `01c7b8e0e4b763b0b5b3cb64e86c131bd6c234cb`; 18+3 test CI PASS. La consegna precedente92c0c78 resta ritirata. Budget264 proposto,255 consumati conservati, consensi nativi distinti ancora necessari; avvio prima20:35:55, scadenza20:55:55 italiane invariata. Owner6/gen6 e rename già completati non si ripetono. Tecniche8/8, funzionali4/6; target E2E non ancora provato.


> **STOP target — 19 ottobre 2026:** la consegna `92c0c78c6b5dcb4dcfd7f923df1906988c235127` si è fermata in PREPARATION con `EXACT_FROZEN256_PREDECESSOR_GUARD_REQUIRED`. Il comando operativo sotto è ritirato: **non rilanciarlo**. Nessun consenso budget264 è stato raccolto; ultimo consumo riferito255/256. Il test usava un guard esportato da una capsula precedente e non provava il guard della capsula219 attuale. Prossima azione: sola lettura autenticata della sorgente e presenza della claim, senza credenziali, OAuth o mutazioni. Owner6/gen6 e file pubblicato non vanno ripetuti; journal resta da riconciliare. Tecniche8/8, funzionali4/6.


### Ultimo stato: token scaduto255/256; proposta264 e continuazione completa qualificata

La lettura target `ouf.installation-binding-continuation-readiness.v1` prova sessione READY **255/256**, accessExpiresAt **1792429331**, token scaduto; finestra ancora aperta fino **1792436155 =20:55:55 Europe/Rome del19ottobre2026**. Rimane1tentativo mentre REFRESH+USERINFO richiedono almeno2: **non avviare rinnovo parziale**, non spendere il256esimo come prova e non azzerare contatori. Restano provati proiezione attiva10b378... già pubblicata, stage CLAIMED/version3 del7x21g1fg e zero dispatch Gateway da quell'azione; owner46iexg9c completato6/generazione6. Nessuna nuova autorità o budget concessi dalla diagnosi. Ricevuta completa in `evidence/installation-binding-continuation-readiness-target-20261019.json`.

**Pronto ma NON eseguito sul target:** nuovo pacchetto chiuso226 moduli `tools/installation_route_reconcile`, source **8ff69df5a19cd161ac185b2b15729e821bba2383**, consegna11file **92c0c78c6b5dcb4dcfd7f923df1906988c235127**, launcher SHA256 **80dd9d9f7e5e78805a298b15fe02c0ac35d73a2f3a8501981aa7e1d03c54839f**. Script/istruzioni in `releases/INSTALLATION_ROUTE_RECONCILIATION_20261019.md`. Non usare launcher intermedi9080204f/d34f... o la vecchia azione219; la sola consegna qui indicata include gli ultimi controlli prima di OAuth.

Prima del login vengono controllati closure/eseguibili/stdlib, storia/pacchetto219 e journal/piani/review/claim vincolati, custodia/proiezione, statoH255 corrente, orizzonte20min dei ruoli pubblici, cinque generazioni container e rotte82 correnti. Sono letture; nessun budget OAuth speso. Il nuovo pacchetto è preparabile solo con **almeno1200s residui**, quindi avvio **prima delle20:35:55 italiane**. Il TTL non viene esteso per attendere.

Primo gate **`APPROVO BUDGET264 <hash>`**: proposta di massimo cumulativo **256→264** (+8 al limite,9richieste residue da255), storico255 conservato, scadenza wall/monotona immutate e11scope invariati. Questo è un NUOVO profilo v5 esplicito, **humanSourceChanged=true nel nuovo pacchetto**: aggiunge un guard ristretto264 e blocca I/O OAuth dalle sessioni predecessore256; il guard congelato precedente resta byte/predicato di identità del predecessore, verificato via AST del corpo. Non fingere che il validatore sia rimasto immutato. Vecchi file/sorgenti/capsule/journalH non riscritti; il successore ha un nuovo journal che parte255. Una sola claim di successore. Nessun vecchio access/refresh/device usato, nessun rinnovo automatico.

Dopo il primo consenso si fa un login device FRESCO: URL/codice nel terminale e pausa fuori dal lock; **`LOGIN COMPLETATO <hash>`** solo dopo successo nel browser, prima del primo token poll. Verifica issuer/scopes/subject/userinfo tramite codice HUMAN originale; caso nominale255→259. Pending/transienti restano entro264 e scadenza originale. Negazione/esaurimento/esito ambiguo/STOP conservano stato e fermano; non rilanciare. Il primo gate non autorizza journal/Gateway.

Secondo gate **`APPROVO <hash>`**: nuova autorità210s, due ruoli firmati, kind `INSTALLATION_ROUTE_RECONCILIATION`, solo2PUT Gateway e **2transizioni journal predecessore**. Le letture owner/profile/rotte sono ricontrollate dopo login e prima/dopo ogni stage; profilo pubblicato pin anche su metadata/inode, zero rename/write. Si riconcilia CLAIMED→APPLIED del rename già provato, poi nuovi claim durevoli prima di ciascuno dei2PUT, con map82 esatta/80altre rotte e sicurezza invariati. Solo dopo i readback e i nuovi stage APPLIED si riconcilia completamento storico con riferimenti alla NUOVA autorità/journal; versione predecessore3→4→5, expiresAt vecchio conservato e mai riarmato. Non vengono inventati effetti: i nuovi PUT hanno prova nel nuovo journal prima del riscontro storico. Una risposta ambigua resta CLAIMED e non viene rispedita.

Zero POST/export owner, zero pubblicazione proiezione, container/DB/migrazioni/IAM/grant/metadati MCP/fonte/job. Endpoint owner è chiuso in modalità GET-only; scope e stage nuovi non includono le vecchie azioni. Questa è amministrazione finita distinta, non approvazione fonte/semantica via MCP; futuri gate di dominio restano HUMAN/THS.

**20test CI passati sulla revisione finale:**17 run39296553970/job118210477015 (7vere firme/journal/2PUT e riconciliazione,8budget/login/guard,2preparazione isolata),3consegna run39296750272/job118211142285 (gh portabile,11hash, tamper/assenza client prima sudo e root recheck). Fonti/provider/terminale delle fixture non provano OAuth/owner/Gateway live; dettagli in `evidence/installation-route-reconciliation-qualification-20261019.json`.

Output pubblici attesi `OUF_INSTALLATION_ROUTE_PREPARED`, `OUF_INSTALLATION_ROUTE_HUMAN`, `OUF_INSTALLATION_ROUTE_RESULT` oppure STOP e contesto. Conservare il processo fino all'esito; niente replay dopo preparazione/STOP/interruzione. Nel caso di futura diagnosi scegliere la sessione nuova da login-window-receipt/execution-plan, non il binding255 predecessore nel case sigillato; il bootstrap conserva il binding esplicito corrente in memoria per lo STOP.

Tecniche **8/8**, funzionali **4/6**. Neppure un esito amministrativo completo prova profilo nativo MCP finale, lettura chat fresca, risoluzione completa503, fonte attiva, seconda acquisizione SAMECSV/provenienza/ACK o release acceptance. Dopo la ricevuta positiva seguono tool/capability readback con ouf-admin e gate di dominio per profilo governato/tappe5–6; nessuna ripetizione di uow4n8lp/azxw328z/srz6__wf/hnfn0zwg/owner46iexg9c.

---

### Stato target provato: proiezione nuova, journal CLAIMED, zero dispatch Gateway

La lettura target `ouf.installation-binding-custody-stop-read.v1` è completata: file attivo **APPROVED_NEW_EXPORT**, SHA256 **10b378c05f6ce38d46b8ba9d66a0fa1f9d5ceb0383975ca6c43ba604e9bf599d**, custodia approvata valida; il vecchio predicato root-only fallisce sull'antenato0750/UID1000. Scope owner46iexg9c RECOVERED/version13/6stageAPPLIED, ACTIVE6/generazione6 conservati come file (non riletti dal backend). Scope7x21g1fg OPEN/version3/nextStage1: VERIFY_INPUTS APPLIED, PUBLISH_ACTIVE_PROJECTION CLAIMED; **zero claim dei due stage Gateway prova nessun dispatch Gateway da questa azione**. Rotte live non interrogate. Non ripetere owner/create/validate/activate/export o rename della proiezione già provata; vecchie autorità scadute non vengono riarmate.

**Correzione nel repository, non distribuita sul VPS:** `native.py` usa ora `approved_projection_bytes` per readback dopo rename e guard successivi. Riusa lo stesso `private_config` e verifica SHA256/byte attesi; non cambia proprietari, permessi o guard del lettore privato per altri artefatti. Source **8e10f19389c9c3522717ecf158f021f20fd47104**, native SHA256 **40d1f6ea6fac915badbc0f4ecfb919a980d6e3c434533e532b969d38548649c3**. **27testCI passati**:14 run39292201803/job118195461013 (8custody read+6regressione publisher/HUMAN, antenato1000 reale),13 run39292202554/job118195465099 (firme2ruoli/journal/HTTPS owner). Non è una prova di applicazione di nuovo runtime sul target.

Per scegliere la continuazione serve lo stato HUMAN attuale, che la diagnosi precedente NON leggeva. Ultimo contatore255/256, finestra consentita fino20:55:55 Europe/Rome; questa scadenza NON prova che l'access token sia valido. Il rinnovo READY richiede almeno2richieste (REFRESH e USERINFO), perciò un solo tentativo residuo non deve avviare un rinnovo parziale. Non aumentare256 né azzerare contatori sulla base di questa diagnosi; un eventuale nuovo profilo finito richiede revisione/consenso HUMAN espliciti e conservazione della storia.

Lettura pronta **non ancora eseguita**: `scripts/read-installation-binding-continuation-readiness.py`, stesso source8e10..., SHA256 **df7bbfa4859462f8c8bf0de9e8b5ec602282e261079ae99538749ca85ec7d9bb**. Ricontrolla pacchetto219, custodia/proiezione e journal; legge SOLO il journal della sessione esatta selezionata dal piano/review già vincolati, verifica identità del binding, boot/clock, review c0f749... e budget255–256. Pubblica solo stato/counter/scadenze e fattibilità registrata. Nessun bearer, chiave, authority file, OAuth, HTTP/Engine, nuovo login, refresh, claim o scrittura; `currentBearerOrSignatureVerificationPerformed=false`. L'eventuale margine temporale registrato non sostituisce `HumanSession.current` e validazione del backend prima della futura autorità.

Prossima azione di modifica: nuova autorità finita distinta per riconciliare lo stage già pubblicato e solo2PUT Gateway, dopo letture correnti owner/rotte/custodia e verifica HUMAN valida. Non è ancora preparata o autorizzata dalla sola diagnosi. Se le credenziali non permettono il seguito entro il budget esistente, prima si prepara una revisione HUMAN del profilo/budget; nessuna richiesta di prova consuma l'ultimo tentativo. Tecniche **8/8**, funzionali **4/6**; profilo governato e tappe5–6 restano aperti.

Ricevuta target completa in `evidence/installation-binding-custody-stop-target-read-20261019.json`; nuova qualifica in `evidence/installation-binding-custody-fix-readiness-qualification-20261019.json`. Consultati Matrix1.7§1 e PET Onboarding/Configuration/THS1.6§§103–106 (THS-A02/A08/A09) per mantenere separati diagnosi, decisione HUMAN e owner execution. Nessun agente o automazione pianificata.

---

### Binding owner attivato; STOP custodia durante il secondo ambito — nessun replay

Ricevute target19ottobre2026: login HUMAN251→255, stesso massimo256, nuova finestra esplicitamente consentita fino alle **20:55:55 Europe/Rome** (`1792436155`). La disponibilità futura del token non è provata da tale scadenza: non avviare refresh/login impliciti né cambiare budget. Owner scope46iexg9c completato: **ACTIVE revisione6/generazione6**, checksum **ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98**;3POST e1export autorevole **10b378c05f6ce38d46b8ba9d66a0fa1f9d5ceb0383975ca6c43ba604e9bf599d**. Owner NON va riattivato/ripetuto.

Secondo scope7x21g1fg: APPROVO registrato, authority/issuance/recovery presenti, update-result assente; STOP `PRIVATE_ROOT_ANCESTRY_REQUIRED`. Il lettore privato `baseline.read` richiede antenati root mentre il Gateway ha già custodia approvata per `/opt/ouf` uid/gid1000/mode0750 e sottodirectory installationroot0700/file0600. **Difetto del codice di readback:** `native.publish_active_projection` esegue rename+fsync PRIMA di usare quel lettore; anche `guard_current` lo usa dopo la pubblicazione. Quindi la proiezione potrebbe già essere nuova mentre lo stage rimane CLAIMED. L'output da solo NON prova zero effetti nel secondo scope né lo stato corrente delle rotte. Nessun chown/chmod o replay per superare il guard.

Diagnosi pronta, **non ancora eseguita sul VPS**: `scripts/read-installation-binding-custody-stop.py`, source **0a6438cad877dd356e0cc512c9883e52c5c37583**, SHA256 **c159ee9c93cb5ccd0e6404542296976e200f9ea218df53c53ea3f0e39d306ff4**. **8test CI passati**, run39290858181/job118190816178, con antenato UID/GID1000 reale.8test locali passati con virtualizzazione proprietario limitata al solo inode fixture (filesystem locale rifiuta chown nonzero). Verifica pacchetto219 de440e..., closure2fb31d..., entrambi i piani/review/journal/claim e completamento owner; importa via AST solo i cinque nodi dei lettori di custodia dal Gateway autenticato, senza main/runtime/autorità. Confronta file attivo con vecchia proiezione conservata e export nuovo, segnala CLAIMED+nuovi byte e presenza di claim Gateway. Nessuna rete, Engine, OAuth, journal o altra scrittura; non apre credenziali, chiavi o authority.

Output atteso `ouf.installation-binding-custody-stop-read.v1`. La diagnosi distingue `APPROVED_NEW_EXPORT`, `RETAINED_OLD_PROJECTION`, `OTHER_CUSTODIED_BYTES`; non dichiara risoluzione/release. Dopo il read si prepara una riconciliazione distinta con nuova autorità finita, controllo owner/rotte correnti, senza ripetere owner/post/export completati o una pubblicazione già provata. Nessuna modifica ai permessi o all'autorità consumata; eventuali effetti nuovi restano soggetti ai gate HUMAN/THS. Tecniche **8/8**, funzionali **4/6**; profilo governato, fonte e tappe5–6 ancora aperti.

Ricevute pubbliche in `evidence/installation-binding-owner-completed-20261019.json` e `evidence/installation-binding-projection-custody-stop-20261019.json`; nessun codice device/credential archiviato. Qualifica in `evidence/installation-binding-custody-stop-qualification-20261019.json`. Le CI del launcher precedente39280839526 e39280897367 risultano ora entrambe SUCCESS: distinguere tale qualifica dal difetto di custodia rilevato sul target.

---

### Ultimo checkpoint: CAS fermato senza OAuth; azione completa con tre consensi nativi

**Stato target provato: tecniche8/8, funzionali4/6.** Onboarding owner atomico hnfn0zwg completato e sano; non ripeterne update o readback. L'ultimo piano CAS si è fermato in `CHECK_COMPLETED_OWNER_HUMAN_NO_REFRESH`, `CURRENT_HUMAN_SESSION_REFRESH_PENDING`: sessione READY251/256, zero OAuth, nessuna autorità; il piano target non è stato completato. Ricevuta completa in `evidence/installation-binding-cas-plan-target-stop-20261019.json`.

È preparata l'azione distinta219 moduli, source **9600d850e5d4b4b42004e68028a5aa6e49c20d35**, delivery **cb66752e13c5e345bc68a929a31285f6cc417f7e**, launcher `scripts/launch-installation-binding-apply-20261019.sh`, SHA256 **d0a647bbaf538b2371b1566a05031a8efada5f2c044461db8b00486a26caf717**. **NON ancora eseguita sul VPS.** Non usare delivery4105a861/vecchi launcher: mantenevano la vecchia finestra ed erano precedenti alla nuova revisione esplicita.

La finestra precedente scade il19ottobre2026 alle17:54:19 Europe/Rome. Il nuovo percorso richiede il consenso terminale **`RIAPRO LOGIN <hash>`** per UNA NUOVA finestra7200s dal consenso. Il contatore riparte dallo storico **251/256**, con soli5residui, budgetResetfalse: nessun reset, credenziale/device/refresh precedente riutilizzato o rinnovo automatico. Il validatore HUMAN resta byte-identico; si usa il suo schema già supportato `ouf.human-explicit-test-continuation-review.v3`. Dopo device URL/codice, la pausa rilascia il lock d'invocazione; **`LOGIN COMPLETATO <hash>`** va scritto solo dopo successo nel browser e precede il primo polling token. Provider rifiuto/esaurimento/STOP richiedono riconciliazione. Nessun login è stato effettuato da questa preparazione.

Dopo verifica token/scopes/userinfo, nuove letture correnti controllano5generazioni container, metadata0440, mappa82rotte, DNS owner alias e ACTIVE/revisione/ACTIVE con ETag forte. Il candidato resta quello del piano6bebb5...: aggiunge un solo binding Ingestion, checksumded675.... Gate owner **`APPROVO <hash>`**: massimo3POST(create/validate/activate If-Match) e1export auditato autorevole, scope210s con due ruoli e firme reali. Gate successivo distinto **`APPROVO <hash>`**:1pubblicazione atomica/CAS della proiezione autorevole e2PUT Gateway, solo host upstream status/history;80altre rotte e porte/metodi/OIDC/delegazione/plugin invariati. Journal durevole registra CLAIMED prima di ogni effetto; esito ambiguo non viene rispedito. Nessun rollback automatico.

Il risultato completo proverebbe binding, proiezione attiva e2rotte, **non** profilo nativo MCP finale, sorgente attiva, lettura chat fresca o acceptance. Nessun container lifecycle, migrazione/SQL manuale, grant/IAM, retry job o metadata MCP. Tappe5–6 ancora aperte; seguiranno prove governate sul client fresco e percorso funzionale secondo PET e gate HUMAN/THS.

Qualifica:13test CI passati sulla precedente revisione4224a093 (run39277961487), comprendono HTTPS owner If-Match/export, vere firme2ruoli/journal, scope distinti, publisher CAS e login. Revisione nuova:6test login locali (incluso predecessore scaduto),2preparazione isolata219,3delivery e3controlli del gate CI passati; CI nuova run39280839526 e delivery39280897367 inizialmente in coda, il comando qualificato verifica entrambi gli esiti e i commit esatti prima di sudo/download/claim/login OUF. Se non verdi, termina WAIT_CI senza preparare alcuna azione. Comando e limiti in `releases/INSTALLATION_BINDING_NATIVE_EXECUTION_20261019.md`. I test locali simulano provider/terminale e bootID (assente nel filesystem locale), non provano autenticazione o apply sul target. Dettagli in `evidence/installation-binding-native-qualification-20261019.json`.

Output da raccogliere: `OUF_INSTALLATION_BINDING_PREPARED`, `OUF_INSTALLATION_BINDING_HUMAN`, `OUF_INSTALLATION_BINDING_OWNER_RESULT`, `OUF_INSTALLATION_BINDING_APPLY_RESULT` oppure STOP con contesto/fase. **Un solo lancio: dopo STOP/interruzione conservare artefatti, non rilanciare, non azzerare budget.** Installazioneuow4n8lp, Gatewayazxw328z, MCPsrz6__wf e ownerhnfn0zwg restano conclusi.

---

### Piano CAS distinto qualificato — tre GET owner, zero OAuth

Pronto `scripts/prepare-installation-binding-cas-plan.py`, source **49714c8dd20cc501154ee65205ac6db40e1d3c21**, SHA256 **c578e5eae5a8d037f04e934a763320ce7026609eebca3a162e28766f78d0c1cd**. **7 test passati** run **39274642879**, job **118135653181**: ETag/generazione forte, rifiuto stale/ABA e candidato diverso, tre soli GET con ETag conservato e nessun replay dopo errore; assenza nel codice di login/refresh/emissione autorità/mutazioni owner. Qualifica in `evidence/installation-binding-cas-plan-qualification-20261019.json`.

Lettura storico owner completa vincolata al checksum **704c8708d668161f0ddea45b997e493ef53dabd48c9db08128362223a33ba46c**, pacchetto213 sorgente bcd33... e entry hash1ce40..., journal RECOVERED29, scope/review/decisione/nuova sessione. Importa esclusivamente i primitivi dal loader213 verificato senza chiamare main storici; verifica gli eseguibili e stdlib conservati. Tre inspect Engine correnti Onboarding/Ingestion/Gateway, verifica proiezione privata conservata; poi massimo tre GET owner ACTIVE/revisione/ACTIVE,45s. Piano conserva lo stesso candidato ded675... e aggiunge il vero ETag/generazione in un nuovo artefatto privato con claim O_EXCL. Non esegue una prova live di scrittura.

La verifica HUMAN avviene prima di HTTP/Engine e non avvia refresh/worker. Se access non è già corrente con almeno90s residui, **STOP senza richieste OAuth**, conservando il budget osservato. Non è una nuova autorizzazione login. Lo stato251/256 della ricevuta precedente non prova token ancora valido al momento di lancio. Zero mutazioni owner, export, proiezioni attive, Gateway, DB o container; nessuna autorità. Le sole scritture previste sono claim e nuovi artefatti privati di pianificazione dopo esito dei controlli. DNS e route map rimangono prove conservate, da rileggere nel futuro gate di apply.

Piano target non ancora eseguito/provato. Output atteso `OUF_INSTALLATION_BINDING_CAS_PLAN_RESULT`, oppure STOP senza rilancio. Aggiornamento owner hnfn0zwg e precedenti installazioni/readback rimangono completati e non vengono ripetuti. Tecniche8/8,funzionali4/6; binding, fonte e acceptance ancora non provati.

---


### Owner Onboarding aggiornato — readback completato;251/256; binding ancora da applicare

Ricevuta utente integrale in `evidence/installation-owner-completed-readback-20261019.json`: **ONBOARDING_OWNER_UPDATE_READBACK_COMPLETE**, contesto **hnfn0zwg**, sorgente **b0f5e3dacbe59ebf87e22dd6af2575e41249f51d**, immagine runtime **sha256:c124a832a1f9f07967a8f3ef9ba9692610ab5c97aa4719e614867f44e6aa63ae**, container **0165a7d260a9c146101ac1471c843b1300587c579a18e99ea0c3a78cadcb0aae**, PID **335586**, start **2026-10-19T14:55:21.10058135Z**. Health **200**, readinessAttempts1, journalVersion29/complete/applicationReady. La ripetizione degli stessi messaggi WAIT non è una seconda mutazione. Nessuna migrazione, Gateway PUT, grant, job, metadato pubblico, attivazione fonte o accettazione. Rotte82/mapd5a e binding delle altre applicazioni conservati. **Aggiornamento completato: non rilanciare.**

L'API owner con precondizione atomica è installata; **non è stata fatta una prova live di scrittura**. Il piano d'installazione6bebb5d1 resta non applicato, ACTIVE previsto5. Counter HUMAN riportato **251/256**, cinque tentativi residui; finestra invariata fino alle **17:54:19 Europe/Rome**. Non dedurre una nuova scadenza access dal solo risultato. La sessione autenticata da selezionare per le prossime letture è quella in `execution-plan.json.humanBinding`, confermata dalla login-window-receipt; il case pre-login resta legato al predecessore BLOCKED244 e non va riutilizzato come selezione corrente.

Prossima preparazione distinta: rileggere ACTIVE/revisione5/ACTIVE dall'owner nuovo, verificare ETag forte revisione/checksum/generazione identico prima/dopo e conservare lo stesso candidato ded675... per futura review nativa. Verificare le generazioni correnti Onboarding/Ingestion/Gateway senza ripetere l'installazione/readback. Nessun refresh, login, richiesta OAuth, export o mutazione owner/Gateway/proiezione. Richiede un access token già corrente con90s di margine; altrimenti STOP conservando251/256 e senza tentare il refresh fallito. La futura applicazione con If-Match, pubblicazione della proiezione e due rotte avrà gate distinto, verifica DNS/Gateway live e fencing nativo. Tecniche **8/8**, funzionali **4/6**; profilo governato e tappe5–6 aperti.

PET consultati per questa decisione: Matrix1.7§1; Onboarding/Configurazione/THS1.6§§103–106,THS-A02/A08/A09. L'ETag va acquisito dal nuovo owner: non inventare la generazione dal precedente piano. Nessuna rivendicazione di conformità completa, acceptance o risoluzione end-to-end503.

---


### Prossima azione qualificata — riautenticazione244 nella stessa finestra, poi gate owner distinto

Il reader target ha confermato **complete/readOnly**, nessuna autorità o journal owner, nessun dispatch Onboarding da questa azione, nessun successore; HUMAN **BLOCKED244/256** dopo REFRESH, access registrato scaduto, **12** tentativi residui e finestra wall/monotonic ancora aperta fino alle **17:54:19 Europe/Rome**. Zero richieste OAuth/owner/Engine, scritture, bearer/key aperti o sorgenti owner eseguiti. Causa specifica issuer **non provata**. La ricevuta integrale è in `evidence/installation-owner-same-window-reauth244-qualified-checkpoint-20261019.json`.

Qualificata una capsula distinta da **213 moduli**, sorgente **bcd33c71c7a906ec867c7ab2ccac40e4545a4f31**: cambia soltanto il modulo entrypoint, fornito dal file autenticato `tools/installation_owner_reauthentication/entry.py` e sigillato sotto il nome chiuso `tools.installation_owner_update.entry`. **Tutti gli altri212moduli, incluso HUMAN, sono byte identici** al package fermato; loader, bootstrap, codice owner e guard restano invariati. Test AST verificano identiche le funzioni current_human/compile_current/main owner (solo main rinominato owner_main). Riutilizza prove e immagine già preparate: nessuna nuova preparazione immagine o rebuild, né esecuzione di reader/main storici.

Primo gate sul VPS: **APPROVO RIAUTENTICAZIONE + hash** autorizza un solo nuovo device login nello stesso issuer/soggetto/tenant/client/11scope; il provider può negare. NON riusa access/refresh/device credential precedenti, NON estende o riapre la finestra e NON azzera244/256. Il successore mantiene `binding.createdAt/expiresAt` come date della **finestra originaria**, il suo identico `governedWindowRenewal` v4 e la deadline monotonic originaria; il consenso nuovo ha timestamp corrente ed è registrato **separatamente** in login-review/login-decision/sameWindowReauthentication. Nessuna data di approvazione precedente viene riscritta o attribuita al nuovo consenso. Il precedente journal resta identico; un claim persistente recinta ogni secondo avvio.

Solo dopo login verificato, stato corrente e margine budget (massimo252tentativi prima dell'ammissione owner) viene letto il piano corrente. Secondo gate **APPROVO + hash** e firme native dei due ruoli autorizzano esclusivamente l'aggiornamento Onboarding già qualificato, massimo900s, con almeno20min residui nella finestra. Il login non emette autorità infrastrutturale. Nessun profilo creato/attivato/esportato, proiezione sostituita, Gateway PUT, grant/IAM, fonte o acquisizione. Source b0f5 e immagine runtime c124 rimangono quelle già verificate. Dopo STOP/interruzione nessun rilancio: riconciliare la capsula selezionata e il relativo claim.

Qualifica **11 test** passati run **39272635912**, job **118128669999**: vero device flow con guard congelato, conservazione date/receipt/deadline/budget, consenso negato, rifiuto issuer durevole, budget consumato dai poll, deriva concorrente e preparazione in subprocess isolato con tutti i file storici intatti e claim one-use. Delivery **3 test** passati run **39272792659**, job **118129225377**: client portable gh autenticato, due pin esatti, sostituzione/mancanza client bloccate prima di sudo/exec. Delivery immutabile **abb9edfe6b2407f519baba350de1c55dfdac2679**, `scripts/launch-installation-owner-reauth244-20261019.sh`, SHA256 **01a41bd821b6a7c00d65d7fd367b7dbbe8b2cb26f78ed33abca0cc0c024f8b08**.

Questa qualifica cloud non ha fatto OAuth, owner/Engine request o operazioni container sul target. Riautenticazione, aggiornamento Onboarding e applicazione del binding **non ancora provati**. Tecniche **8/8**, funzionali **4/6**. Vecchio launcher consumato, installazione uow4n8lp/readback MCP/piano ofjxmhff non si ripetono. Profilo governato e tappe5–6 restano aperti.

---


### STOP corrente — HUMAN BLOCKED244/256; nessun aggiornamento owner avviato

**Il launcher owner precedente è consumato: non rilanciarlo.** Preparazione213 riuscita in `installation-owner-update-execution-cr_wsios`: package **174b8f8325a2721eddc90480a0a6851f5b060de10790115e4f655cbd096a3e4a**, chiusura **64f6139235d2f06a5c3cc0a7b2393ec6e213c1c4a56b2e392372c2790e9695fd**, immagine runtime containerd **sha256:c124a832a1f9f07967a8f3ef9ba9692610ab5c97aa4719e614867f44e6aa63ae**, prova34migrazioni **d1b046b00ca761e04eb810402840c87e0dcbe7022051ea1ede80adcce68fb99a**. Nessun rebuild o replay delle fasi completate.

Lo stato riportato si ferma in **EXISTING_HUMAN_SESSION_NO_NEW_LOGIN**, prima di compile_current, gate APPROVO, autorità ed effetti: **HumanSessionPaused**, **HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN**, contatore **244/256**, sessione **BLOCKED**, scadenza invariata **17:54:19 Europe/Rome**. Il codice aggrega cause permanenti/revoca/sconosciute: **non prova la causa specifica issuer**. Inventario riportato: execution-plan/review/issuance/authority/recovery/update-result assenti. La preparazione non è prova di aggiornamento installato; binding e fonte non applicati. Tecniche8/8,funzionali4/6.

Ricevute complete in `evidence/installation-owner-update-stop-checkpoint-20261019.json`. Prossimo passo: reader `scripts/read-installation-owner-update-stop.py`, vincolato a questo package/context/source/closure; nessun sorgente owner eseguito, bearer/key aperto, richiesta OAuth/owner/Engine, scrittura journal o rilancio. Legge il journal HUMAN solo per proiettare stato, budget e scadenze senza valori credenziali. Un eventuale nuovo login richiede un'azione distinta con consenso HUMAN esplicito, custodia cumulativa244/256 e nessun replay del refresh fallito; non è autorizzato dal reader. Nessun successore creato da questa continuazione cloud.

---


### Checkpoint corrente — piano target completato; correzione owner qualificata; aggiornamento distinto pronto

Tecniche **8/8**, funzionali **4/6**. Ricevute utente registrate integralmente in `evidence/installation-owner-update-qualified-checkpoint-20261019.json`. Completato il piano di sola lettura **ofjxmhff** / **6bebb5d19b337d4156bd63be78e4068c7117ecec3f3199ef142046cb20d695e9**: ACTIVE **5**, checksum sorgente **e9bea44bf977b17c94d9a9d1a1f2f2ddfff188360df3dbe11d20ee31460298b4**, candidato **ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98**, un binding aggiunto, altri campi conservati. Tre owner GET, zero mutazioni, export, proiezioni, Gateway PUT, SQL o cicli container. Nessuna autorità di apply: **non rilanciare piano/login/installazione/readback MCP completati**.

La sessione HUMAN installation-binding ha riportato **243/256** tentativi cumulativi (236→243), quattro scope installation aggiuntivi, finestra fino al **19 ottobre 2026,17:54:19 Europe/Rome**. Nessun reset, replay refresh precedente o nuova finestra. Questo è l'ultimo stato riportato, non una nuova interrogazione live.

Corretto il sorgente Onboarding in **b0f5e3dacbe59ebf87e22dd6af2575e41249f51d**, draft [PR47](https://github.com/GioNob/ouf-source-onboarding/pull/47): precondizione forte ACTIVE revisione/checksum/generazione sotto lo stesso lock della mutazione; generazione append-only contro ABA; deduplica create per attore/correlazione/payload; probe ambientali fuori transazione e recheck atomico prima della persistenza. Nessuna migrazione. Qualifica: **270 test applicativi +10 SDK**, build/scan HIGH-CRITICAL-UNKNOWN incluse vulnerabilità senza fix e boot smoke, run **39265848953**; browser verdi. Il codice è qualificato, **non ancora dimostrato installato**.

Immagine costruita/scansionata e depositata soltanto come file dal run **39266502171**: manifest **174c354c604d02267a2c3172ca2c06a2af1f15075c5abcb1a8034769bcdc3fc0**, image config **sha256:4790f4e8739282c33a8b5151e2f6c080a0db3284d226934160105538068a9035**. Nessun servizio modificato da questo staging; l'identità runtime containerd deriva dall'audit nativo, non dal solo config digest.

Pronta azione distinta **INSTALLATION_OWNER_UPDATE**, **213 moduli**, sorgente deploy **15827c6d5ee9ed761ce9a534441e689ea6007dfa**: 18 verifiche reali firma/journal/custodia/preparazione passate nel run **39270290481**, job **118120475846**. Delivery immutabile **c5aa4f578d1a806c94b9feaa0d27d011f9dcecc1**, launcher `scripts/launch-installation-owner-update-20261019.sh`, SHA256 **940c9ed3483a6316b70f73b1fd9f35a168fe2a4dd0bfd043354a4bffbb35abfe**: tre test delivery passati nel run **39270932534**, job **118122717660**. Il preparatore audita JAR fisico dell'immagine, tutte le **34** migrazioni identiche al sorgente installato be388, chiusura moduli e cronologia completata come file. Il runtime conserva e verifica anche le binding dei file di configurazione Flyway; preserva ambiente, mount, endpoint, metadati pubblici0440, profilo ACTIVE5 e82rotte/d5a.

Gate sul VPS: **APPROVO + hash corrente**, firme native dei due ruoli, sessione HUMAN esistente a11scope; nessun nuovo login/rinnovo finestra/reset budget. Ammissione richiede almeno20min residui nella finestra (prima delle17:34:19), budget residuo e stato corrente valido; durata massima900s. Aggiorna **solo Onboarding**, con breve indisponibilità e vecchio container conservato fermo. Nessuna migrazione, nuova revisione/attivazione/export installation, sostituzione proiezione, Gateway PUT, grant/IAM, attivazione fonte o acquisizione. Ogni stage ha claim persistente: dopo STOP/interruzione **non rilanciare**; riconciliare tramite ricevute pubbliche.

Applicazione binding/proiezione e due rotte richiedono una successiva azione nativa distinta dopo il readback owner. Poi lettura MCP con nuovo token/scope, attivazione fonte HUMAN distinta, seconda acquisizione dello stesso CSV e verifica identità/proprietà/provenienza/ACK; profilo governato e tappe5–6 restano aperti. Fonte non attivata, profilo non pubblicato, nessuna accettazione release o prova completa di risoluzione503. Consultati PET Matrice1.7§1; Onboarding/Configurazione/THS1.6§§103–106,THS-A02/A08/A09; Gateway1.5§§18–20,25.1–25.2,T11.3GW-NET01–05. La qualifica è circoscritta a questi cambiamenti, non certifica conformità completa o installazioni diverse.

---


### DNS osservato e piano distinto del binding d'installazione qualificato — 2026-10-19,15:50 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. La ricevuta target `ouf.mcp-ingestion503-dns-read.v1` è completa e di sola lettura: il target delle due rotte conservate restituisce **SERVFAIL/0A**, l'alias verificato dell'owner **RESOLVED/1A**, appartenente al container Ingestion conservato. Il profilo approvato non contiene il binding esplicito `services.bindings["ouf-ingestion-runtime"]`; le rotte coincidono con la proiezione approvata. Due query DNS, zero retry, sei EngineGET; namespace ripristinato. Nessun OAuth, journal HUMAN, ownerHTTP/backend probe, segreto, SQL, PUT o ciclo container. Map snapshot82/d5a invariata; nessuna nuova GET live Gateway. **Questo prova il difetto di risoluzione del target conservato, non ancora l'intera causa del503 né la correzione end-to-end.**

Con `ouf-admin`, policy **47**/hash `sha256:8aa234827edee9271548830a518407309d7042303a634a127ef46ec9e2371f00`, la vista GRANTS completa conferma già i quattro grant installation.configuration read/write/activate/export. Grant configurati, non prova di permessi effettivi o di scope del bearer. Nessun grant/ruolo/IAM modificato. Il percorso owner è InstallationConfiguration nativo HUMAN su Onboarding **be388e1462778438a208c2e00e166370fee32189**: nuova revisione immutabile, validazione ambiente, attivazione, export ACTIVE autorevole. L'export GET scrive audit: escluso dalla preparazione di sola lettura. Non eseguire lo storico script r4a di login/apply o editare a mano la proiezione attiva.

Il sorgente owner corrente non espone nell'attivazione una precondizione atomica sulla precedente revisione/checksum ACTIVE; il solo controllo client prima/dopo non elimina la race. Inoltre validateEnvironment attuale mantiene la transazione durante probe esterni. **Non autorizzare l'applicazione con questo piano**: la futura azione deve risolvere/qualificare questi vincoli secondo la politica di resilienza v3 e avere gate HUMAN/THS distinti. Nessun bypass tramite file o SQL.

Pronto un pacchetto **209 moduli**, source **7e0eddca54df18b3b01f5059b19feea50b7b645b**, delivery **fecdd70ddef15a269da5ebb592fba287bbd355cd**, launcher `scripts/launch-installation-ingestion-binding-plan-20261019.sh`, SHA256 **87fa08531e377c7223f5bcfa2c2b8ca94b5ea6117a44751d3f02681a91e761c9**. Conserva i205 moduli del pacchetto completato salvo due sole costanti scope HUMAN (AST di tutte le funzioni e guard invariato); aggiunge quattro moduli di pianificazione. Usa **humanBinding di execution-plan.json srz6__wf**, non il predecessor presente nel case. Prima di ogni consenso verifica cronologia/file/hash/custodia, eseguibili/stdlib, generazioni Gateway/Ingestion/Onboarding e alias attuale. Il vecchio main MCP non viene invocato.

Gate nativo **RIAPRO LOGIN + hash** per i quattro scope aggiuntivi, stesso issuer/soggetto/tenant/client, una finestra7200s, contatore corrente almeno236 e tetto cumulativo256, nessun reset/rinnovo automatico/vecchio refresh. Lo scope-v4 è già ammesso dal guard originale: non si allarga il predicato. Il provider può negare scope/consenso; in tal caso STOP senza replay. Solo dopo autenticazione e verifica del nuovo bearer: massimo **tre GET owner** (ACTIVE, payload revisione, ACTIVE) e piano privato con **una sola aggiunta** a `networking.serviceBindings`, ricavata dall'alias verificato; tutti gli altri campi preservati e checksum owner verificato. Massimo sei EngineGET e una DNS positiva nuova; niente retry del target fallito.

**Il comando prepara soltanto il piano e non è ancora eseguito sul target.** Zero creazione/validazione/attivazione revisione, export, sostituzione profilo, GatewayPUT, ciclo container, grant/IAM/SQL, source activation o job. `ownerApplyAuthorized=false`, `atomicOwnerActivePreconditionSupportProven=false`; futuro gate separato. Preparazione/runtime/successor hanno claim O_EXCL e journal cumulativo CAS; dopo STOP/interruzione riconciliare, senza rilancio.

Qualifica: **19PASS**, run [39263339190](https://github.com/GioNob/ouf-deploy/actions/runs/39263339190), job118096441209: vero stato macchina HUMAN e guard esportato dal target,236→240 nel fixture, rifiuto/deriva/denial provider/cap256, schema scope-v4, AST invariato, tre GET esatti, checksum/ACTIVE drift, closure209 e preparazione file-only con binding corretto. Delivery **3PASS**, run [39263560832](https://github.com/GioNob/ouf-deploy/actions/runs/39263560832), job118097205092: gh portabile autenticato,8pin, tamper/client assente prima di sudo, secondo controllo root. **Non acceptance del target.**

Non rilanciare install/readbackuow4n8lp, Gatewayazxw328z, MCPsrz6__wf o vecchi login/claim. Ultimo counter target riportato236/256, non riletto da questa preparazione CLOUD. Revisione fonte c9fec43c APPROVED/lock3 e activationNOT_STARTED sono ultime letture, non nuove verifiche. Restano lettura MCP Ingestion riuscita/scope fresh, attivazione HUMAN distinta, seconda acquisizione dello stessoCSV,13Teatri con stesse identità/20proprietà e provenance+ACK entrambe le acquisizioni,8Cinema preservati, profilo nativo governato e tappe5–6. Nessun subagente o automazione pianificata.

### Topologia target letta:8080WILDCARD,1retecomune,nessun alias match; DNS/profile read qualificata — 2026-10-19,15:27 Europe/Rome

Tecniche **8/8**,funzionali **4/6**. Ricevuta target `ouf.mcp-ingestion503-topology-read.v1` completa/readOnlytrue sul contextsrz6__wf,packageHash **d5e2be3a877c33c082d52fb0180a7a4a8cc10c9f4385c4064713417b366c4d38**. Sei EngineGET e2tabelleTCP,3generazioni correnti verificate; la cronologia MCP completata è provata come file, senza replay. Per ENTRAMBEstatus/history:porta upstream8080 è in ascoltoWILDCARD nel namespace Ingestion;1rete comune;ownerAliasOnSharedNetwork=false,literalOwnerAddressOnSharedNetwork=false,extraHostMapsToRetainedOwner=false. RiferimentoHMAC nell'EnvGateway presente/forma64hex attesa: **non è una prova di uguaglianza del segreto,firma o autenticazione end-to-end**.82rotte snapshot/hashd5a invariati nell'evidence; nessuna GETliveGateway,provaDNS/probeHTTP o causa503 specifica. Tutti i counter di OAuth/owner/DB/journalwrite/processdispatch/containerlifecycle/Gatewaywrite a0; nessun file credenziale,HUMANjournal,bearer,rawlog o hashvalorecredenziale stampato. Ultimo counterHUMAN riportato236/256,non riletto.

L'assenza di match statico del nome upstream restringe la diagnosi ma **non prova NXDOMAIN,neppure la causa esatta del503**. Nessuna modifica di rotte/reti/alias/profili o riavvio è autorizzata o effettuata da questa lettura. Nessuna nuova chiamata MCP Ingestion ripetuta: restano i due soli503 già registrati. Non rilanciare updateMCPsrz6__wf,Gatewayazxw328z,install/readbackuow4n8lp o login/claim consumati. Revisionc9fec43c resta APPROVED/lock3,activationNOT_STARTED alla lettura precedente; non ricreare o riapprovare la challenge giàCONFIRMED.

Sorgente Gateway2dfa `tools/apply_installation_projection.py` riletto: `services.bindings` risolve i nomi logici dei backend; in assenza della voce Ingestion resta il nome logico del catalogo. Non è ancora noto se tale voce manchi sul target; il prossimo reader confronta la proiezione realmente approvata con le due destinazioni conservate. **Non applicare un hostname/IP intuito dal cloud o un override ad hoc**: un'eventuale correzione dovrà essere versionata nel profilo validato e sottoposta al gate amministrativo distinto necessario.

Nuova diagnosi circoscritta `scripts/read-mcp-ingestion503-dns.py`,source **51c0db6a41fb7c14031b3dc7eae6eebdf47a37fe**,SHA256 **2e45b0afecccf4015264b1a4ba40e4e781c1969969a580ffbed35639e0c9cdd1**. Pin package205d5e2 e cronologia11stagecompletata/version27/result236; nessun main storico. Verifica le3generazioniGateway/Ingestion/MCP prima/dopo con6GET,proiezione approvata/path/hash/custodia(metadata9campi) e targetambeduerotte. La sola eccezione di ancestry conserva l'osservato /opt/ouf1000:1000/0750,senza chmod/chown; il resto richiede custodia root.

Seleziona due SOLI nomi:target delle rotte approvate e nome del containerIngestion ESPLICITAMENTE presente nei suoiAliases/DNSNames sulla sola rete comune verificata. Il secondo serve solo al confronto diagnostico,non diventa un nuovo upstream. Legge il resolv.conf root-controlled del containerGateway dalla posizione Dockerretained/pinnedID; richiede un solo resolverlocaleDocker127.0.0.11,nessun fallback verso resolver arbitrari o libc/host/searchsuffix. Nel processoPythonrootisolato/singlethread entra nel namespaceGateway dalFD/profilodev+ino atteso; invia **2queryDNS A UDP**,una per nome,timeout2sec,zero retry,4096byte/64recordmassimi. Ripristina il namespace di origine in finally e ne verifica dev/ino; nessun subprocess/containerexec e nessuna modifica di namespace di altri processi. Ricontrolla configurazione resolver,proiezione e tutte le generazioni dopo il ripristino.90sec massimo.

Proiezione pubblica:presenza della vocebindingsesplicita e matchcolprofìlo; per i due ruoli,statusDNS/counterrisposte/matchconIPownerretained ed eventuali indirizzi estranei. Nessun nomeDNS,IP,Env,token,chiave,credentialhash o pacchetto grezzo stampato. Parser controlla transactionID,questionA/IN,compressione/loop,CNAMEchain,risposte non pertinenti,troncamenti e dimensioni; nessuna interrogazione CNAME aggiuntiva,TCPfallback,HTTPbackend,OAuth,IAM,DB,owner/adminGateway,log o HUMANjournal. Namespace setns è transitorio nel solo lettore;processDispatches=0 e containerLifecycleOperations=0. liveGatewayRoutesRequeried=false: usa lo snapshot82 conservato,non ricontrolla le rotte live. specific503CauseProven restafalse: eventuale mancata risoluzione del target e risoluzione dell'alias owner sono evidenza di bindingDNS da valutare,non accettazione del percorso applicativo.

Qualifica CI[39259932560](https://github.com/GioNob/ouf-deploy/actions/runs/39259932560),job118084620771:**13PASS**. Include ripristino reale del namespace kernel su eccezione,rootfilecustody/proiezione default/esplicita e deriva negata,queryUDP singola/no retry/resolver chiuso,parserA/CNAME/loop/ID/domanda/troncamento/recordestranei,redazione e storico205/custodia ereditati eseguiti contro il nuovo reader. DNS risposte sono fixture: non sono una prova di risoluzione target già avvenuta.

Consegna **ee6d3ed3fdfa6def0d26a33b0df4417b840ae6d4**,launcher `scripts/launch-mcp-ingestion503-dns-read-20261019.sh`,SHA256 **e4ae7c488a76575a16c783ad9171510788c6cda443cab72ec017d71df85fa031**. Portablegh esistente/autenticato prima di PATH,checksumreader prima di sudo e ricontrollo root byte-per-byte prima dell'exec del solo sorgente qualificato. CI[39260068487](https://github.com/GioNob/ouf-deploy/actions/runs/39260068487),job118085084565:**3PASS** portableclient/pin/sudounico,tamper/clientassente,rootsubstitutionSTOP. Prossimo passo necessario: UNA letturaDNS/profilo dal terminaleoufadmin e sola ricevuta pubblica. Non eseguita dal cloud; nessuna nuova authority o modifica runtime.

PET originaleGateway1.5T11.3GW-NET01–05 riletto: endpointda configurazioneapprovata,DNS/allowlistindipendenti,nessunURLcaller/fallbackdestinazione. Owner/THSgate e resilienza v3§§5–7 invariati. Scopeinstallation-specific; non prova distribuzione multi-host,coerenza generale,conformità completa o releaseacceptance. Attivazione fonte e tappe5–6 restano ferme in attesa di un percorso operativo provato: SAMECSVsecondaacquisizione,13Teatri stessiID/20proprietà,provenance+ACKentrambe e8Cinema conservati.


### MCP aggiornato e readback completato; letture client Ingestion503; diagnosi topology qualificata — 2026-10-19,15:18 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. Ricevuta target operatore `ouf.mcp-ingestion-read-transport-update-result.v1`, statusMCP_TRANSPORT_UPDATE_READBACK_COMPLETE, context `/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-srz6__wf`: complete/applicationReady=true, journalVersion27, HTTP204/readinessAttempts1. Nuovo MCP container `8b199a6767bd39dadf82f6d70f964ab6da9c914a3b327229214d88991893647b`,PID312624,start2026-10-19T13:07:59.712730076Z,source1f2c28d7abadae78680b040ba7b58be62ef85ee9,imagea0a6f9562ba0b28ba3fef2b3a78bf46e90d9e14c99448d413bacf5d5cb75f182. Gateway routeMapHashd5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927 invariato,0PUT/0DBmigrazioni/0grant/0metadata changes/0jobretry; fonte non attivata, nativeProfilePublished=false,acceptanceGranted=false. HUMAN ultima osservazione236/256,20residui; la scadenza della nuova finestra non è stata fornita in questa ricevuta e non si deduce quella vecchia15:15. Non rilanciare srz6__wf,azxw328z,uow4n8lp,launcher di login/continuazione o predecessori consumati. Il readback è acquisito, non ripetuto dal cloud.

Strumenti disponibili ricontrollati con routing esplicito account `ouf-admin`/link_6aafef96b4148191b767e9af7b756a07, senza selezionare giovanni-chatgpt. Una chiamata `ouf.ingestion.status` sourceIdteatri-csv-6609b245,limit1 e una distinta `ouf.ingestion.history` stessa fonte,since2026-10-16T00:00:00Z,limit2 hanno restituito entrambe HTTP503,ProblemType/Title/Code/Detail vuoti,RetryAfter vuoto. Il wrapper espone error_codeINVALID_ARGUMENT, ma il payload osservato dichiara503: non attribuire il guasto a parametri utente. Nessuna ripetizione equivalente, loop o retry automatico, né altra chiamata Ingestion dopo i due esiti. **FreshChatClientReadProven e fresh client token scopes restano non provati**. MCP pronto204 non equivale a percorso Gateway→Ingestion fruibile.

Lettura owner separata `source.onboarding.revision.read` sullo stesso account riuscita: revisionc9fec43c-19b3-4ffb-9111-781bc347c5b0 **APPROVED/lock3**,configurationHashsha256:b13c5fe234168bdb8b315087917bccfe428ceaa8e136ed1c0f56f5bf43deed3d;parent9860853e-e8f3-4b93-b9d2-03521a039962/hashae7f46b4214d09c55a9885530920026258f0dcd588462c353b06d82185e12c9b. Challenge9bca610c-aa24-4be3-ac29-0e5454e9d877 è CONFIRMED,ora expired; humanApprovalRequired=false. **Non ricreare/riapprovare questa revisione né ripetere la challenge**. ActivationProgressNOT_STARTED/readiness_attempts0,generation0,ingestionCompatibilityObserved=false; humanActivationRequired=true,NEW_PUBLICATION_MAY_START_ACQUISITION,historicalJobsReplayed=false. Nessuna attivazione effettuata. Il mapping precedentemente qualificato20proprietà è legato allo stesso configurationHash; questa risposta è una receipt di revisione e non una nuova esposizione delle20regole.

Analisi codice primario: MCP1f invoca ora i due path dedicati e trasmetteHTTP503 dal Gateway; Gateway2dfa Lua può restituire503 se il riferimento HMAC non produce firma, oppure APISIX/upstream può produrlo. Nessuna causa specifica provata: non scegliere a priori HMAC, scope, DNS, rete, porta o backend. Il sorgente Ingestion main consultato per orientamento espone POST/api/internal/v1/ingestion/operations/status|history; **main non dimostra il commit installato**, che resta da ottenere dalla generazione qualificata target. Nessun bypass owner/Authorization o probe diretto backend.

Diagnosi installation-specific SOLA LETTURA `scripts/read-mcp-ingestion503-topology.py`, commit `6c1659b44ce1c39b2495b053f719215c1d836cfa`,SHA256 `707bbaa59d166a241cfc5c2943bf784f099c55901c67bfefdcb5fd3a83e4fef7`. Autentica205package/case/preparation/runtimeclaim/sources,review/decision/scope,11stageAPPLIED/RECOVERED/version27,result236 e snapshot82/hashd5a come FILE, senza entry/main/load o replay di alcun programma target. Quindi SOLO **6GET inspect**:Gateway,Ingestion,MCP,prima/dopo; runtime container/image/PID/start/config/host/mount/network confrontati coi binding qualificati. Legge/proietta esclusivamente i listener TCPv4/v6 del namespace PIDIngestion conservato; verifica namespace e generazioni prima/dopo. Per le sole due destinazioni approvate: porta,numero reti comuni,match alias/DNSNames,IPletterale/ExtraHosts verso il container atteso,presenza listener e classeWILDCARD/LOOPBACK/SPECIFIC_ADDRESS; presenza e forma64hex del solo riferimento HMAC selezionato da Lua. ConfigEnv viene ricevuta internamente con inspect, ma nessun valore/hash di segreto, indirizzo, hostname o altro Env è stampato.

Nessuna chiamata OAuth/IAM/owner/HTTPbackend/DNS attivo/adminGateway, nessun log, journalHUMAN, bearer/privatekey file;0processdispatch/exec/setns/containerlifecycle/DB/journalwrite/PUT/configchange. Massimo90sec,6EngineGET,limiti bytes e whitelist3container. Il map82 è **snapshot conservato**, non nuova GET alle rotte Gateway: liveGatewayRoutesRequeried=false e specific503CauseProven=false anche a lettura completa. Risultati statici/topologici non provano DNS live o causa issuer. Nessuna nuova authority.

CI[39258559949](https://github.com/GioNob/ouf-deploy/actions/runs/39258559949),job118079958102:**11PASS**, custody root0600/hash/symlink reali, storico205completato/deriva o stageincompleto negati,superficieEngineesatta,topologia/porta/reti/HMAC/formato kernelIPv4IPv6 e redazione,noexec/journal/login. Consegna `badf1824b2731c5de4e00385762dd713adfb2953`,launcher `scripts/launch-mcp-ingestion503-topology-read-20261019.sh`,SHA256 **77b71e403f0e6efaadebba1f9036cb3fb1fe88b16a3945b93f15de58f43815e2**:portablegh autenticato,pin reader6c165,checksumprima di sudo e ricontrollo root byte-per-byte. CI[39258891627](https://github.com/GioNob/ouf-deploy/actions/runs/39258891627),job118081080773:**3PASS** (client/pin/sudo unico,tamper e client assente,root recheck con sostituzione respinta). Prossimo passaggio: eseguire UNA diagnosi dal terminaleoufadmin e riportare solo la receipt pubblica. Questa diagnosi non è stata eseguita dal cloud. Qualsiasi riparazione mutativa richiede nuovo piano e gate nativo separato; niente rilancio degli update già completati.

Originali riletti per la decisione: Matrix1.7§1,MCP1.4§33.1–33.2,Gateway1.5§14(error model503Backend OUF non disponibile)/T11.3GW-NET01–05,THS1.6§106A02/A03/A08/A09. Policyresilienzav3§§5–7 richiamata:503 senza classificazione owner/RetryAfter non autorizza retry automatico sconosciuto. Nessuna claim di completa conformità,portabilità o accettazione end-to-end. Tappe5–6 restano SAMECSV seconda acquisizione,13Teatri stessiID/20proprietà,provenance+ACKentrambe,8Cinema invariati; attivazioneHUMAN ancora distinta e sospesa.


### Continuazione HUMAN distinta205 e aggiornamento SOLO MCP pronti per i due gate nativi — 2026-10-19,15:04 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. Gatewayazxw328z resta COMPLETATO:82rotte/hashd5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927,2PUT,80precedenti conservate,0container lifecycle,0DB,metadati0440preservati. Non rilanciare Gateway, installazione/readbackuow4n8lp o capsule consumate. Il precedente preparatore202 senza nuovo login resta non ammesso dopo14:55:03; nessun limite è stato ridotto sul target.

**Nuova azione amministrativa HUMAN da eseguire una sola volta**, sorgente `0be8fb13db3ff1ea014920bbbbb3738a8a434240`, closure205. Mantiene198moduli target +4MCP82 qualificati +3nuovi `tools.mcp_read_transport_gateway82_continuation.{entry,authority,login}`. Preparazione root isolata: autentica i file della capsule198 Gateway COMPLETATA e i3hash custody770, congela nuova205 e nuovo claim di preparazione;0OAuth/0authority/0PUT/0container, nessun main storico, copia/rebuild/import immagine o nuovo login in preparazione. Nuova capsule collega la cronologia Gateway e lo stesso logicalUpdateRef/fence MCP, immagine già custodita e source1f2c28d. Non riusa il runtime202 o alcun consenso consumato.

Primo gate nativo `RIAPRO LOGIN <reviewHash>`: review `ouf.human-explicit-test-continuation-review.v3`, motivazione finestra precedente insufficiente, stesso soggetto/tenant/issuer/client e scope ESATTAMENTE uguali alla sessione precedente. Counter corrente riletto,>=229 e<256; tetto cumulativo256, residui256-counter; nuova finestra7200secondi dal consenso e nessun rinnovo automatico. Schema già accettato dalla guardia HUMAN congelata: nessuna nuova patch/compatibilità o deroga. READY originale e journal invariati; CAS sul journal e successor-window.claim monouso prima della nuova sessione, collegata a review/decisione/hash cronologia. Vecchi access/refresh non vengono inviati. Solo dopo consenso nativo parte un login nuovo deciso dal provider; negazioni permanenti o sconosciute bloccano, senza replay. Il nuovo tempo non concede tentativi extra né aggira revoche.

Secondo gate nativo, solo dopo login verificato: ricompilazione piano corrente con4generazioni,82rotte/hashd5a invarianti,3metadati0440 con custodia/hash esatti e immagine MCP già qualificata; `APPROVO <reviewHash>` su piano privato nuovo. Autorità a due firme concede solo il replacement MCP a79b139→1f2c28d, vecchio container conservato fermo; timeout esecuzione<=900sec, un tentativo per effetto, readiness bounded e journal durabile.0PUT Gateway/0SQL-migrazioni/0metadata writes/0IAM-grant-policy/0attivazioni fonte-job. Login e authority runtime restano separati; nessuno dei due consensi è desunto dal chatbot o dalla preparazione.

Qualificazione sorgente0be: CI[39256750723](https://github.com/GioNob/ouf-deploy/actions/runs/39256750723), job118073840946, **220PASS** =206baselineMCP82 +10continuazione +4preparazione205. Test login con macchina HUMAN reale/journalCAS, provider boundary fixture e4richieste simulate porta229→233/READY, pubblica bearer nuovo senza riuso dei vecchi, lascia invariato il journal precedente e passa ANCHE il metodo esportato dalla guardia congelata target2e96cfc5 con reviewv3. Declino consenso, deriva contatore durante consenso, budget256/BLOCKED/secondo claim e diniego provider permanente danno STOP senza ripetizione/authority. Reali due firme Ed25519 per entry205, e login scope rifiutato come scope infrastrutturale. Questo è test fixture, non un login target già eseguito.

Consegna immutabile `0feed58a0172fd6a2e42b232b3a0c705e1670873`: script `scripts/launch-mcp82-human-continuation-20261019.sh`, SHA256 **6d6e490bccf4ab5339eab3b288c95c746ffa3d6a5c907390b46dee850db309b6**,10payload pin a0be verificati prima di sudo e di nuovo da root. Portablegh esistente prima di PATH; nessuna installazione client, curl anonimo o credenziale stampata. CI[39256906043](https://github.com/GioNob/ouf-deploy/actions/runs/39256906043),job118074374134,**4PASS** portable/tamper/client assente/ricontrollo10hash. Nessuna esecuzione o nuova finestra HUMAN effettuata dal cloud; il prossimo passaggio è questa unica consegna e i due gate sul terminaleoufadmin. Dopo STOP conservare tutti i claim/journal e riportare ricevute pubbliche; nessun rilancio. Le nuove directory e i counter reali saranno forniti soltanto dalle ricevute target. Eventuale human snapshot del bootstrap legato al case originario descrive il PREDECESSORE; la nuova sessione si individua dalla ricevuta login o successor claim, non si deduce un rollback del contatore da quello snapshot.

Dopo readback MCP effettivo: aggiornare strumenti accountouf-admin, provare status/history con token client scope corrente e leggere la revisione esistente c9fec43c APPROVED/lock3 prima del distinto gate HUMAN di attivazione. Fonte non attivata e accettazione non concessa da questa qualifica. Tappe5–6: seconda acquisizione SAMECSV;13Teatri identità conservate/20proprietà, provenance+ACK entrambe acquisizioni e8Cinema preservati.

Originali consultati per la continuazione: Matrix1.7§1,Blueprint0.3§1,MCP1.4§4/§33.1–33.2,THS1.6§106A02/A08/A09; policy resilienza v3§§5–7/14–16 riletta (nuova sessione finita solo HUMAN, contatori/fencing/idempotenza invariati, nessun superamento di revoca o ambiguità). Scope installation-specific; non prova multi-host, conformità completa o accettazione release.


### Gateway completato; aggiornamento distinto MCP82 qualificato; ammissione HUMAN da rinnovare — 2026-10-19,14:57 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. Ricevuta target fornita dall'operatore: `ouf.ingestion-read-gateway-result.v1`, context `/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-azxw328z`, complete=true. GatewayWrites=2, routeCount=82, retainedRoutesPreserved=80, routeMapHash=`d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927`, gatewaySourceCommit=`2dfa53fcf3792e8ed68df4e14303c3b085cdbd43`. ApprovedPublicMetadata0440Preserved=true, containerLifecycleOperations=0, databaseCalls=0, sourceActivated=false; notReleaseAcceptance=true. Questa azione Gateway è COMPLETATA: non rilanciare azxw328z né alcun predecessore o installazione/readback uow4n8lp. La ricevuta è evidence di esecuzione/readback target dell'operatore; questo checkpoint non rappresenta una nuova lettura live eseguita dal cloud.

HUMAN ultima osservazione target:229/256,27 residui, budgetReset=false; scadenza originale1792415703 =15:15:03 Europe/Rome. Nessuna ulteriore richiesta OAuth o apertura login dal cloud. Non dedurre che il token o la finestra siano ancora correnti da questa ricevuta.

Azione MCP distinta implementata e qualificata nel commit `8e47f464bca7ff994075917a8be929a9bf42413d`, namespace `tools.mcp_read_transport_gateway82`, closure202 =198moduli predecessori conservati +4nuovi(entry/authority/owner/native). Riusa l'immagine privata già qualificata di MCP1f2c28d7abadae78680b040ba7b58be62ef85ee9; nessun rebuild o ripetizione del preparatore originale. Il preparatore autentica fence/preparation/package/runtime.claim/case/sources della capsule198 completata, i3hash del namespace custody77033cd, review/decision/scope/journal/result Gateway, e vincola nuovo case ai file plan/journal/result. Prima del gate ricontrolla live82rotte/hashd5a, le4generazioni applicative e i3metadati0440 senza ripinnarne la custodia. Confronta MCP installato a79b139 con la stessa configurazione e immagine candidata già custodita. Mantiene lo stesso logicalUpdateRef e fence monouso MCP: nessun reset o bypass dei claim.

NativePorts nuovo richiama il metadata_file tipizzato qualificato per profilo/policy/permit0440. Il lettore privato0600 e tutte le capsule198/195/191/188/185 restano invariati. Solo sostituzione container MCP, conservando il vecchio fermo;0PUT Gateway,0migrazioni,0metadata writes,0IAM/grant/policy/source activation/jobs. Nuovo piano e consenso nativo `APPROVO <reviewHash>` precedono nuove firme/authority. Nessun consenso testuale nel chatbot equivale a questa authority.

CI [39255807172](https://github.com/GioNob/ouf-deploy/actions/runs/39255807172), job118070668089: **206PASS** =190regressioni +12MCP82 +4preparazione. Firma Ed25519 a due ruoli e vincoli Java owner reali, journal durabile/fence, nessun replay dell'effetto ambiguo, full NativePorts.guard_current con3file root0440 reali; il vecchio lettore0600 li rifiuta ancora. Preparatore202 esercitato con dati fixture, conservazione journal/claim/sessione e STOP su history incompleta, budget esaurito/statoBLOCKED/finestra insufficiente. Docker/HTTP sono boundary fixtures: questo non prova deployment target, letture ChatGPT fresche o accettazione funzionale.

Delivery7pin [39256066202](https://github.com/GioNob/ouf-deploy/actions/runs/39256066202):4PASS (portablegh prima di PATH, tamper STOP prima di sudo, assenza client STOP, ricontrollo root dei7hash). LauncherSHA2561257e2ee1d17e5aaa875bdfc436c975fd3a4c72f1aab83ba306a13cd3c5263b2, deliverycommit06644621d75175039f852cd59b1120e0e84a1809.

**Gate temporale aperto da risolvere prima dell'esecuzione MCP**: preparatore qualificato mantiene `time.time()+1200 < 1792415703` e corrispondente deadline monotona. Il termine di avvio14:55:03 è passato durante la qualificazione; non ridurre il requisito, modificare journal o estendere implicitamente la finestra. Il launcher7pin è archiviato per revisione ma **NON VA LANCIATO nella finestra attuale**. Una distinta continuazione HUMAN finita deve essere preparata e approvata nel terminale nativo, preservando soggetto/tenant/client/scope, history e cumulativo256; valore corrente del contatore da riconciliare, nessun replay del vecchio refresh. Quindi nuova capsule MCP che vincoli la nuova sessione autorizzata; il preparatore attuale è deliberatamente vincolato alla vecchia e non va adattato sul target.

Dopo effettivo aggiornamento/readback MCP: refresh strumenti accountouf-admin e UNA lettura bounded ingestion.status/history con token scope corrente; non anticipare tale prova. Leggere revisione c9fec43c-19b3-4ffb-9111-781bc347c5b0 giàAPPROVED/lock3 e proprietà20, senza ricrearla/riapprovarla; successivo gate HUMAN distinto per attivazione. Tappe5–6 ancora da provare: seconda acquisizione SAMECSV,13Teatri stesse identità/20proprietà, provenance e ACK per entrambe le acquisizioni,8Cinema conservati.

PET originali riletti per la decisione: Matrix1.7§1(confini congelati), Blueprint0.3§1(gerarchia), MCP1.4§4(budget/session/correlation e dispatch) e§33.1–33.2(OA bounded/owner), OnboardingTHS1.6§106A02/A08/A09. Confermano gate HUMAN/THS separati, budget cumulativi e assenza di raw logs/token. Nessuna dichiarazione di conformità completa o portabilità multi-host da questa qualifica installation-specific.


### Zero PUT provate; nuova chiusura198 con custodia0440 corretta qualificata — 2026-10-19,14:44 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. Reader target s_qwngj5 completo: packageHasha925da0d4a1a695f22690ac24d351f7dd34ba46b620465fa0198e13feedf0a16, closureHash898db65bfb84e361d957e8288b189c0c453b3c7e63e9546b9b9d7801f83b7182, planHasha316deb877fc9d2506ee41da98915fd43c582ec9f9fc2b7188af90452f19c617, reviewHashf1222de6ac5ab736120fb9cd159443992e4089186296891c8cc61cb2ab50dbd3. Journal versione0/nextStage0/effects[]/incidentOPEN: zeroStageClaimsProventrue e noGatewayDispatchByThisActionProventrue. Questo prova zero PUT di quell'azione, non una nuova lettura live generale Gateway. Autorità originaria scaduta1792413359 =14:35:59 Europe/Rome. Candidate-review0600 valida;3metadati permit/policy/profile0440 con hash e tutti gli attributi di custodia identici al piano approvato. Guardia dal sorgente nativo congelato SHA7ecc130876b88fead82f371b29f797751d6bf78530891c89ff1526504cf5034a impone S_IMODE==384 (0600): causa precisa confermata. Nessun effetto o token dal reader.

Correzione in namespace DISTINTO tools.ingestion_read_gateway_custody (entry/authority/owner), closure198 =195moduli conservati byte-per-byte +3nuovi; codice qualificato77033cd6125b633d5d188541f2ddac8366e07db2. Non modifica il lettore privato0600 né le capsule consumate. Nuovo metadata_file tipizzato accetta SOLO file pubblici profile/policy/permit0440, root-owned, nlink1, entro65536byte; root ancestry e nofollow, esatti inode/dev/uid/gid/mode/nlink/size dal piano, hash SHA256 approvato e snapshot FD/path invariato anche nei timestamp durante la lettura. Nessun chmod/chown o cambio di file. Candidate-review e prove private continuano a richiedere0600. Nuovo scope ingestionReadGatewayCustodyUpdate/profileouf.ingestion-read-gateway-custody-correction.v1 contiene metadataReadProfile PUBLIC_MCP0440_EXACT_BINDING e hash delle prove predecessore.

Ripresa governata della STESSA operazione logica delle due rotte: logicalUpdateRef e idempotenza dei due URI restano quelli originali; nuovo fence monouso custody-preparation/custody-execution, collegato a vecchi plan/review/journal/runtime.claim/logical.claim. Nessun claim rimosso, sovrascritto o rigiocato, nessun budget azzerato. Preparazione richiede autorità195 GIA SCADUTA, journal195 ancora0vuoto e fence/hash originali; qualsiasi stage/claim/risultato o deriva nega la preparazione. Prima e durante l'azione i5binding predecessori devono restare invariati. Nuovo gate APPROVO <hash> e nuove due firme amministrative sul codice corretto: l'autorità195 scaduta non autorizza la nuova chiusura. Nessuna authority runtime da cloud/preparazione.

Prima del gate: verifica live80rotte e4generazioni container, ricompila con lo stesso bundle Gateway2dfa53f qualificato e richiede afterRoutes ESATTAMENTE identico alle82rotte del piano195 già approvato, compresi gli80precedenti invariati; stessi4container e3metadata con identica custodia. Il nuovo owner ripete la validazione tipizzata0440 durante i4stage. Massimo2PUT con claim e readback completo; STOP ambiguo resta CLAIMED e non si ripete. Nessun lifecycle/riavvio/container/MCP replacement, import immagine, DB/migrazione, IAM/grant/policy47/metadati, attivazione fonte/acquisizione o job.

Sessione HUMAN esistente READY227/256 all'ultima osservazione,29residui; nessuna nuova login/finestra/budget. Scadenza originale1792415703 =15:15:03 Europe/Rome; refresh nativo eventualmente necessario mantiene il cumulativo. Avvio preparazione PRIMA14:55:03 per avere1200secondi residui; scope massimo900secondi sempre entro la scadenza originale. Runtime/entry/authority195 non si rilanciano, né i predecessori uow4n8lp/1lxoo2ws/mbbleugm/wiqedn9w/zzp9gqcs.

Qualifica [39254000378](https://github.com/GioNob/ouf-deploy/actions/runs/39254000378), job118064581103:190test PASS =168regressioni+16owner/custodia/crypto+6preparer. La nuova fixture contiene TUTTI I3FILE0440 reali: vecchio lettore0600 fallisce, helper tipizzato e percorso completo owner con2PUT/readback passano senza cambiare modalità. Test negativi hash/gid/mode/inode/symlink/hardlink, predecessore ancora live o journal alterato, doppia preparazione/claim, budget/finestra, firme reali due ruoli sulla entry198, old195immutati, nessun login/main storico. Gateway materializer e Lua non cambiano: restano valide le prove137test e APISIX reale del checkpoint precedente, che non costituiscono accettazione target. Il nuovo test non lascia più vuota la lista metadati nel percorso nativo.

Launcher scripts/launch-ingestion-read-gateway-custody-20261019.sh SHA256f7f018679cf380662f21c7d570955f3edcd7a3d4d0b063f86d5d86f2bc35c52c,6payload pinned77033cd, controlli prima di sudo e ripetuti da root;4test consegna locali e CI [39254420058](https://github.com/GioNob/ouf-deploy/actions/runs/39254420058), job118065994867 PASS;6file verificati anche contro il tree Git77033cd. Consegna immutabilede35b02e55ff7d6b15424711030071249a0e29fb. Nessuna esecuzione target dichiarata da CI. Dopo STOP/interruzione NON ripetere; nuova diagnosi sulla nuova capsula esatta. Dopo readback Gateway82 occorre preparare separatamente MCP1f2c28d, correggendo ANCHE il suo adapter metadati600/440 e la baseline attesa82; NON riusare il vecchio piano solo-MCP80. Poi prova token ChatGPT fresco, revisione fonte APPROVED già esistente, attivazione HUMAN/THS e acquisizione SAMECSV/identità/provenance/ACK per tappe5–6.

PET originali consultati: Authorization1.5 §§20–22/109.6; THS1.6 §106 A08/A09; Gateway1.5 §§18–19/25; resilienza v3 punti14–16 (stessa operazione/idempotenza, un'autorità attiva, fence e storia conservati). Non è un rinnovo di budget o una nuova approvazione di dominio.

### Gateway HUMAN approvato; STOP custodia0440/0600 da riconciliare — 2026-10-19,14:27 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. Operatore ha superato APPROVO dell'azione due rotte: capsula /etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-s_qwngj5; execution-plan/review/authority/issuance/recovery presenti, update-result assente. Stop UpdateDenied(PRIVATE_FILE_CUSTODY_REQUIRED) in TWO_GATEWAY_PUTS_AND_READBACK; HUMAN READY227/256 (29residui all'osservazione), scadenza originale1792415703 =15:15:03 Europe/Rome. L'autorità è stata emessa: NON descrivere questo stop come pre-authority. Dal solo JSON gli stage/PUT non sono ancora provati; nessun replay/rilancio o claim rimosso.

Incoerenza trovata nel codice: entry.compile_current impone metadati MCP0440; GatewayUpdate.guard li passa a tools.semantic_mcp_update.native.private_file, che nella repository richiede root:root0600. La fixture CI native precedente aveva retainedMcpMetadata vuoto e ha omesso questo confine reale. Non correggere con chmod/chown, non allargare genericamente il lettore600 a file pubblici, non riscrivere il piano/review/source closure firmati o riusare autorità con codice diverso. Serve controllo tipizzato dei metadati pubblici0440 con hash/custody esatti; anche l'adapter MCP da preparare contiene la stessa chiamata e va corretto/testato prima dell'azione successiva. La correzione runtime non è ancora preparata o eseguita.

Nuovo scripts/read-ingestion-read-gateway-custody-stop.py, vincolato alla capsula esatta e ai fence deterministici: verifica package195/bab8a2d,4sorgenti Gateway pubbliche, case/lineage c131/02d, piano/review/decisione e journal nativo contro scope e intentHash. Autorità/chiavi/credenziali non aperte. Restituisce solo stage/state/versione/scadenza e due prove distinte: zeroStageClaimsProven e noGatewayDispatchByThisActionProven; un claim route viene classificato ambiguo, non zero effetto. Hash del journal deve restare identico alla seconda lettura. Non invoca Gateway live/Engine/owner/OAuth, nessun exec di sorgenti target o scrittura. Controlla SOLO candidate-review privata e3metadati pubblici mediante FD nofollow, tipo/nlink/limiti/hash/stabilità/custody approvata; nessun valore dei file viene stampato. AST estrae inoltre l'esatta guardia PRIVATE_FILE_CUSTODY_REQUIRED dal modulo native sigillato per verificare il contratto congelato senza eseguirlo. Limite60secondi, zero authority concessa dal reader.

9test locali e CI [39252207836](https://github.com/GioNob/ouf-deploy/actions/runs/39252207836), job118058522352 PASS con veri file root0440/0600, hash/custody, symlink/hardlink, journal vuoto, claim route ambiguo, scope/stage errati, estrazione sola guardia pubblica e assenza superficie exec/rete/write. Reader SHA25654d46f5a0c8d5a7ab503c3e73c66f41b025e23e918e781d5ed7395e0f6bb4eff. La prova target deve precedere un'eventuale nuova azione con chiusura corretta e relativo gate, conservando tutti i claim/budget/storico. Se esistono claim o PUT, prima riconciliazione esatta senza ripetizioni. Nessuna conclusione di route publication, MCP update, profilo governato o tappa5–6 da questo STOP.

PET originali consultati: Authorization1.5 §109.6 (deny su integrità/configurazione non verificata); THS1.6 §106 A08/A09 (secret esclusi, hash/state stale richiedono nuova review); Gateway1.5 §§18–19,25/25.1; resilienza v3 punti5–7/14–16. I permessi0440 sono un binding dell'installazione già approvato, non un nuovo valore normativo PET.

### Due rotte READ assenti: azione Gateway distinta qualificata, NON eseguita — 2026-10-19,14:18 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. Reader target completato: zzp9gqcs packageHashc131f941202667fb52e639fd6a59f8084dbae2a2ebe9015c3fb86bdc57e394b4, closure191 hash02d07d681c6a407e666027f7c97206f79c2235e95254e7b44140ca137bb5e206. Inventario9artefatti MCP assenti; routeShapes status/history entrambe selectedRoutes[], retainedGuardWouldPassfalse. Snapshot80rotte con hash9b022a247a5777347cd7794733507bb90a9142ffd62c6497ae3e3c1cbd66fcd2. Zero rete/OAuth/journal HUMAN/Engine/scritture. Non basta cambiare uri→uris o togliere il controllo: i due binding dedicati non sono materializzati. Il confronto live80==snapshot era già passato prima dello STOP; il reader non costituisce una nuova lettura live.

Causa nel codice Gateway: i descrittori mcp-ingestion-status/history e capability ingestion.operations.read esistono in dd8553d, ma i materializzatori execute coprono system.status e sei capability operations diverse. Nuovo materializzatore additivo Gateway2dfa53fcf3792e8ed68df4e14303c3b085cdbd43, DRAFTPR80; discendentef831d80d41b5b9687116671899c538dd7024d478 aggiunge SOLO prove APISIX. Mantiene OIDC/JWKS/TLS verification, workload esatto, delegazione firmata HUMAN, scope ingestion.operations.read, owner Ingestion e argomenti chiusi. Backend service/port risolti dal profilo validato, nessun URL chiamante o fallback locale. Nessuna merge eseguita.

**Separazione corretta dello scope**: prima NUOVA azione per SOLO due PUT Gateway; poi nuovo aggiornamento MCP con decisione distinta e baseline82 verificata. Nessun effetto Gateway viene inserito nella review precedente solo-MCP che lo vietava. Nuovo namespace tools.ingestion_read_gateway_update, closure195 =191 conservati +4moduli. Sorgente eseguibile bab8a2d3d7965b9d2de60f13de475e7afad44b8e, qualifica discendente453c1f724f31b259578796d80a053f315e40e615 (corregge SOLO fixture di test). Riusa sessione HUMAN già autenticata225/256,31residui ALLA RICEVUTA, scadenza originale1792415703 =15:15:03 Europe/Rome; non riapre login/finestra o budget. Un eventuale refresh della sessione READY resta nativo, cumulativo e bounded; errore permanente/sconosciuto ferma senza replay. Nessuna modifica a review/decisione/journal/claim storici.

Preparazione distinta monouso e O_EXCL, ancorata esattamente a c131/02d/zzp9gqcs e alla ricevuta225. Nuovo compiler bundle include7file Gateway con SHA256+Git blob SHA corrispondenti al tree2dfa; projection/compiled bindings/renderer/Lua/schemi vengono rieseguiti solo come compiler qualificato, non come main storico o autorizzatore. La chiusura eseguibile include hash del case con binding del bundle. Prima del gate vengono verificati attuali80rotte,4generazioni container,3metadati0440, profilo di installazione e identità HUMAN; viene pubblicato un piano concreto82rotte. Gate nativo APPROVO <hash corrente> emette le consuete due firme amministrative SOLO sul nuovo scope ingestionReadGatewayUpdate. Il precedente consenso solo-MCP non autorizza le PUT.

Quattro stage: VERIFY_INPUTS, GATEWAY_STATUS_ROUTE, GATEWAY_HISTORY_ROUTE, VERIFY_FINAL. Massimo2PUT, una per rotta /internal/capabilities/v1/execute/ouf.ingestion.status|history, ciascuna con claim durabile e GET/readback completo.80rotte esistenti preservate integralmente,82finali. Esito ambiguo lascia CLAIMED e blocca il secondo invio; nessun DELETE/rollback/ripetizione. Fence logico impedisce seconda capsula sullo stesso delta. Engine solo GET per verificare MCP/Onboarding/UDP/Ingestion invariati. Zero lifecycle container, import immagine, migrazioni/DB, modifiche IAM/grant/policy47/metadati, attivazione fonte/acquisizione/job. Nessuna authority o PUT eseguita in CLOUD.

Qualifiche: Gateway137test mirati PASS ([39249510448](https://github.com/GioNob/ouf-api-gateway/actions/runs/39249510448), job118049556648); suite Gateway545PASS/3skip e APISIX3.18/OIDC reale1PASS con entrambe le nuove rotte e negativi firma/workload/tenant/scope/URL ([39250002276](https://github.com/GioNob/ouf-api-gateway/actions/runs/39250002276), job118051181272). Native owner/preparer:168test PASS ([39250646151](https://github.com/GioNob/ouf-deploy/actions/runs/39250646151), job118053309057):150 regressioni+13nuovo owner/crypto/compiler+5preparer. Prove native di rete Gateway e owner journal/signature sono separate; APISIX CI è un'istanza isolata, non accettazione del VPS o del backend Ingestion reale.

Launcher scripts/launch-ingestion-read-gateway-update-20261019.sh SHA256eb27459d56a486d1e33da952fef36e219779f044ccd2c1cb4dcf98ed29b70000:8payload pinned bab8a2d, hash verificati prima di sudo e ripetuti da root;5test consegna locali e CI [39251110599](https://github.com/GioNob/ouf-deploy/actions/runs/39251110599), job118054843144 PASS; launcher pubblicato in9d7e2e7db1f4d6a4c86f90ca36464251d829ff21 (portable gh, entry/bundle manomessi, assenza client,8hash root). Preparazione richiede1200secondi residui: avvio PRIMA14:55:03 italiane. Runtimescope massimo900secondi, sempre entro la scadenza originale. Dopo STOP/interruzione NON rilanciare; usare nuova diagnosi esatta. Non eseguire più launcher uow4n8lp/1lxoo2ws/mbbleugm/wiqedn9w/zzp9gqcs.

PET originali consultati: Gateway1.5 §§18–21,25/25.1; Authorization1.5 §§20–22,109.6; THS1.6 §106 A02/A08/A09; resilienza v3 punti5–7,14–16. Resta separata la revisione c9fec43c-19b3-4ffb-9111-781bc347c5b0 APPROVED: nessuna riapprovazione/attivazione implicita. Dopo Gateway e MCP occorre ancora prova da token ChatGPT fresco, profilo governato, acquisizione SAMECSV con13Teatri/20proprietà, identità/provenance/ACK e8Cinema conservati per tappe5–6.

### Login riuscito225; STOP nella verifica forma rotte, nessuna authority MCP — 2026-10-19,13:59 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. Ricevuta nativa dell'operatore: login stesso account completato,217→225/256,31tentativi residui, nessun replay refresh e nessuna nuova finestra; consenso originale conservato, expiresAt1792415703 (15:15:03 Europe/Rome). compatibilityReviewHash71ed7ce4faa930e84d7582ced9aaec56f07abf7fc1d9886e447f6fca39353c3e; loginReviewHash43b0caf6165b43df25e6fba7a37ccce39a1dc56597d47cffe7b6b8a8fed0b301. Custodia delle credenziali rimane sul target.

Capsula distinta /etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-zzp9gqcs ferma in READ_ONLY_CURRENT_PLAN con UpdateDenied(REVIEWED_INGESTION_GATEWAY_ROUTE_MISSING). Sessione osservata READY225; compatibility-review/decision e login-window-receipt presenti; execution-plan/review/authority/issuance/recovery/update-result assenti. Nessuna autorità runtime o effetto MCP provato. NON rilanciare launcher/bootstrap/login/refresh o claim consumati. Il codice è già passato dal confronto completo live80rotte == afterRoutes del readback uow4n8lp, poi fallisce nella ricerca uri esatta + methods==['POST']; non prova da solo assenza di un binding equivalente né autorizza scritture Gateway.

Nuovo scripts/read-mcp-ingestion-route-stop.py: diagnostica installation-specific,60secondi, sola lettura. Risolve SOLO fence deterministico della preparazione compatibilità e richiede il contestozzp9gqcs; autentica case/191sorgenti e entry fallita39498090, ricevute/hash dichiarati, assenza artefatti autoritativi, piano/journal storici con hash già conservati. Proietta esclusivamente le due rotte: forma uri/uris, metodi HTTP ammessi, corrispondenza ai path pubblici execute/owner e risultato del predicato attuale. Non esporta plugin, host, credenziali o payload privati. Snapshot storico esplicito, nessuna nuova interrogazione live Gateway o journal HUMAN, nessun exec target/Engine/rete/OAuth/processo/scrittura. Non riavvia installazione/readback o azione fermata.8test locali e CI [39248598167](https://github.com/GioNob/ouf-deploy/actions/runs/39248598167), job118046548784 PASS: forme alternative non automaticamente ammesse, assenza/cardinalità, redazione, negativi artefatti/receipt, lettura esatta e assenza superficie esecuzione/mutazione. Correzione del controllo o modifica Gateway dipenderanno dall'evidenza target; nessun gate indebolito per superare lo STOP.

PET originali consultati per questa decisione: Gateway1.5 §25/25.1 (binding derivati da artefatti approvati), Authorization1.5 §21 e109.6, THS1.6 §106 A02/A08/A09; resilienza v3 punti5–7/14–16. Fonte/revisione restano separate e senza attivazione o acquisizione. Policy47 e grant finito già pubblicati non si ripropongono.

### Compatibilità del guard congelato qualificata; stessa finestra HUMAN — 2026-10-19,13:54 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. L'AST esportato dal target (humanSourceSha256 2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285) prova che la guardia ammette solo review v2/v3/v4: rifiuta la review già approvata schema ouf.mcp-read-transport-human-reauthentication-review.v1. La causa del PlanDenied è riprodotta; non deriva da reset richiesto o finestra nuova necessaria.

Nuovo codice qualificato f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e: transformer vincolato al SHA originale aggiunge un solo ramo OR per lo schema esatto e prova equivalenza dell'intero AST rimuovendo quel ramo. Identità, scope, budget, decisionHash, timestamp e guardie esterne invariati. Non modifica review, decisione o journal originali. Aggiunge namespace tools.mcp_read_transport_compatibility (191 moduli), capsula e fence distinti; NON rilancia wiqedn9w/mbbleugm/installazione uow4n8lp/admin1lxoo2ws.

Riusa SOLO la sessione NEW217 esistente, già approvata alle13:15:03, scadenza15:15:03 Europe/Rome del19ottobre2026 (1792408503–1792415703);217/256 consumati,39residui. Nessuna nuova finestra o proroga. Preparazione e ripresa richiedono almeno1200secondi residui: avvio prima14:55:03. Stato/token/contatore diversi, claim già presente o scadenza provocano STOP; nessun replay automatico.

Gate nativo APPROVO COMPATIBILITA <hash> autorizza la nuova chiusura eseguibile per iniziare UN login già consentito: necessario perché cambia il codice eseguito, non rinnova il consenso o il tempo. Provider verifica nuovamente lo stesso account; segue distinto APPROVO <hash> per il SOLO aggiornamento MCP1f2c28d con immagine già custodita a0a6f956. Nessuna autorità infrastrutturale dal primo gate. Gateway80rotte, grant/policy47, metadati0440, altri servizi, revisioni/fonte e job esclusi. Refresh fallito e credenziali precedenti mai riusati.

CI [39247144428](https://github.com/GioNob/ouf-deploy/actions/runs/39247144428), job118041708029:150test PASS, inclusi rifiuto esatto/correzione, schema legacy, negativi identità/budget/tempi/consenso/permessi, login completo con provider di prova e metodo esportato, doppio avvio fenced e firme reali dei due ruoli sull'entry distinta. Limite: CI usa l'esatto metodo pubblico esportato nel runtime fixture; sorgente h completo congelato rimane sul target e viene autenticato dal transformer prima di modificarlo. Nessuna prova di esecuzione/accettazione target dalla CI.

Launcher con7file pinned f0ecc3e, controlli prima di sudo e ripetuti da root, SHA256 fc14871dac371106f849ce8e822bf16eff2dd8041cecb062041d4a27202a99f9;4test consegna locali e CI [39247854928](https://github.com/GioNob/ouf-deploy/actions/runs/39247854928), job118044074922 PASS; consegna d8e8280434bf016df8d0aec0e271a8ad0854ec21. STOP ora include fase/codice sicuro whitelistato e inventario senza token. Nessuna OAuth, authority o sostituzione runtime eseguita in CLOUD da questa preparazione. PET originali consultati: Authorization1.5 §§20–22,109.6; THS1.6 §106 THS-A02/A08/A09; resilienza v3 punti5–7,14–16. Nessuna dichiarazione di conformità completa.

### wiqedn9w riconciliato:NEW217, nessuna OAuth; guardia rinnovo incompatibile da isolare — 2026-10-19,13:26 Europe/Rome

Tecniche8/8, funzionali4/6. Reader188 completo nella capsula `/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-wiqedn9w`, packageHash4c63051ba4f22d3f83c33b96a5cc150824a6aadf79b9a6948ff09972b8c601be, sourceClosureHash2eb74254682d3fec8e49f2c5c08acaa83ff87b1f5d736b38124b7380e2a99a76. Tutti i9artefatti piano/review/authority/issuance/journal/result MCP ASSENTI; login-review presente, login-window-receipt assente, runtimeclaim consumato. Nessuna autorità o sostituzione MCP iniziata. Successor HUMAN creato ma stateNEW, attempts217, nessuna operation/token/accessExpiresAt/refresh; OAuth non ancora invocata dal nuovo login,39residui conservati.

Binding vecchio e nuovo entrambi validi; i due controlli native _check_identity_and_budget/_check falliscono PlanDenied(RENEWED_HUMAN_WINDOW_CUMULATIVE_HISTORY_REQUIRED). Il flusso è arrivato alla creazione durevole del journal nuovo e al primo controllo immediatamente successivo, PRIMA dell'emit FRESH_ISSUER_AUTHENTICATION e prima di following.login. La qualifica precedente usava il runtime h della repository con profilo test256 patchato, non il metodo completo realmente congelato sul target: questo confine non era coperto. Non correggere il problema simulando il predicato, cambiando il contatore o riscrivendo review/decisione. Non rilanciare c9/launcher/login/bootstrap e non eliminare claim.

Finestra HUMAN già approvata e persistita: createdAt1792408503 =2026-10-19T13:15:03+02:00, expiresAt1792415703 =15:15:03+02:00,7200secondi. Non sostituirla con una nuova finestra e non cambiare timestamp/approvazione per risolvere incompatibilità. La soluzione deve preservare prova del consenso e max256/217consumati, con nuova review solo se cambia materia che richiede HUMAN/THS.

Reader successivo `scripts/read-human-renewal-guard-source.py`: legge esclusivamente package/sources sigillati della capsula wiqedn9w e il claim già consumato, ancorati ai due hash sopra e c9d3ca8; nessun journal/token/chiave o codice target eseguito. AST estrae solo HumanSession._check_identity_and_budget e l'espressione del require con codice RENEWED_HUMAN_WINDOW_CUMULATIVE_HISTORY_REQUIRED, per ottenere l'esatto contratto pubblico del runtime congelato e la fixture da qualificare. Nessun valore runtime, row, credenziale o fingerprint viene esportato.4test passati anche nella CI39245110835 per estrazione senza exec, guardia assente/doppia/bounded, esclusione altri metodi e zero dispatch. Non è una nuova autorità né una prosecuzione dell'azione.


### Nuovo STOP PlanDenied: fase e contatore da riconciliare — 2026-10-19,13:15 Europe/Rome

Tecniche8/8, funzionali4/6. L'operatore ha restituito solo il JSON terminale schemaouf.mcp-ingestion-read-transport-stop.v1, exceptionClassPlanDenied, STOP_RECONCILE, runtimeCompletionProvenfalse, automaticReplayAllowedfalse/budgetResetfalse. Mancano le righe preparazione/fasi e l'eventuale ricevuta login: NON è provato da questo solo messaggio se il login sia completato, se la seconda review/authority esista o se siano iniziati effetti MCP.217/256 resta l'ultimo contatore provato del predecessore, non quello della nuova sessione. Non rilanciare launcher, bootstrap, login o refresh; non assumere stage applicati o assenti. Nessuna nuova diagnosi OAuth o modifica runtime avviata in cloud.

Preparato `scripts/read-mcp-reauthentication-stop.py`: risolve SOLO il claim deterministico della preparazione distinta (package predecessoref4552fa8 + candidate imagea0a6f956), poi la capsula esatta senza scansione delle altre sessioni. Verifica sorgentec9d3ca8/closure188,3moduli aggiunti e loader con hash pubblici indipendenti,185sorgenti conservati con package185f455 ancora ancorato. Inventario dei9artefatti azione +2login; eventuale journal native proiettato nei soli stage/state e contatori finiti; authority/chiavi/bearer non aperti. Segue solo il successor-claim del vecchio HUMAN e legge in privato l'eventuale nuovo journal per contatore/stato/receipt, senza valori o hash di credenziali.

Carica le sole definizioni sigillate e invoca solo validate_session_binding e _check_identity_and_budget/_check sui dati già letti: nessun main, authenticate, current, login, refresh, compile_current, signing o network. Mostra codici di guardia solo se literal nei sorgenti sigillati; JWT eventualmente persistito viene decodificato localmente nei soli predicati issuer/sub/tenant/actor/client/audience/assurance e scope pubblici mancanti, mai come nuova prova di firma. Verifiche di scadenza sono esplicitamente al tempo della diagnosi, non prova automatica della causa originale. Se il token non è stato persistito non viene recuperato o richiesto.7test passati anche nella CI39244135128 (redazione, whitelist codici, journal CLAIMED, JWT mancanti/predicati, drift budget e superficie di sola lettura). Reader vincolato120secondi, zero OAuth/owner/Engine/processi/scritture; anche errori del reader espongono solo fase e codice locale whitelistato. Nessuna autorità di ripresa concessa.


### Correlazione non attribuita; nuova autenticazione HUMAN distinta pronta, NON eseguita — 2026-10-19,12:29 Europe/Rome

Checkpoint corrente: tecniche **8/8**, funzionali **4/6**. Correlation reader restituito dall'operatore: identificativi disponibili ma nessun match token/session-id/soggetto;1errore client non attribuito `invalid_token / TOKEN_NOT_ACTIVE`. matchingIssuerEventProvenfalse, specificIssuerReasonProvenfalse; non imputare la causa specifica al HUMAN217.3GET Engine, journal HUMAN letto solo in locale (due snapshot invariati), zero OAuth/admin/exec/scritture; nessun identificativo/valore/hash di credenziale stampato o trasmesso. La sessione resta BLOCKED217/256,39residui. Non ritentare il suo refresh o launcher mbbleugm.

Preparata una NUOVA azione con gate nativo esplicito: `tools.mcp_read_transport_reauthentication`, sorgente `c9d3ca870c95518c94f754640cd68dc8462c609e`, closure188moduli = i185byte-sorgenti della capsula mbbleugm conservati +3moduli entry/authority/login. Non cambia il codice o le autorizzazioni del pacchetto consumato. Nuova preparazione distinta con fence O_EXCL; nessun main storico, nuova build/import immagine o migrazione. Riusa l'immagine privata già preparata a0a6f956 (stessi config/layer; MCPsource1f2c28d), la cui custodia viene verificata dall'owner prima dell'effetto.

Primo gate `RIAPRO LOGIN <hash corrente>`: apre UNA nuova autenticazione dello stesso soggetto/tenant/issuer e stessi7scope, con finestra7200secondi dal consenso e tetto cumulativo256 INVARIATO (parte217,39residui). Nessuna richiesta OAuth prima del consenso. Questa è una nuova finestra autorizzabile, non una proroga silenziosa della vecchia scadenza10:32:43Z; il vecchio journal resta BLOCKED/intatto, si aggiunge solo il successor-claim monouso. Nuovo journal parte217 senza vecchi token o refresh; provider verificato via HTTPS/userinfo conserva revoca, account/client policy e assurance. Nessuna modifica IAM/grant/ruolo/policy47; errori o negazioni del provider bloccano, non vengono aggirati. Causa specifica precedente resta dichiarata non attribuita. Nessun rinnovo automatico né incremento del budget.

Il primo consenso NON emette autorità infrastrutturale. Solo DOPO nuova identità HUMAN verificata viene compilato lo stato corrente e richiesto un SECONDO `APPROVO <hash>` per il solo MCP; due firme installer reali e scope esatto invariato. Breve indisponibilità MCP, vecchio container fermo/restart disabilitato conservato; Onboarding/UDP/Ingestion invariati. Zero backup/migrazioni/SQL, scritture Gateway/80rotte/metadati/permessi, attivazione fonte, acquisizioni o job. Incertezza/STOP/interruzione richiedono riconciliazione, mai rilancio automatico.

Qualifica `39237400524`/job118009691902 PASS: **132test** complessivi, di cui12nuovi. Login runtime e journal/publisher reali con provider fixture deterministico: discovery/device/poll/userinfo, bearer pubblicato dopo verifica,217→221; vecchio journal invariato e nessun refresh vecchio; consenso rifiutato, drift/successore doppio, provider deny, nuovo loader188, due firme installer reali per la nuova entry e negazione scope aggiuntivi. Nessun login o aggiornamento target eseguito dalla CI.4test di consegna launcher passati in locale e nella CI39237861394. Launcher `scripts/launch-mcp-transport-reauthentication-20261019.sh`,6download/hash autenticati prima di sudo e ricontrollati da root; SHA256702d4a28e8ea1151b5fa1e47537b82ce4fa4efa9b3f2e37702702acbdaf6570a. UN SOLO lancio; non usare i vecchi launcher. Riportare solo ricevute pubbliche finali o STOP, non codici device/credenziali.

PET originali effettivamente consultati per questa scelta: Authorization1.5§§20–22 e109.6; SourceOnboarding/THS1.6§103 eTHS-A02/A08/A09; policy resilienzav3§§5–7 e14–16. Autenticazione nuova e consenso infrastrutturale restano distinti dalle decisioni di dominio THS. Policy47/grant finito e amministrazione1lxoo2ws già completati non si ripetono; uow4n8lp install/readback acquisiti. Revisione fonte c9fec43c già APPROVED/lock3: dopo update MCP verificare tool/scope e stato attuale, poi attivazione HUMAN separata e milestone5–6 SAMECSV/13Teatri/20proprietà/provenance+ACK/8Cinema. Nessuna accettazione funzionale ancora dedotta.


### Issuer:1errore client, soggetto non corrispondente; correlazione locale da verificare — 2026-10-19,12:15 Europe/Rome

Reader issuer completato, generazione verificata,3GET Engine, zero OAuth/IAM admin/processi/credenziali/journalwrites. Nella finestra1792404450→1792404520: clientErrorCount1, clientErrorsWithoutExactSubject1, nessun matchedErrorClass, matchingIssuerEventProvenfalse, specificIssuerReasonProvenfalse. Non attribuire questo evento al HUMAN217 dalla sola coincidenza client/tempo. Nessuna ripresa o nuovo login autorizzato; tecniche8/8, funzionali4/6, MCP non sostituito.

Preparata correlazione distinta `scripts/read-mcp-human-issuer-correlation.py`: stessa capsula/selection/finestra/container e3GET; apre solo il journal HUMAN privato esatto già vincolato e richiede BLOCKED/REFRESH/217 con motivo generico invariato. Decodifica in memoria gli eventuali claim JWT del refresh conservato, solo se issuer/sub/client/typ corrispondono; jti/session-id servono esclusivamente per uguaglianza locale con l'evento issuer. Nessun identificativo/token/hash delle credenziali viene stampato o trasmesso; nessuna firma del refresh JWT è provata né questi claim conferiscono autenticazione o autorità. Soggetto concreto diverso non può essere sovrascritto da un match token/session-id. Token opaco, claim non corrispondenti o id assenti producono nessuna correlazione. Espone anche le sole classi error/reason whitelisted degli eventi client non attribuiti, dichiarando espressamente che non provano la causa del HUMAN.8test passati anche nella CI39236491589: match subjectnull+id, negazione soggetto diverso, wrong/opaque JWT, journaldrift, redazione, framing e superficie GET. Nessun login, refresh, scrittura o replay consentito dal reader.


### STOP confermato: HUMAN BLOCKED dopo REFRESH,217/256; issuer da diagnosticare — 2026-10-19,12:12 Europe/Rome

Tecniche8/8, funzionali4/6. Reader protetto mbbleugm restituito dall'operatore: complete/readOnlytrue, nessuno dei9artefatti candidate-review/execution-plan/review/decision/human/authority/issuance/recovery/update-result presente; runtimeclaim consumato e runtimeCompletionfalse. HUMAN stateBLOCKED, operationREFRESH, reasonHUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN, tentativi217/256 (39residui), bearer precedente scaduto/accessExpiresAt1792402605, refreshAt1792402545, lastObservedAt1792404489.1316833. Finestra originale1792405963 ancora aperta sia wall che monotonic; nessun nextAttemptAt. Zero OAuth/engine/owner/database o journalwrites del reader; nessun bearer/chiave aperto, nessun valore/hash delle credenziali stampato.

Questo è un blocco permanente/sconosciuto, NON una pausa transitoria da ritentare automaticamente. La risposta issuer dettagliata non è persistita dal helper; non attribuire invalid_grant, revoca o idle timeout dal solo codice generico. Non ritentare refresh, non riportare READY il journal, non rigiocare launcher/bootstrap, non resettare claim o budget e non avviare nuovo login/finestra. L'aggiornamento MCP resta non eseguito; policy47 e grant finito già pubblicati non vanno ripetuti.

Preparata diagnosi distinta `scripts/read-mcp-human-issuer-stop.py`: risolve il container IAM e socket esclusivamente dal profilo originale sigillato della capsula mbbleugm;3GET Engine totali (generazione prima/dopo, logs), finestra1792404450→1792404520 (70secondi), tail≤2000, output log≤4MiB, timeout complessivo60secondi. Nessun exec, IAM admin o OAuth; non apre journal/token HUMAN. Filtra REFRESH_TOKEN_ERROR per client ouf-human-admin, realm e soggetto esatti; espone solo whitelist error/reason, conteggi e provenienza del matching. Log grezzi, ID token, altri soggetti, dettagli sconosciuti non sono stampati. Evento corrispondente e motivo specifico sono prove separate; nessun evento non significa issuer sano né autorizza nuovo login.5test passati anche nella CI39236073207 (framing Docker, subject/client negativi, whitelist/redazione, superficie3GET). Questa diagnosi non modifica il blocco e non concede autorità di recupero.


### STOP mbbleugm: preparazione immagine completata, sessione HUMAN da riconciliare — 2026-10-19,12:08 Europe/Rome

Checkpoint corrente: tecniche8/8, funzionali4/6. Il launcher MCP distinto è stato eseguito UNA VOLTA. Preparazione completata nel contesto `/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-mbbleugm`, packageHash f4552fa8894c2050e67f025df9d6c14eb02b04a7c6d18d4a9019994d8bda1de9, sourceClosureHash6e2a0e4ec523c7de9c337ce71f18e3b1983205738a2aaccecf2c97319bb313ee. Sorgente MCP1f2c28d verificata; immagine containerd derivata sha256:a0a6f9562ba0b28ba3fef2b3a78bf46e90d9e14c99448d413bacf5d5cb75f182, stessi config/layer originali, imageRebuiltfalse. Prima del bootstrap contatore216/256 e runtimeAuthorityIssuedfalse.

Bootstrap ha attraversato VERIFY_SOURCE_CLOSURE poi EXISTING_HUMAN_SESSION ed è terminato HumanSessionPaused/STOP_RECONCILE. Il flusso non ha raggiunto compilazione piano, review HUMAN, emissione authority o effetti sul MCP. Il motivo esatto e il contatore DOPO l'eventuale refresh restano da leggere: non inferire revoca, scadenza, throttle o errore transitorio dalla sola classe. Non rilanciare preparazione/bootstrap/launcher; claim preparazione e runtime conservati. Non avviare login o nuova finestra, non azzerare il cumulativo.

Reader distinto `scripts/read-mcp-ingestion-transport-stop.py`: verifica esatta capsula mbbleugm, package/case/sorgenti e claim; inventaria senza aprire authority/chiavi; solo lettura del journal HUMAN già vincolato, senza aprire bearer o stampare valori/hash delle credenziali. Espone solo enum/codice presente nei sorgenti sigillati, contatore, tempi e artefatti. Zero OAuth/owner/engine/database/scritture journal. Nessuna chiamata a main storico/install/readback o refresh.5test di proiezione/negazione/redazione passati in locale e nella CI39235610852. PET originali consultati: Authorization1.5§109.6; policy resilienzav3§§3–7 (ambiguità/permanenti non ritentabili). Il reader non concede autorità di ripresa. Solo dopo il suo risultato scegliere un recupero finito e una nuova review nativa se consentiti, senza replay degli effetti o delle richieste rotanti ambigue.


### Policy47 pubblicata; correzione trasporto MCP qualificata, applicazione HUMAN pendente — 2026-10-19,12:06 Europe/Rome

Questo è il checkpoint corrente; le sezioni successive conservano la cronologia. Tecniche **8/8**, funzionali **4/6**. La proposta finita `c94ca071-b465-47e6-a01d-06cc7984785a` è PUBLISHED/revisione1; lettura GRANTS indipendente ouf-admin: policy `ouf-lab-authorization:47`, hash `sha256:8aa234827edee9271548830a518407309d7042303a634a127ef46ec9e2371f00`,81grant del soggetto/pagina completa, grant esatto ingestion.operations.read per teatri-csv-6609b245 valido09:34:16Z19ottobre→09:34:16Z20ottobre. Non riproporre o riconfermare questo grant.

La prima lettura MCP ingestion.status, dopo la pubblicazione, ha risposto400 permanente con payload Gateway vuoto: non ripetuta. Diagnosi sul codice installato a79b139: mancava il dispatch dei due capability-id ingestion.status/history ai percorsi Gateway dedicati POST /internal/capabilities/v1/execute/ouf.ingestion.status|history. Le80rotte Gateway già contengono i percorsi; nessuna modifica Gateway richiesta. PR MCP75 DRAFT, sorgente `1f2c28d7abadae78680b040ba7b58be62ef85ee9`, derivata dall'esatto installato a79b139 (non da main, che non contiene i tool revisione fonte). Qualifica mirata39232077313: vecchio adattatore riproduce400, corretto passa;26test/subtest con race, scope/tenant/soggetto/fonte negativi conservati.

Pacchetto MCP già costruito e scansito, run39232718756 PASS; stage `/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-ingestion-read-transport-39232718756`, qualified-package.json SHA256 c685d0c26e7fcdf4936c5d86341a79f23310b09e40b02441b870ff89333a0ce6, configurazione immagine sha256:bf40c534c96221e5cc989871a13465565942e86556751410ba6812a977e40631; il preparatore verifica config/layer byte per byte e deriva l'identità manifest del containerd conservato. Zero effetti sui servizi in questa preparazione CI.

Azione infrastrutturale distinta, nuovo codice `f57728d2aa68dc9cf58b86a7f3fad04b45df82dc`: namespace tools.ingestion_read_transport_update, closure185moduli, solo11stage MCP, zero migrazioni/SQL/scritture Gateway/metadati/policy/grant. Conserva configurazione, ambiente, mount, IP/MAC/restart policy del MCP; vecchio MCP fermo e restart disabilitato, Onboarding/UDP/Ingestion e altri servizi conservati verificati per generazione. Breve indisponibilità MCP esplicitata nella review. Qualifica39234772487 PASS:120test complessivi, firme Ed25519 reali dei due ruoli installer, publisher privato reale, journal durevole e blocco replay/effetto ambiguo;4test aggiuntivi del launcher passano in locale e nella CI39235070853. Nessuna autorità runtime ancora emessa e nessuna sostituzione eseguita.

Launcher `scripts/launch-mcp-ingestion-read-transport-20261019.sh` con8download autenticati/hash prima di sudo e ricontrollati da root, portable gh prima del fallback. Un solo lancio: serve nuova frase nativa APPROVO + hash della review corrente. Non riusa la decisione amministrativa completata. Preparatore richiede≥900secondi della finestra HUMAN originale, cioè avvio prima2026-10-19T10:17:43Z; scadenza originale10:32:43Z (12:32:43Europe/Rome). Cumulativo OAuth corrente≥216 e≤256, nessun nuovo login/reset/proroga. STOP o interruzione richiedono riconciliazione, mai rilancio automatico.

Installazione/readback uow4n8lp e amministrazione1lxoo2ws sono storia acquisita: nessun loro main, SQL, effetto o readback è rilanciato. Dopo ricevuta del nuovo aggiornamento: verificare tool status/history con ouf-admin e scope effettivo ChatGPT; leggere revisione/attivazione correnti prima del gate HUMAN di attivazione separato. Revisione c9fec43c-19b3-4ffb-9111-781bc347c5b0 già APPROVED/lock3: non ricreare/ripetere approvazione. Milestone5–6 ancora richiedono seconda acquisizione SAMECSV,13Teatri identici/20proprietà, provenienza/ACK delle due acquisizioni e8Cinema conservati. La sola policy47 o il pacchetto non provano accettazione funzionale.


### Azione amministrativa completata; grant finito in THS — 2026-10-19,11:33 Europe/Rome

Tecniche **8/8**, funzionali **4/6**. Ricevuta target `ADMINISTRATIVE_READBACK_COMPLETE` nella capsula `/etc/ouf/deploy-snapshots/ingestion-read-authorization-execution-1lxoo2ws`: policy `ouf-lab-authorization:46`, SHA256 `41b6aa5970c59b86b8d8f571d1e47989d7eaecfd05f9ce29d2b0c1e60f4df84f`, owner policy/roles/scopes riconciliati; grant e assegnazioni conservati, zero nuovi grant, ruoli invariati, zero effetti infrastrutturali e nessuna attivazione della fonte. OAuth cumulativo216/256, nessun login/budget nuovo. Questa azione è completata: non ripetere preparazione, launcher o readback amministrativo per riconoscerla; installazione/readback uow4n8lp restano acquisiti e non vanno ripetuti.

Letture MCP indipendenti con ouf-admin confermano policy46/hash esatto,2ruoli/2assegnazioni e80grant configurati del soggetto (pagina completa, non conteggio totale104 della policy). Nessun grant ingestion.operations.read già configurato per quel soggetto. Scope del token ChatGPT nuovo ancora NON provato; una proposta riuscita non lo dimostra.

Creata una sola proposta nativa `c94ca071-b465-47e6-a01d-06cc7984785a`, revisione0, PENDING: grant diretto `grant-ingestion-operations-read-teatri-csv-6609b245-20261019-24h`, capability ingestion.operations.read, tenant ouf-lab, soggetto b93d8cf6-cd14-4ee6-91d7-84cd76c4f500, resourceType operational, attributi module=INGESTION/sourceRef=teatri-csv-6609b245, solo TENANT_OPERATIONAL. Validità2026-10-19T09:34:16Z→2026-10-20T09:34:16Z, esattamente24ore; non eredita la scadenza2036 delle assegnazioni. [Conferma diretta THS](https://api.ouf-lab.it/trusted-human/authorization/?proposal=c94ca071-b465-47e6-a01d-06cc7984785a); proposta da decidere entro2026-10-19T09:49:23.832698Z (11:49:23italiane). MCP prepara, non approva o pubblica. Nessun nuovo grant ancora pubblicato al momento di questa ricevuta.

Dopo decisione HUMAN: riconciliare questa esatta proposta con authorization.proposal.read, senza crearne un'altra; verificare grant/policy finali e il token/scope ChatGPT tramite i tool owner. Poi leggere Ingestion status/history e lo stato della fonte prima dell'attivazione HUMAN separata. Non ripetere review della revisione c9fec43c già APPROVED/lock3; l'attivazione può avviare acquisizione secondo lo scheduler conservato. Milestone5 richiede la seconda acquisizione controllata dello stesso CSV senza duplicare13Teatri; milestone6 richiede provenance/ACK delle due acquisizioni,20proprietà e8Cinema preservati. Nessun avanzamento funzionale è dedotto dalla sola amministrazione dei permessi.

### Publisher amministrativo corretto; prosecuzione governata distinta — 2026-10-19

La ricevuta del reader ojz9hai3 prova bootstrap/piano/primitivi owner/hash eseguibili+stdlib/finestre pubbliche validi,181moduli e nessun piano/review/authority/issuance/journal amministrativo presente. Nessun token aperto o contatore corrente letto. Nel codice consegnato il publisher rollout `tools.linked_property_rollout.preparation.publish_json` rifiuta `authorization-plan.json` e `administrative-result.json` con ValueError(EXACT_ROLLOUT_DOCUMENT_REQUIRED), prima delle scritture. I test precedenti lo simulavano e non verificavano questo confine.12 nuove prove con i helper reali riproducono il rifiuto e verificano piano/review/risultato reali, custodia, O_EXCL, readback e flusso fino al risultato con risposte HUMAN/owner/firme simulate.

La correzione usa un publisher privato separato per soli3 nomi/schema; non amplia la whitelist rollout o le authority. Sorgente bc6fd07e65589b59408cf2a0fb2a646d8d8e0812. La nuova preparazione verifica package/closure/claim consumati di ojz9hai3 e riproduce sul sorgente congelato solo la prima guardia letterale del publisher, senza chiamare il writer. Se appaiono effetti o authority, si ferma. Conserva dyvd8zal, ojz9hai3 e tutti i claim, crea un solo claim distinto di riparazione, riusa piano9216f0ba e legge il cumulativo HUMAN effettivo (almeno212, massimo256), senza login, finestra o budget nuovi. Nuova closure181moduli, baseline owner completa riletta e APPROVO nativo prima delle mutazioni; marker di fase sicuri. Tecniche8/8, funzionali4/6; uow4n8lp non ripetuto. Qualifica acquisita:109 test sorgente/owner/firme/sessione nella run39230290934 e4 test consegna nella run39230492990, tutti PASS. Delivery immutabile3f8321f5a7490a43f5aa0481c975b3330b5ef6bf. Prova della guardia congelata sul target ed esito dell'azione corretta ancora da acquisire. Vedi [rilascio](../releases/INGESTION_ADMINISTRATIVE_PUBLISHER_REPAIR_20261019.md).


Qualifica del reader:8 test PASS nella [run39229041547](https://github.com/GioNob/ouf-deploy/actions/runs/39229041547), job117982270177. Sorgente3a2de521bdb0467791954bd56d74b38276e2ea17; SHA2562a4d855d4a034673c3ec7bca933bb246a7a4ca38534597e7c3eb12ddb4a07074. Fixture con loader reale181moduli, hash/bootstrap originali e fonti applicative sintetiche; nessuna prova target nuova. Il reader non ricostruisce la cronologia di rete e non ri-esegue refresh o chiamate owner: se tutti i controlli puri passano, il punto esatto del fallimento resta non provato. Ricevuta target ancora da acquisire.

### ojz9hai3: preparazione riuscita, nuovo STOP da riconciliare — 2026-10-19,11:12 Europe/Rome

La ricevuta operatore prova la nuova capsula ojz9hai3, package b2b01238a1c760a5e0334f0ed7770b4d03746ee9fdfc271a96798ff282327e84, closure4152ca6bcd44e745ea3a03dc884b67a948d1f91536a80c752a82c27afd9fc657, piano9216f0ba e contatore212 alla preparazione. Segue STOP_RECONCILE/ValueError redatto: fase, contatore successivo ed eventuali effetti non sono provati. Non rilanciare launcher58961af, preparazione, preflight o login; conservare tutti i claim. Tecniche8/8, funzionali4/6; uow4n8lp resta completato e non va ripetuto.

Diagnosi distinta `scripts/read-ingestion-existing-session-stop.py`: verifica solo questa capsula/piano, ricostruisce il prefisso originale bootstrap prima della riga52 (claim runtime), poi controlli puri su riferimenti del piano, primitivi owner, hash eseguibili/stdlib e metadati pubblici dell'autorità. Audit nega scritture, socket, processi, credenziali HUMAN e chiavi private. Nessun refresh, OAuth, IAM, owner request o main esecutivo. Nessuna esecuzione OpenSSL/version viene tentata; quella verifica resta esplicitamente non provata. L'inventario rileva presenza degli artefatti e stati del journal senza aprire authority/decisioni. Qualifica CI acquisita; ricevuta diagnostica target ancora da acquisire. Il solo numero di test precedenti non prova l'azione amministrativa riuscita.

Qualifica della continuazione:97 test owner/firme/sessione PASS in CI39227850265;4 test della consegna immutabile PASS in CI39228097092. Launcher58961af73532eae5a1b504c934c0931a76a21a99, SHA2563d4e7c6b31cbd83b3835e52618e2f97ad80c7b36b9323ccd42178bcfd014ab3a. Esecuzione target della continuazione ancora pendente al gate nativo APPROVO. Vedi [rilascio](../releases/INGESTION_EXISTING_SESSION_ADMINISTRATION_20261019.md).

### Preflight target acquisito; continuazione amministrativa distinta — 2026-10-19

Tecniche **8/8**, funzionali **4/6**. L'operatore ha restituito il preflight riuscito in `/etc/ouf/deploy-snapshots/ingestion-read-preflight-0jvu7qzh`: piano SHA256 `9216f0bae1056f1a6f8c8bf8627915d9a70f126e476fe6700e65f0d58112b53b`, policy `ouf-lab-authorization:45`,104 grant conservati e2 ruoli. Una registrazione, un descrittore, una creazione scope e un binding ChatGPT da eseguire; nessuna authority emessa. Refresh nativo210→212/256, medesima finestra fino a2026-10-19T10:32:43Z. Il vecchio STOP non è riprodotto; la sua causa esatta resta indeterminata. Non ripetere preflight, login, launcher consumati o installazione/readback uow4n8lp.

Lettura MCP con ouf-admin: revisione `c9fec43c-19b3-4ffb-9111-781bc347c5b0` APPROVED/lock3; challenge CONFIRMED storico, activation NOT_STARTED/0tentativi. Non ricreare la revisione o la review della fonte. La continuazione sigilla una nuova entry e un nuovo case nella closure181moduli, mantiene tutti i claim predecessori e usa un claim figlio O_EXCL distinto. Rilegge il piano verificato e confronta integralmente la baseline prima della review nativa APPROVO; nessun nuovo login o recupero IAM. Eventuali drift/scadenza/esiti incerti fermano il flusso per riconciliazione. Pubblicazione di grant, attivazione e acquisizione restano gate successivi. Preparazione/esecuzione della continuazione sul target ancora da acquisire; test CI non sostituiscono tale ricevuta.

### Diagnosi amministrativa acquisita — 2026-10-19,10:43 Europe/Rome

La preparazione è riuscita (181 moduli); login HUMAN/IAM già eseguiti; piano autorizzativo, review APPROVO, authority e journal degli effetti assenti nella capsula dyvd8zal. Lo STOP è dopo il login e prima del piano; nessun rilancio del vecchio launcher. Il preflight vincolato alla sessione esistente passa12 test CI39226412775, ma non è ancora eseguito sul target. Una sola invocazione refresh nella finestra già approvata, cumulativo256 preservato;8GET owner,1ROLES MCP,8GET IAM massimi; nessuna mutazione amministrativa, firma o nuovo login. Tecniche8/8, funzionali4/6. Installazione/readback uow4n8lp acquisiti e non ripetuti. Vedi evidence/ingestion-administrative-stopped-context-dyvd8zal-20261019.json.



### STOP amministrativo da riconciliare — 2026-10-19,10:33 Europe/Rome

Tecniche8/8, funzionali4/6. L'operatore ha riportato `STOP_RECONCILE / ValueError / PRIVATE_DETAILS_REDACTED` dopo il launcher amministrativo. La fase e gli eventuali effetti parziali restano sconosciuti; non dedurre assenza di effetti o autorizzare un rilancio. Installazione/readback uow4n8lp restano acquisiti.

La diagnosi separata [read-ingestion-administration-stop.py](https://github.com/GioNob/ouf-deploy/blob/2d5739281ab33f024a560e340838c75f58d629e8/scripts/read-ingestion-administration-stop.py) ha superato8 test CI nella [run39224438289](https://github.com/GioNob/ouf-deploy/actions/runs/39224438289), job117967183765. SHA256069c189f29344ad4e508c0a78db246abf07b2abd1befaa4c99e3fe6f0fc35134. Legge solo il prefisso verificato precedente al primo claim e i metadati/journal della sola azione amministrativa; audit indipendente nega scritture, rete e processi esterni. Non chiama installer/runtime/preparer main, non apre credenziali HUMAN, non ripete readback, non riapre budget o authority. Il read sul target è ancora da acquisire.


Consegna finale qualificata: [run39223108393](https://github.com/GioNob/ouf-deploy/actions/runs/39223108393), job117962847831,6 test PASS (3 regressioni shim storico e3 controlli del nuovo launcher). Launcher immutabile: [b836891c7c899c549482f81945046ad592b92f6f](https://github.com/GioNob/ouf-deploy/blob/b836891c7c899c549482f81945046ad592b92f6f/scripts/launch-ingestion-human-administration-20261019.sh), SHA256 `636330a0b5d54dad590969d2ada8799bdb47b49c02aa8af297d65da199da16cd`. La qualifica conferma manifest, hash preparer e STOP prima di qualsiasi lettura privata su codice alterato. Il canary delle eccezioni resta oscurato. **La preparazione root e l'azione sul target attendono ancora il terminale HUMAN.**


### Azione amministrativa HUMAN distinta — 2026-10-19, preparata per avvio nativo

Tecniche **8/8**, funzionali **4/6**. Il codice standalone `1e1a9f9eddca649e64db36fe018f59f2f15a2105` ha superato73 test nella run [39222837925](https://github.com/GioNob/ouf-deploy/actions/runs/39222837925), con firme Ed25519 reali/journal privati e fixture HTTP/IAM esplicite. Il job117962337255 ha predisposto10 file pubblici qualificati sul server; nessun input privato letto, login, authority o effetto amministrativo eseguito.

Lo stage è `/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-ingestion-read-administrative-code-39222837925`; manifest SHA256 `633bbf2a17dc0395dd362694833b2264e7aef9501a06d5ce3fc54a4569e879c2`. Il nuovo launcher `scripts/launch-ingestion-human-administration-20261019.sh` verifica gli hash prima del processo root. La preparazione privata verifica solo la storia/frozen custody già acquisita, costruisce una nuova closure isolata e non richiama installazione o readback uow4n8lp. Dopo PREPARED, la fase nativa verifica la sessione IAM e HUMAN; eventuale RIAPRO LOGIN conserva il cumulativo256, poi APPROVO vincola il piano corrente a massimo900secondi.

Perimetro: registrazione `ingestion.operations.read`, aggiunta del descrittore nella policy immutabile e relativo scope OAuth del client ChatGPT. Ruoli, assegnazioni e grant rimangono invariati. Il successivo grant temporaneo sulla fonte `teatri-csv-6609b245` richiede una proposta e decisione THS distinte. Nessuna attivazione della revisione approvata, acquisizione, modifica infrastrutturale o retry job. Dopo STOP/interruzione: conservare il contesto e riconciliare, senza rilanciare il launcher.

La preparazione root e l'esecuzione sul target restano **NON ESEGUITE**: dal CLOUD manca un terminale operatore autenticato per i gate nativi. CI e staging non dimostrano pubblicazione della capability o token aggiornati. Tappe5–6 ancora aperte.


Technical8/8; functional4/6. User confirmed source approval; direct ouf-admin revision.read and a later owner read independently prove c9fec43c-19b3-4ffb-9111-781bc347c5b0 APPROVED, lock3, challenge9bca610c… CONFIRMED, hashb13c5fe2… unchanged. The latter read reports challengeExpired=true while approval remains APPROVED/CONFIRMED; do not interpret historical challenge expiry as loss of the recorded decision or recreate the source review. Activation/readiness remain NOT_STARTED/0, compatibility unobserved; no publication or second acquisition.

[Current evidence and remaining native boundary](../evidence/source-approved-ingestion-read-qualified-20261019.json). A new narrow authorization profile is implemented in source64554957a6b1f944c654064f5acbc48e94ed9db8 and passes CI39220098048/job117953125583:50tests (22existing authorization +6durable observations +11revision +11new profile). Tests include real signed AggregateAction/private journals, lost-response reconciliation, revocation, no duplicate draft/dispatch and exact Java owner serialization. HTTP/IAM are explicit fixtures; no target policy modification is claimed.

Profile ouf.ingestion-operational-read-authorization.v1 plans only registration/immutable policy addition for ingestion.operations.read and its exact ChatGPT scope binding. It preserves every grant, role, assignment, session and unrelated OAuth binding. The source ID is explicit and validated; the plan binds operational/INGESTION/sourceRef with TENANT_OPERATIONAL. No role permission is added: a separate finite direct human grant must later be proposed and confirmed in THS, so this read privilege does not silently inherit the existing admin assignment's long expiry. [Design and limits](INGESTION_OPERATIONAL_READ_AUTHORIZATION_20261019.md).

Still required before native execution: new full-current owner/IAM observations and validated installation bindings, a separate finite administrative review/authority and completed private capsule/delivery. No operator launcher is released yet and no new login or authority has been opened. There is no MCP capability-registration tool; existing native HUMAN administrative APIs are the required path. Source approval does not authorize this separate policy change. Preserve expired uow4n8lp authority and successful installation/readback; do not replay them, alter frozen modules, write policy through SQL, use raw RPC or switch accounts. After registration/policy/scope reconciliation, prepare the finite scoped grant and verify actual fresh scope/status/history before the separate source activation. Functional5/6 remain pending.

Original PET sections actually consulted for this decision: Matrix1.7 §1, Authorization1.5 §§20–22/109.6, Onboarding1.6 §103 and Ingestion1.3 §46. No subagent or automation.

## Historical checkpoint — budget diagnosed; native source review prepared, 2026-10-19

Technical8/8; functional4/6. [Qualified current diagnosis and native receipts](../evidence/cloud-admission-resolution-and-source-review-20261019.json). CI39218769408:7testsPASS including real PostgreSQL17 read-only SELECT fixture; target job117948975848 completes2READ ONLY metadata sessions through existing runner Docker access. No sudo, credential/token/HUMAN-journal reads, database writes or budget reset.

The exact MCP cause is now measured:07:41UTC window had3consumed calls,0reserved calls,0object debt,20547bytes and0objects; the fourth admission exceeded the existing3-call cap. That window expired naturally at07:42UTC. The earlier smaller-envelope concern is not the cause of this STOP and no MCP runtime code change was made. Following the user's explicit diagnosis/resolution continuation, exact original-command reconciliation returned ABSENT; one preparation in a later natural server window succeeded. No automatic retry, new command key or HUMAN budget renewal.

Native revision is IN_REVIEW: source teatri-csv-6609b245, new version c9fec43c-19b3-4ffb-9111-781bc347c5b0, lock2, configurationHash sha256:b13c5fe234168bdb8b315087917bccfe428ceaa8e136ed1c0f56f5bf43deed3d. Original commandKey linked-property-v1:teatri-csv-6609b245:9860853e remains bound to parent9860853e-e8f3-4b93-b9d2-03521a039962/hashae7f46b4… and all20explicit SINGLE/EXACT_TYPEDv1/SOURCE_INTERVAL changes. Independent revision.read returns the same native review. This proves actual revision read/prepare authorization for ouf-admin, not every unrelated scope.

HUMAN challenge9bca610c-aa24-4be3-ac29-0e5454e9d877 expires2026-10-19T08:03:31.199Z (10:03:31Europe/Rome). [Native review](https://api.ouf-lab.it/trusted-human/onboarding/?challenge=9bca610c-aa24-4be3-ac29-0e5454e9d877). Installed THS distinguishes “Approva la configurazione” from “Verifica e attiva la fonte approvata”. Request approval of the configuration only; keep activation suspended pending restored governed Ingestion visibility. Approval is not publication; activation may start a new acquisition with retained scheduler settings. Never recreate or silently renew an expired/decided review: reconcile this same command/version first.

The earlier permission-read connector diagnosis is corrected: the assistant supplied limit with viewROLES, which the native schema forbids. Correct viewROLES plus ouf-admin link_id succeeds; the complete GRANTS page also succeeds on policy45,80grants,nextAfter=null. No connector schema defect is proven. Exact target metadata proves ingestion.operations.read registration0, active descriptor0, nominal grants0. A single scoped24-hour grant proposal returned400ONB_BAD_REQUEST/invalid grant reference, without a proposal ID; do not retry it. The missing descriptor requires native authenticated HUMAN registration and immutable policy addition before a grant proposal can work; fresh IAM scopes/bindings must also be verified. There is no MCP registration tool. Existing native administrative API supports the operation; do not bypass it via DB or raw RPC, add wildcard grants, change accounts, relabel another capability or reuse expired runtime authority.

uow4n8lp installation/readback remain completed and unrepeated. Source profile publication, second acquisition/ACK/provenance and functional5/6 remain unproven. The13Teatri/20properties and8Cinema baseline remains the prior fresh serving proof; no new identity decision, source activation or job replay was performed.

## Historical checkpoint — refreshed tools verified; native preparation blocked before dispatch, 2026-10-19

Technical8/8; functional4/6. This supersedes the missing-tool discovery boundary below. Both revision tools are exposed among26 tools. Direct ouf-admin revision.read succeeds: same ACTIVE parent9860853e-e8f3-4b93-b9d2-03521a039962, lock4, unchanged configuration hash and all20 property rules. MCP is HEALTHY. Fresh serving reads confirm the same13 ACTIVE Teatri with20 properties and all8 original ACTIVE Cinema with2 properties, complete pages. The attached baseline matches e63df67e… and all323 checksums PASS; consulted original Matrix1.7 §1, Onboarding1.6 §§91.2/103/106, Authorization1.5 §109.6 and MCP1.4 §§10.1–12/error taxonomy.

One native revision.prepare was attempted with the explicit20 SINGLE/EXACT_TYPED v1/SOURCE_INTERVAL rules and commandKey `linked-property-v1:teatri-csv-6609b245:9860853e`. It returned `orchestration budget exhausted`, retryable=false. Exact revision.read reconciliation returns ABSENT/newCommandAuthorized=false: no owner revision/challenge was created. Do not retry automatically, change key/account, reset budgets or route commands around admission. This response does not prove all fresh token scopes. Installation and completed readback uow4n8lp were not repeated.

Independent ouf.ingestion.status for this source returned authorization denied/retryable=false. No account bypass or grant change. Permission catalogue inspection is blocked by connector routing/schema: the schema omits link_id, omission is rejected by the connector, and the exact ouf-admin link_id is rejected by argument oneOf validation. Neither failure proves which grant/scope is missing.

Installed MCP source a79b139c… raises the budget error in Reserve before Dispatch. Its business window shares principal/tenant/manifest identity and derives ceilings from each invocation's maximum times3; a revision reserves1 object/65536bytes, so different-size tool traffic can conflict with its smaller ceiling. Exact live counters and exhausted dimension were not read; do not claim a measured root cause or a HUMAN OAuth-budget exhaustion. Original MCP1.4 distinguishes orchestration admission and runtime human authority and marks this exhaustion non-retryable.

Next: bounded approved admission evidence (window counters/reservations/debt and attempt context), plus native owner evidence for ingestion.operations.read and connector account-schema reconciliation. No sudo/readback/install replay is required merely to repeat completed infrastructure proof. Preserve the exact source/parent/command and reconcile before any governed continuation. Only after a usable native review and restored verification visibility may HUMAN approve/activate; activation may start the controlled second acquisition using retained scheduler settings. Profile publication, second acquisition/ACK/provenance and functional5/6 remain unproven. No source activation, historical replay, identity decision, automation or subagent.

Evidence: [fresh discovery, attempted command and reconciled STOP](../evidence/source-revision-cloud-admission-stop-20261019.json).

## Current checkpoint — independent post-install target readback PASS, 2026-10-19

Technical8/8; functional4/6. Operator supplied qualified root readback complete for uow4n8lp: all stages applied, journal57,81frozen files, Onboarding34 with application-owned append-only revision table, UDP36/MCP migrations unchanged, readinessOnboarding200/MCP204,80routes preserving78original+2additions, exact0440MCP metadata, stopped retained old containers, unchanged UDP/Ingestion. New authority not issued/accepted; old authority expired. Backup current custody/size/receipt proven, current full payload checksum explicitly NOT proven. A NEW direct ouf-admin owner read confirms Teatri ACTIVE/lock4/config/publication unchanged. Current chat lacks installed source.onboarding.revision.read/prepare in its exposed tool inventory. Refresh client metadata before further revision actions; no install replay or fresh runtime authority. Fresh scopes/profile publication/controlled second acquisition/combined verification remain outstanding. [Target receipt](../evidence/source-revision-postinstallation-target-20261019.json), [current cloud handoff and next native read](handoffs/OUF_CLOUD_POSTINSTALL_HANDOFF_20261019.md).

## Historical checkpoint — completed update readback delivery qualified, 2026-10-19

Technical8/8; functional4/6. Native uow4n8lp completion and independently read THS policy45 remain the latest target evidence. The protected, no-replay diagnostic is now qualified: final root CI39215600588/job117938599307,12tests PASS; immutable reader and launcher blobs independently matched. It verifies81sources, original input bindings, completed journal/child claim,0440MCP metadata, current/retired generations, readiness, exact additive routes and three READ ONLY migration queries. No bearer/HUMAN journal/data dump is opened; backup current full checksum is explicitly unproven. Direct ouf-admin MCP health is HEALTHY, with no partial/actionRequired flag. Physical sudo target readback is pending because protected references are unavailable to this cloud session. No new OUF login or executor replay. Fresh client scopes, governed generic profile publication and functional5/6 remain outstanding. [Qualification and exact one-use read command](../releases/SOURCE_REVISION_COMPLETED_READ_20261019.md), [evidence](../evidence/source-revision-completed-read-qualified-20261019.json).

## Historical checkpoint — native update complete, Onboarding V34, 2026-10-19

Technical8/8; functional4/6. Native execution `uow4n8lp` returned complete, applicationReady, Onboarding migration34 and journalVersion57. Authorization receipt reconciles owner policy, roles and scopes on `ouf-lab-authorization:45`, preserving existing grants and role assignments; direct MCP independently confirmed its THS proposal PUBLISHED. This is execution-flow evidence, with independent protected infrastructure readback still outstanding. Fresh client token scopes remain unproven, release acceptance is false, generic profile remains unpublished, source activation and semantic dispatch are unproven, and no jobs were retried. Preserve the successful context and all claims/journals; do not rerun the executor. Next: current-state readback, native client-scope verification, governed profile publication, then functional5 controlled same-CSV acquisition and functional6 combined verification preserving8Cinema and existing identity/property evidence. [Exact native receipt](../evidence/source-revision-native-update-completed-20261019.json).

## Historical checkpoint — native THS role published, 2026-10-19

Technical8/8; functional4/6. The operator confirmed the native THS publication; one direct ouf-admin `authorization.proposal.read` independently returned proposal `f25d9028-b81f-4eec-a567-43fa160f869b`, revision1, `PUBLISHED`, finalPolicyRef `ouf-lab-authorization:45`. Prior Onboarding readiness WAIT and role PENDING observations are superseded. The original native process must consume this outcome and emit its final result. No independent infrastructure readback or final execution receipt has yet been received. Role policy publication does not prove generic ingestion-profile publication or functional stages5/6. Keep the original process open; after STOP preserve and reconcile, with no replay. [Bounded receipt](../evidence/source-revision-native-role-published-20261019.json).

## Historical checkpoint — governed capsule complete; APPROVO accepted; custody STOP

## Current checkpoint — blocked REFRESH189 reconciled, 2026-10-19

Technical8/8; functional4/6. Protected target read proves inmfuoj2 nine-file closure9a829a8a70ca4c86d0653119ebe7737ba67a7af37347443d276a90b3d301c0df and no authority/login artifacts. HUMAN BLOCKED/REFRESH189/256,67 attempts remain; the failed refresh is not replayable and revocation is not proven by its generic reason. Both old successor claims absent; original custody capsule/all81files/kfy inputs and consumed kcw IAM fence preserved. The two-module explicit private successor reusing the native RIAPRO LOGIN/APPROVO/THS path passed144 tests including immutable delivery (runs39212047375/39212428373), with source-only staging and no target execution; physical sudo/conditional IAM password/RIAPRO LOGIN/fresh APPROVO/THS remain native gates. No HUMAN/session/window/budget reset by preparation. [Target proof](../evidence/source-revision-human-blocked-read-target-20261019.json), [recovery qualification](../releases/SOURCE_REVISION_HUMAN_RECOVERY_20261019.md).


## Current checkpoint — IAM reconciled, HUMAN OAuth STOP, 2026-10-19

Technical8/8; functional4/6. The operator's protected read proved kcw73ask nine-file closure153581a3f2294823d08c3668fb98433d49a34dd51a95056a24111379a4d07e9f, no authority/login artifacts, full81-file verification and HUMAN READY188/256 at observation. One IAM admin login/GET succeeded; the new native process inmfuoj2 reached provider metadata then stopped on HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN. Do not replay IAM login or HUMAN refresh. Revocation is not proven by this generic reason; current counter/operation and authority absence require protected readback. [Evidence](../evidence/source-revision-custody-human-oauth-stop-20261019.json), [read-only delivery qualification](../releases/SOURCE_REVISION_CUSTODY_HUMAN_STOP_READ_20261019.md). Earlier remaining-window observations are historical. The dedicated read-only delivery passed11 root CI tests (run39210618716), including complete diagnostic/file preservation; no target execution or token request. Physical sudo readback remains required.


## Current checkpoint — custody prepared, IAM STOP, 2026-10-19

Technical8/8; functional4/6. Custody preparation completed with new case/package/closure, four read-only DB sessions and zero OAuth/runtime effects. Existing kfy inputs and candidate archives preserved. Fresh executor kcw73ask stopped on EXISTING_IAM_SESSION_EXPIRED before the existing-HUMAN refresh/new APPROVO. Do not replay preparation or old launchers. Protected inventory plus one-use native IAM resume passed18 root CI tests (run39209506145), with immutable delivery and no target execution; no authority absence is assumed until readback. [Evidence](../evidence/source-revision-custody-iam-stop-20261019.json), [reconciliation/resume](../releases/SOURCE_REVISION_CUSTODY_IAM_RESUME_20261019.md).


## Current checkpoint — protected custody read, 2026-10-19

Technical8/8; functional4/6. The operator's protected dvf517sr read proves an expired issued authority and consumed claim, journal version0/nextStage0/effects[], no backup and unchanged running applications. MCP permit/policy/profile hashes match; root:10005/0440 explains the generic private-reader stop. Preserve all bytes/permissions/claims/budgets. An explicit fresh-review custody successor passed136 tests including immutable delivery (runs39206613640/39206831574), with source-only staging and no target execution; physical sudo and a new native APPROVO remain; do not replay dvf or the governed launcher. [Evidence](../evidence/source-revision-after-approval-custody-target-20261019.json), [successor qualification record](../releases/SOURCE_REVISION_CUSTODY_CONTINUATION_20261019.md). Older readiness/checkpoints below do not supersede this stop.


**Tecniche8/8; funzionali4/6.** Capsula privata completa: ricevuta a0dd0cd5…, case00054f41…, package2c50390d…, closure be575708…. Nuovo processo dvf517sr: refresh HUMAN186→188 riuscito,68residui e finestra preservata; APPROVO55384120… accettato. STOP `PRIVATE_FILE_CUSTODY_REQUIRED`. Non inferire assenza authority o effetti dal log: lettura protetta di journal, claim, firme/authority, file vincolati e generazioni ancora necessaria. Non ripetere launcher, preparazione, refresh, APPROVO o claim. Nessun chmod/chown o guard allentato. [Ricevuta](../evidence/source-revision-after-approval-stop-20261019.json). [Riconciliazione readonly](../releases/SOURCE_REVISION_AFTER_APPROVAL_CUSTODY_READ_20261019.md): CI39204570304,7test PASS; blob e SHA verificati, lettura target ancora pendente. Nessun guard o permesso file modificato.

## Current checkpoint — READY HUMAN186 preserved; governed continuation qualified

**Tecniche8/8; funzionali4/6.** Target readonly: daxl0o6h11file conservati, closure398eec9d…, nessuna authority, ricevuta login presente. HUMAN READY sul boot corrente:186/256,70residui, finestra originaria ancora valida alla lettura, bearer scaduto e refresh token presente. [Prova](../evidence/source-revision-human-binding-target-read-20261019.json). Non ripetere IAM o RIAPRO LOGIN. Qualificati3successori espliciti Authorization/entry/login: contratto governato solo per REVISION_PROFILE, branch della sessione esistente e solo refresh nativo. Canonico nominale, CSV HumanSession, loader ed executor invariati. Capsula esclusiva vincola input kfy originali invariati, contesto11file, sessione186 e nuova case/hash/closure/piano; preparazione readonly prima del nuovo processo e di APPROVO/THS. **CI PASS:95+11+18+5+3=132test**, codice5file depositato sul runner con manifest verificato. Nessuna nuova capsula/refresh/authority eseguita sul target. [Scope, ricevute e comando immutabile](../releases/SOURCE_REVISION_GOVERNED_CONTINUATION_20261019.md).

## Current checkpoint — IAM renewed; HUMAN/Authorization binding STOP

**Tecniche8/8; funzionali4/6.** IAM_GET_RECONCILED e81file verificati prima/dopo il rinnovo; nuovo contesto daxl0o6h, provider metadata letti, RIAPRO LOGIN accettato per revisione cc9e1e66…, challenge dispositivo emessa. STOP `FINITE_NOMINAL_HUMAN_SESSION_CONTEXT_REQUIRED` prima di APPROVO. Non inferire dal log stato READY, token assenti o contatore finale: lettura protetta ancora necessaria. Non rilanciare rinnovo/preparazione o riusare il device code. Il validatore Authorization congelato ammette ancora il profilo nominale128/6scope, mentre HUMAN usa il profilo governato256/7scope: il test di questo passaggio mancava nella qualifica della consegna IAM. I guard non vengono allentati; prima si riconciliano file, claim, decisione e journal senza stampare credenziali/hash dei journal o aprire bearer. [Ricevuta](../evidence/source-revision-human-binding-stop-20261019.json). [Diagnosi e limiti](../releases/SOURCE_REVISION_HUMAN_BINDING_STOP_READ_20261019.md). Diagnosi/consegna readonly qualificata in CI39202029955:10test PASS; nessun guard runtime modificato. Lettura protetta sul target ancora pendente.

## Current checkpoint — IAM STOP reconciled; preserved executor resume qualified

**Tecniche8/8; funzionali4/6.** Ricevuta protetta target: tvc2ilnv9file, closure e93fd92c…, compilatore esatto, piano/revisione coerenti, nessun artefatto login/authority. Preparazione kfy691gh confermata dalla ricevuta90559c21… letta indipendentemente. Nessun rinnovo IAM, journal HUMAN o token aperto. [Prova target](../evidence/source-revision-iam-stop-20261019.json). Qualificata in CI39200215260:13test PASS una consegna installazione-specifica che riusa gli81file32f86add…, verifica nuovamente la closure conservata, registra un tentativo IAM unico e richiede password direttamente nel terminale kcadm; GET e generazione Keycloak devono essere riconciliati prima dei gate nativi. Nessuna nuova preparazione, reset budget o replay del vecchio contesto. [Scope](../releases/SOURCE_REVISION_IAM_RESUME_20261019.md).

## Current checkpoint — postboot successor prepared; existing IAM session expired

**Tecniche8/8; funzionali4/6.** Ricevuta operatore: kfy691gh completo, sorgente32f86add…, quattro sessioni SQL readonly, binding originale b3988d96… preservato. Passaggio al processo isolato osservato; nuovo contesto tvc2ilnv fermo su `EXISTING_IAM_SESSION_EXPIRED`, nella lettura amministrativa OAuth e prima di RIAPRO LOGIN/authority. Nessun rinnovo IAM o nuovo login HUMAN dimostrato. Conservare entrambi i contesti; non rilanciare la preparazione o il launcher precedente. Prima del rinnovo interattivo IAM serve la riconciliazione protetta dei9file di tvc2ilnv, distinta dalla qualifica cloud e dal risultato target. [Ricevuta](../evidence/source-revision-iam-stop-20261019.json). [Diagnosi e percorso](../releases/SOURCE_REVISION_IAM_STOP_READ_20261019.md).

## Current checkpoint — preboot HUMAN history proven; fresh postboot successor qualified

**Tecniche8/8; funzionali4/6.** Lettura target completa: tutti i predicati identità/binding/profilo/storia coerenti, solo currentBootMatches=false in4sessioni scadute. Catena153→160→168→175, massimo256 e81residui; historyBindingsSHAe2da3b1c… ricostruito indipendentemente dai metadati redatti. k6rk22xj riconciliato:9file, closure2e68fd91…, nessun artefatto authority/login. [Ricevuta](../evidence/source-revision-human-history-target-20261019.json). Qualificato un successore esplicito entry/login: storia preboot usata solo come prova, login nuovo sul boot corrente dopo RIAPRO LOGIN, nessun refresh/riuso token preboot, contatore iniziale175 e massimo256. CSV HumanSession e il suo guard boot restano invariati. La preparazione vincola i3delta di sorgente e verifica tutti i contesti conservati; solo dopo END passa a un nuovo processo isolato fino ai gate nativi. Nessun gate eseguito dal cloud.

**CI PASS:90 nativi +18 postboot +7 consegna.** Pacchetto14file depositato sul runner, hash verificato; nessun successore eseguito sul target. [Scope, prove e comando unico](../releases/SOURCE_REVISION_POSTBOOT_HUMAN_SUCCESSOR_20261019.md).

## Current checkpoint — prepared executor verified; HUMAN history STOP

**Tecniche8/8; funzionali4/6.** VERIFIED_PREPARED_EXECUTOR conferma ricevuta privata a9ecda1c… e81file congelati. Il nuovo contesto k6rk22xj si ferma in `current_human` / `HUMAN_SESSION_BINDING_OR_HISTORY_DRIFT`, prima dei gate login/authority. La preparazione gezxi85l resta completa; non va ripetuta. [Ricevuta STOP](../evidence/source-revision-execution-human-stop-20261019.json). Sospeso il launcher di esecuzione: serve riconciliare i9file privati previsti nel contesto e leggere i singoli predicati della storia HUMAN e dei successori, senza modificare journal, boot/clock, contatori o authority. Non si assume che il solo boot sia la causa. Diagnosi readonly qualificata: CI39192641238,8test PASS; lettura protetta target ancora da eseguire. [Scope e comando](../releases/SOURCE_REVISION_HUMAN_HISTORY_READ_20261019.md). Nessun nuovo consenso/login.

## Current checkpoint — postboot preparation COMPLETE; native release pending

**Tecniche8/8; funzionali4/6.** Ricevuta target END complete=true nel contesto gezxi85l: compilazione nativa e configurazione Flyway provate,4sessioni SQL readonly, provider/custodia/generazioni/host journal verificati dal preparatore. Entrambi i contesti90file e i7sorgenti55e riconciliati e conservati;78route baseline, UDP36 e migrazioni MCP invariati; zero import, backup, authority e pubblicazioni. [Ricevuta e hash](../evidence/source-revision-postboot-preparation-target-success-20261019.json). `readyForExecution=false` resta corretto: manca la revisione runtime con i gate nativi. Consegna dell'esecutore qualificata in CI39190694557:7 test PASS, vincolata a case48e9885c…, package7e511c3b…, piano dcb0952e… e closure1820bcea…. Nessuna nuova sessione HUMAN aperta. Prima del gate saranno verificati tutti gli81file congelati e gli input originali riconciliati; il ruolo richiede conferma THS.

[Percorso runtime, gate nativi e comando immutabile](../releases/SOURCE_REVISION_PREPARED_EXECUTION_20261019.md). Richiede sudo e terminale HUMAN sul VPS. Nessun executor target ancora avviato.

## Current checkpoint — both STOP contexts reconciled; session-property successor qualified

**Tecniche8/8; funzionali4/6.** Lettura protetta q7bq1ex3:90file esatti, closureSHAe44977b8…, nessuna authority/ricevuta finale; f6w3lo6z preservato e ricontrollato e693804d…. Proprietà OUF/OAuth ammesse; solo4 proprietà sessione HTTP escluse (HttpOnly, SameSite, Secure, timeout). [Diagnosi target](../evidence/source-revision-postboot-property-target-20261018.json). PET Onboarding1.6 THS-09 richiede cookie security e scadenza: successore circoscritto a tali4 proprietà, tipi e valori sicuri, nessuna modifica del file. Entrambi i contesti sono vincolati e verificati prima/dopo la preparazione;76 moduli e loader c750 restano invariati. CI PASS:85 nativi +14 postboot +5 consegna; pacchetto depositato sul runner con hash verificato. Preparazione target ancora da eseguire; nessun nuovo login, authority, rilascio o pubblicazione. [Qualifica e comando immutabile](../releases/SOURCE_REVISION_POSTBOOT_SESSION_SUCCESSOR_20261018.md).

## Current checkpoint — JSON successor STOP on unreviewed namespace

**Tecniche8/8; funzionali4/6.** Nuovo tentativo q7bq1ex3 fermo in configuration.visit:85: `UNREVIEWED_OWNER_JSON_NAMESPACE`. Il formato JSON è decodificato ma una proprietà non è ammessa; nome e significato ancora da provare. Nessuna authority o ricevuta finale. Il comando55e236da è sospeso e non va ripetuto. [Ricevuta operatore](../evidence/source-revision-postboot-json-stop-20261018.json). Diagnosi di sola lettura qualificata in CI39164070132:11 test PASS. Esito per ciascuna foglia, nomi standard solamente, nessun valore o identificatore dinamico; riconciliazione90file q7bq1ex3 e verifica closure conservata f6w3lo6z. Nessuna modifica al verificatore di ammissione, retry o reset budget.

[Diagnosi e comando](../releases/SOURCE_REVISION_POSTBOOT_PROPERTY_READ_20261018.md); lettura target ancora da eseguire.

## Current checkpoint — retained postboot STOP reconciled; JSON successor qualified

**Tecniche8/8; funzionali4/6.** La lettura protetta conferma90file, assenza authority/ricevuta finale, consumer originale riconciliato e overlay JSON invariato rispetto al piano host (hash6d546047…). Nessuna generazione corrente certificata dalla sola diagnosi. [Ricevuta target](../evidence/source-revision-postboot-stop-read-target-20261018.json). È qualificato in CI un successore esplicito del verificatore: JSON owner/THS OAuth, nessun datasource/Flyway/import/profili/loader. Mantiene76 moduli e loader c750, cambia solo configuration.py; il nuovo case/package/closure vincola tale delta. Contesto f6w3lo6z preservato e ricontrollato con closureSHAe693804d… prima/dopo la preparazione. Nessun replay del vecchio comando, login HUMAN o nuovo budget runtime.

**CI PASS:80 nativi +13 postboot +5 consegna.** Nuovo pacchetto depositato sul runner; preparazione target ancora da eseguire. [Qualifica, limiti e comando immutabile](../releases/SOURCE_REVISION_POSTBOOT_JSON_SUCCESSOR_20261018.md).

## Current checkpoint — postboot preparation STOP; do not replay

**Tecniche8/8; funzionali4/6.** Il tentativo ha creato il contesto privato `source-revision-postboot-prepared-f6w3lo6z`, poi si è fermato in `configuration.overlay_text:67`, prima di candidate-review, piano completo e authority. Il sorgente qualificato identifica `UNREVIEWED_OWNER_OVERLAY_SYNTAX`: il formato effettivo non è ancora noto e non va confuso con un override Flyway dimostrato. Conservare log e originali; il precedente comando di preparazione è sospeso. [Ricevuta operatore](../evidence/source-revision-postboot-stop-20261018.json). È qualificata in CI39162711396 (7 test PASS) una lettura di sola riconciliazione: inventario esatto dei file residui, binding e classificazione del formato senza valori. Nessun retry o nuovo budget. [Comando diagnostico](../outputs/OUF_Postboot_Stop_Read_20261018.sh). La lettura sul VPS resta da eseguire.

## Checkpoint cloud — successore postboot qualificato

**Tecniche8/8; funzionali4/6.** PET originali v1.7 verificati:323 checksum PASS. CI39160533382:74 regressioni native +11 prove postboot PASS; pacchetto di preparazione depositato sul runner. Nuovi case/executor/closure ricaricano esplicitamente il prepared riconciliato. Rimane la preparazione protetta sul VPS con sudo fisico; nessuna nuova sessione HUMAN, installazione o pubblicazione. [Qualification and target command](../releases/SOURCE_REVISION_POSTBOOT_PREPARATION_20261018.md).

## Aggiornamento cloud — readback nativo completato con successo

**Tecniche8/8; funzionali4/6.** Run39158332027, commit ce132bbcb3bd8239689415797371afe636db7762: completed/success riconfermato. Sei endpoint fissi e nove identità/processi stabili; UDP200UP, Onboarding200UP, MCP204 pronto. Tre sole GET native, zero mutazioni/SQL/retry/pubblicazioni. [Ricevuta](../evidence/post-host-network-native-read-target-20261018.json). Questa prova non dimostra Semantic/provider/grafo né il journal root. Il recupero host completato non va rilanciato.

Le due bozze conservate nell'handoff50a1966 restano NON QUALIFICATE e non sono state eseguite. Il successore deve legare esplicitamente case, hash, closure e caricamento del prepared originale riconciliato, preservare c23/custodia/budget e verificare le generazioni prima e dopo la compilazione. Nessuna nuova sessione HUMAN è stata aperta. [Stato corrente](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

## Checkpoint precedenti (superati nel perimetro del readback sopra)

## Aggiornamento — recupero rete completato, UDP avviato

**Tecniche8/8; funzionali4/6.** L'esecuzione75c6 ha completato6endpoint/13scritture Docker e avviato UDP, con tutti i controlli di configurazione e custodia superati. Il comando completato non va ripetuto. Provider BLOCKED/vuoto resta revocato; disponibilità applicativa ancora da provare. Nessuna migrazione, pubblicazione o ripresa esplicita dei job. [Ricevuta e stato](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

Sono in preparazione le letture native sul runner e il successore esplicito degli input privati dopo il boot. MCP HEALTHY riguarda solo il suo modulo; il riepilogo operativo403 resta non verificato. Non si riutilizzano PID/socket/binding scaduti né vecchie authority. Restano rilascio nativo Onboarding/MCP, pubblicazione governata del profilo e collaudi5/6.

## Aggiornamento — profilo di custodia circoscritto qualificato

**Tecniche8/8; funzionali4/6.** Provider e confronto preboot erano passati; lo STOP successivo riguarda la custodia dei mount, prima degli effetti. Metadati del runner e ACL confermano il file applicativo0400 intestato all'utente dichiarato e il Caddyfile0664 con il solo operatore1000 come scrittore. Il profilo v2 è vincolato a file/container/mount esatti, senza nuovi utenti fidati globali o modifiche a contenuti e permessi. **37 prove superate**. [Stato, prove e consegna](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

Il successore host non è ancora eseguito: resta un solo passaggio sudo, stesso budget13Docker scritture/300secondi,6endpoint e1avvio UDP. I due file protetti non verificabili dal runner sono controllati da root prima degli effetti. Nessuna nuova authority, migrazione, pubblicazione o ripresa esplicita dei job; provider BLOCKED resta non autorizzato. Seguono disponibilità reale, binding postboot, rilascio nativo revisione fonte e tappe5/6. I vecchi launcher non vanno ripetuti.

## Aggiornamento — custodia dei mount ricostruita, nessuna modifica ai permessi

**Tecniche8/8; funzionali4/6.** Metadati del runner: il file Onboarding0400 appartiene al suo utente applicativo10003; il gruppo1000 del Caddyfile0664 contiene solo l'operatore1000. È in qualificazione un profilo di custodia limitato agli esatti file/container/mount, con verifica nativa degli scrittori e assenza di ACL aggiuntive. Nessuna fiducia globale a nuovi utenti, chmod/chown o esclusione dei file dalle verifiche. Due metadati protetti restano da verificare con root prima di qualunque effetto. [Stato e limiti](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

## Aggiornamento — confronti superati, STOP sulla custodia di un mount

**Tecniche8/8; funzionali4/6.** Il tentativo54d3 ha superato provider e confronto DNS/preboot; durante la preparazione del piano ha incontrato CONFIGURATION_CUSTODY_REQUIRED. Nessun piano/incidente o cambiamento Docker è stato raggiunto. Il requisito preciso non è stampato e non viene ignorato. È in qualificazione un inventario dei soli metadati di tutti i file interessati, tramite il runner, senza contenuti o nuove richieste sudo. [Stato e confine](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

## Aggiornamento — liste DNS vuote confermate, recupero rete qualificato

**Tecniche8/8; funzionali4/6.** Il runner ha verificato che tutte e tre le liste DNS sono vuote. Il successore accetta soltanto HostConfig.Dns null→[], mantenendo invariati riferimento storico e configurazioni reali; blocca ogni altra differenza e qualsiasi cambiamento fra confronto e piano. **29 prove passate**, incluse integrazioni reali Docker29.8.1 e avvio a freddo dei metadati legacy. [Prove, consegna immutabile e stato](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

Il recupero host corretto non è ancora eseguito: resta una sola operazione sudo per lo stesso perimetro13scritture/300secondi,6endpoint e1avvio UDP esistente. Nessuna nuova authority, migrazione, pubblicazione o ripresa esplicita dei job. Provider BLOCKED/vuoto resta non autorizzato. La diagnosi completata e i vecchi launcher non vanno ripetuti. Seguono disponibilità applicativa/provider, binding postboot, rilascio nativo revisione fonte e tappe5/6; nessuna nuova funzione è dichiarata completata.

## Aggiornamento — differenza circoscritta a HostConfig.Dns

**Tecniche8/8; funzionali4/6.** La lettura protetta è completa: API1.44 mostra solo HostConfig.Dns da null a lista sulle tre applicazioni; identità, Config e mount uguali. Non è ancora dimostrato che la lista sia vuota. Il provider è confermato BLOCKED/vuoto e non autorizzato all'avvio. È in qualificazione la sola equivalenza null→lista effettivamente vuota, mantenendo invariati riferimento storico, configurazioni e limiti. Non viene introdotta un'eccezione generale ai controlli. [Stato e prove](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

## Aggiornamento — confronto protetto delle configurazioni qualificato

**Tecniche8/8; funzionali4/6.** Il controllo nativo del provider è superato; il confronto applicativo preboot ha fermato l'intervento prima di creare incidenti o modificare la rete. La causa concreta della differenza non è ancora stampata e non viene presunta innocua. Una lettura unica delle tre applicazioni, con entrambe le rappresentazioni Docker e senza valori riservati, ha superato **10 prove**. [Consegna immutabile e stato](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md). Il solo passaggio fisico necessario è sudo per leggere il riferimento c23 protetto. Nessun nuovo login OUF o consenso repository/MCP. Il vecchio launcher resta ritirato; nessuna tappa funzionale aggiuntiva è dimostrata.

## Aggiornamento — controllo provider superato, differenza applicativa da identificare

**Tecniche8/8; funzionali4/6.** Il successore2c597 ha superato il controllo nativo del provider ma si è fermato sul confronto con le configurazioni sigillate prima del boot. Nessuna modifica rete, avvio UDP o creazione di un incidente è stata raggiunta. Il launcher va conservato e non ripetuto. È in qualificazione una lettura unica delle tre applicazioni per distinguere valori modificati, ordine dei mount e rappresentazioni Docker, senza stampare configurazioni o adottare un nuovo riferimento. [Stato e limiti](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

## Aggiornamento — successore del recupero rete qualificato

**Tecniche8/8; funzionali4/6.** Il tentativo precedente si è fermato al primo controllo del provider, prima degli effetti sulla rete; il vecchio launcher è ritirato. Il contratto nativo può mantenere BLOCKED dopo il ripristino vuoto al boot. Il successore lo riconosce soltanto con autorizzazioni revocate, journal originali validi e prova delle tabelle native vuote, senza cambiare lo stato o avviare il provider.

**23 prove superate**, inclusa integrazione Docker29.8.1 e5 regressioni sul codice nativo del provider. [Stato, prova e consegna immutabile](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md). Resta un unico passaggio sudo sul VPS, necessario per i profili amministrativi protetti; non richiede nuovi consensi repository/MCP o login OUF. Il successore non è ancora stato eseguito sul target. Nessuna pubblicazione o nuovo collaudo funzionale dimostrato. Restano disponibilità applicativa/provider, binding dopo il boot, rilascio nativo revisione fonte e tappe5/6.

## Storico precedente allo STOP

## Preparazione tappa5 — correzione dell'infrastruttura qualificata, target da eseguire

**Tecniche8/8; funzionali4/6.** La lettura protetta dei contratti precedenti è completa. La correzione circoscritta della rete è qualificata:13 prove del journal privato,4 della consegna e1 integrazione reale Docker29.8.1, inclusi risposte perse, identità, DNS/HTTP pubblico, dati persistenti e riavvio del daemon di collaudo. [Stato, prove e limite amministrativo corrente](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md). Sul VPS non è ancora stata eseguita.

Il passaggio corrente richiede soltanto l'amministrazione host già disponibile tramite sudo; non un nuovo consenso ai repository/MCP né un login OUF. Questo recupero infrastrutturale non sostituisce il requisito del percorso ordinario interamente da chat. Restano da provare disponibilità applicativa/provider, nuovi binding dopo il boot, rilascio nativo della revisione fonte, pubblicazione governata del profilo e tappe5/6. Nessuna nuova pubblicazione, decisione d'identità o ripresa esplicita dei job storici.

## Tappa funzionale4 completata — ricerca chatbot con proprietà leggibili

**Tecniche8/8; funzionali4/6.** Dopo la conferma HUMAN, proposta94306235-fc45-4433-a05e-0ead3f83a9f8 PUBLISHED e policy43. La ricerca diretta MCP restituisce13 oggetti distinti ACTIVE con20 proprietà ciascuno, pagina completa; oggetto originario conservato. [Prova diretta](../evidence/csv-functional-stage4-chat-proof-20261018.json).

Restano tappa5 (seconda acquisizione controllata dello stesso CSV senza duplicati) e tappa6 (riscontro di entrambe le acquisizioni e conservazione degli8Cinema). Il profilo generico di riconciliazione non è ancora pubblicato. Nessuna nuova decisione d'identità o ripresa dei vecchi job.

## Blocco di visibilità individuato — revisione nativa dei permessi pronta

Tecniche **8/8**, funzionali **3/6**. Dopo il rinnovo della connessione MCP, GRANTS funziona e conferma policy42. La proprietà RESTRICTED è bloccata da un vincolo operativo detailLevel presente nel solo grant di ruolo della ricerca; la risorsa dati non lo dichiara. **13 test superati** con lo SDK installato. Proposta nativa 94306235-fc45-4433-a05e-0ead3f83a9f8 PENDING: rimuove quel solo vincolo da admin/urban.object.search, conserva etichette, ruoli, assegnazioni e tutte le altre regole. [Evidenza e link THS](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md). Dopo conferma umana occorre nuova ricerca delle proprietà per provare la tappa4. Nessuna nuova acquisizione o pubblicazione del profilo.

## Verifica diretta dopo V36 — 13 identità visibili, proprietà da chiarire

Tecniche **8/8**, funzionali **3/6**. Ricerca MCP fresca:13 oggetti distinti ACTIVE/revisione1, ma proprietà vuote. Il runner conferma che il ciclo automatico UDP è già abilitato; anche l'API HUMAN delle riprese tecniche è abilitata. Sono due funzioni diverse. Riferimento e mount delle credenziali presenti, continuità della rotazione ancora da provare. [Evidenza](../evidence/chat-recovery-runtime-and-chat-verification-20261018.json).

La lettura GRANTS dal collegamento attuale fallisce nello schema, mentre ROLES funziona. MCP PR73 aggiunge una regressione di protocollo reale, superata con tutte14 CI e unita: nessuna modifica produttiva o prova della causa del problema client. Occorre riconciliare discovery/serializzazione senza modificare policy o budget.

Il profilo concreto conserva i20 campi; nessuna pubblicazione nuova. Il percorso nativo esistente richiede DRAFT/clone, modifica con versione attesa, validazione e revisione; manca ancora la sua esposizione generica di revisione da MCP. Non trattare la review della versione ACTIVE come un aggiornamento del profilo.

## Aggiornamento installato — UDP V36 e MCP pronti

Tecniche **8/8**, funzionali **3/6**. Il risultato target ricevuto conferma complete=true, applicationReady=true, journalVersion=55 e UDP V36 nel contesto chat-recovery-execution-4kokhxpd. [Evidenza](../evidence/chat-recovery-rollout-target-receipt-20261018.json). Il precedente blocco di preparazione è superato; non ripetere il launcher completato.

Restano distinti la pubblicazione nativa del profilo, l'attivazione del recupero e il ciclo continuo delle credenziali: il risultato non li dichiara eseguiti. Nessuna decisione d'identità o ripresa job ripetuta. Proseguire con verifica delle capabilities effettive, configurazione e percorso nativo, poi collaudi funzionali4–6.

## Correzione del controllo preliminare — 18 ottobre 2026

Tecniche **8/8**, funzionali **3/6**. Il tentativo di aggiornamento si è fermato prima dell'autorità runtime con RETAINED_HOST_CONFIGURATION_CHANGED: il compilatore confrontava la policy di riavvio temporanea della creazione con quella finale già ripristinata. Corretto il confronto senza accettare modifiche non previste; **73 test superati** nel [rilascio qualificato 39082554565](https://github.com/GioNob/ouf-deploy/actions/runs/39082554565). La nuova esecuzione riconcilia gli artefatti privati del tentativo fermato prima del login. Aggiornamento target ancora da provare; usare soltanto il launcher aggiornato. [Stato e limiti](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

## Aggiornamento corrente — esecutore completo qualificato, presenza HUMAN necessaria

Tecniche **8/8**, funzionali **3/6**. Correzione MCP PR72 unita, nuovo pacchetto firmato verificato e preparato dal runner; [69 test della preparazione/esecuzione superati](https://github.com/GioNob/ouf-deploy/actions/runs/39082232187). Il launcher unico prepara la custodia privata delle nuove immagini, verifica generazioni e storia, quindi richiede l'autorità HUMAN nativa per backup e aggiornamento UDP V35→V36/MCP. Nessuna modifica dei servizi è ancora avvenuta. Le evidenze di custodia precedenti riguardano il vecchio pacchetto e restano storiche.

La pubblicazione delle policy, l'attivazione effettiva del recupero e la continuità delle credenziali restano verifiche distinte; non dichiarare automatico il percorso finché queste non sono provate. Seguono le tappe funzionali4–6. Dettagli e impronte nello [stato aggiornato](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

## Aggiornamento preparazione rilascio — 18 ottobre 2026

Tecniche **8/8**, funzionali **3/6**. La custodia amministrativa delle immagini UDP/MCP candidate è confermata dal [log target ricevuto](../evidence/chat-recovery-root-custody-target-20261018.json). Nessuna immagine importata, nessun backup o aggiornamento dei servizi; piano non ancora eseguibile. Questo avanzamento riguarda la preparazione del rilascio e non modifica le tappe funzionali. Vedere lo [stato corrente e i passaggi residui](CSV_CHAT_ONLY_COMPLETION_STATUS_20261018.md).

## Tappa funzionale3 completata sul target — 18 ottobre 2026

**Stato corrente: tecniche8/8; funzionali3/6;13/13 righe committate;13 oggetti distinti; zero quarantene residue per la sorgente di collaudo.** Questo esito supera i precedenti checkpoint2/6 e12/13, conservati sotto come storia.

Il log fornito dall'utente `/home/oufadmin/ouf-csv-last-row-recovery.sHJ0mSn1/run.log` riporta `OUF_LAST_ROW_RECOVERY_RESULT.complete=true`, `singleJobCommitted=true`, `functionalStage3Proven=true` e `upstreamHandoffsAndLineageMatch=true`. Sono confermati il commit di tutte13 le righe, gli11 oggetti CREATE_NEW precedentemente verificati e la conservazione dell'oggetto originario; nessuna riga non provata. [Evidenza target redatta](csv-functional-stage3-target-proof-20261018.json). È evidenza del log target ricevuto, non una nuova interrogazione live dell'agente.

Il job residuo `c5692362-8a22-4656-97b6-46b5ba8ce17f` ha ricevuto **una sola ripresa nativa accettata** ed è arrivato al commit senza ripetere la decisione d'identità. Un grant aggiunto tramite owner ha pubblicato `ouf-lab-authorization:42`, hash `75834f0c64d929cc40401867aa65542b4ba15bb3e4bc32a6fd4ca719bab79fb1`, conservando grant preesistenti e capabilities. Nessuna nuova pubblicazione della fonte o reset di budget. La sessione del credential owner ha effettuato un tentativo/una pubblicazione oltre i318 conservati, entro il tetto444.

Lo stato finale `CANCELLED_BY_OWNER` del worker è la terminazione prevista del recupero finito dopo il successo; non annulla il commit. Il campo `applicationReady=false` del reporter del token owner non è una valutazione della disponibilità complessiva OUF né una prova di accettazione end-to-end. `continuousCredentialLifecycleProven=false` resta esplicito.

La verifica funzionale successiva è la **tappa4: ritrovare i dati con una nuova ricerca dal chatbot**; seguono la5 (seconda importazione dello stesso CSV senza duplicazioni) e la6 (verifica di entrambe le acquisizioni e conservazione degli8 Cinema preesistenti). Prima della ripetizione, valutare gli effetti di pubblicazione/scheduler e le policy effettive senza inventare cardinalità o priorità. Il successo della tappa3 non dimostra l'attivazione di un profilo nativo di riconciliazione, il caso merge/collegamento a oggetto esistente, il rinnovo continuativo o il percorso interamente da chat. Restano criteri di accettazione anche resilienza di rete, ripresa durevole e nessun comando VPS per l'utente.

## Resilienza nel percorso da chat — conferma owner 18 ottobre 2026

L'owner richiede gestione automatica anche di latenza, perdita pacchetti e interruzioni di rete. Si applica la [policy di resilienza v3](OUF_RESILIENCE_POLICY.md), già normativa; questa conferma non introduce budget nuovi né prova conformità dei runtime.

- Errori esplicitamente transitori: timeout per tentativo e retry con backoff/jitter e Retry-After, entro budget durevoli. Default v3:5/15/60/300/900 secondi, jitter fino20%, massimo128 tentativi e24 ore, salvo profilo finito versionato. Restart e nuova chat non azzerano contatori o progresso.
- Risposta persa dopo una scrittura: esito ambiguo, da riconciliare con l'owner prima di rispedire. Stessa idempotency key per la stessa operazione; ACK, receipt e commit verificati prima di avanzare. Un timeout non dimostra che la scrittura sia fallita.
- Dipendenza indisponibile: pausa/circuito condiviso, incidente correlato e lavoro indipendente attivo. Non trasformare ogni record dipendente in una quarantena separata; ripresa graduale e limitata quando disponibilità e autorità tornano verificabili.
- Problema isolato sul record o budget esaurito: quarantena/blocco del più piccolo scope indipendente consentito dal contratto, conservando input durevole, configurazione/versioni, lineage, tentativi, effetti noti e causa. Nessuna perdita silenziosa o successo fittizio; nessun superamento dei checkpoint se vietato dall'owner.
- Errore permanente, revoca o integrità/configurazione non verificabile: blocco motivato, senza retry ciechi. Esiti incerti richiedono riconciliazione; un eventuale nuovo budget HUMAN preserva lo storico e passa dal flusso supportato MCP/THS.
- La chat mostra stato, causa sicura, prossimo tentativo, budget residuo e azioni ammesse tramite le capability operative esistenti. Le attese, la persistenza e la ripresa sono compiti del backend e continuano senza mantenere aperta la chat o richiedere comandi sul VPS.

L'accettazione del percorso CSV richiede fault injection su latenza/perdita rete/disconnessioni prima e dopo effetti, risposte e ACK persi o tardivi, restart durante attesa, indisponibilità prolungata, esaurimento budget, revoca/cancellazione durante pausa e recupero graduale. Verificare: niente duplicati o perdita dati, checkpoint e contatori conservati, isolamento corretto e stato MCP concordante con gli owner. Distinguere prove con tempo simulato da prove reali dei trasporti configurati. **Tecniche8/8 e funzionali2/6 restano invariati finché non arrivano le relative prove target.**

## Requisito di accettazione: intero percorso da chat, senza VPS — decisione owner 18 ottobre 2026

L'utente conferma che il percorso ordinario e il recupero dopo THS devono essere automatici attraverso qualsiasi chatbot compatibile con l'endpoint MCP. **Nessun accesso al VPS, comando shell, launcher specifico, operazione SQL o riavvio manuale può essere richiesto all'utente per completare la pipeline.** Il comando operativo consegnato per il singolo incidente è uno strumento transitorio: non soddisfa questo criterio e non chiude l'end-to-end.

Il chatbot scopre capabilities, schemi e prerequisiti dall'endpoint. L'onboarding e l'arricchimento semantico precedono la pubblicazione; per i file autorizzati l'ingestion e la successiva materializzazione proseguono tramite i contratti owner. Una decisione THS risolta deve rendere proseguibile il job originale verso creazione o collegamento/merge, riconciliazione delle proprietà, commit e integrazione nel grafo urbano, con esito e provenienza leggibili dalla chat. Se rimane un impedimento tecnico, la chat deve mostrarne stato e causa e guidare il recupero supportato; non deve dichiarare completamento sulla sola chiusura dell'issue.

Credenziali dei servizi e relativo rinnovo, propagazione delle policy, riattivazione delle lavorazioni ammissibili e controllo degli esiti appartengono al runtime, con stato durevole, budget cumulativi, fencing e idempotenza. Le decisioni HUMAN richieste dai contratti restano esplicite tramite flussi MCP/THS collegati alla chat; l'automazione non fabbrica identità o consensi né interpreta un diniego permanente come transitorio. Eventuale autenticazione dell'utente usa il flusso supportato dal client, senza terminale VPS.

Il runner CI/CD esistente in ouf-deploy è il percorso di distribuzione da riusare per le modifiche qualificate; la pipeline utente non deve dipendere dal suo impiego come shell remota. Teatri resta soltanto il collaudo: implementazione generica per file e altri connettori, preservando il percorso scheduler per API/delta/layer dinamici.

**Prova richiesta:** un CSV nuovo seguito interamente da chat, più casi controllati di quarantena risolta con CREATE_NEW e collegamento/merge a oggetto esistente; verifica del commit, proprietà concorrenti/provenienza, visibilità nel grafo, assenza di duplicati al riavvio e ripresa dopo interruzione delle dipendenze. Evidenze di installazione, pubblicazione profilo, singolo recupero e accettazione end-to-end devono restare distinte. Stato attuale invariato: tecniche8/8, funzionali2/6; rinnovo continuativo e percorso senza operazioni VPS non ancora provati.

## Piano privato acquisito e recupero operativo unico — 18 ottobre 2026

La preparazione sul target è **completa**, log `/home/oufadmin/ouf-csv-last-row-prepare.prOtPeUF/prepare.log`. Piano privato `/etc/ouf/deploy-snapshots/csv-last-row-prepared-o9ziuyhf/prepared-plan.json`, SHA256 `9993b1ca7f3877ba7632c3530d3b54da013f8059a762c48239b21f2f080cfb6c`. Una sola scrittura privata, zero login/grant/worker/retry e nessuna mutazione runtime. `readyForExecution=false` è atteso: la preparazione non emette autorità.

Il solo job residuo `c5692362-8a22-4656-97b6-46b5ba8ce17f`, versione11, conserva cinque tentativi e baseline `sha256:0a276d062d3447a243d6e2611d9a618dd1ba2b8cf64668d02dad7aa5c75eccdb`; decisione CREATE_NEW/RESOLVED già presente. Restano12/13 righe committate; nessun nuovo oggetto o contributo sul job residuo. **Tecniche8/8; funzionali2/6.**

Il [pacchetto operativo](../releases/csv-last-row-recovery-code-package-20261018.json) e il [launcher](../scripts/launch-csv-last-row-recovery-20261018.sh) vincolano tutti i52 overlay, bootstrap, loader e selezione al commit sorgente `73bf5767e4ee2e3397ef5cf9193b91589d0522d6` e all'impronta del piano privato. La revisione completa si presenta dopo il login della sessione HUMAN scaduta (160/256 tentativi conservati): una sola approvazione runtime composta per nuova sessione del credential owner già esistente, un grant temporaneo esatto e massimo una ripresa del job.

Il credential owner conserva318 tentativi, massimo126 nuovi, tetto444, fence e cronologia precedenti. La policy41→42 aggiunge solo il grant `udp.materialization.retry` per l'identità HUMAN e il job/sorgente/run/tipo/access label verificati, preservando tutte le altre voci. Il contratto nativo deve confermare idoneità, versione11, stessa baseline e snapshot fresco prima dell'unico POST con operationId stabile e claim durevole. Non si ripetono decisioni d'identità, pubblicazioni della fonte o ingestion CSV.

Prima della prima lettura nativa, il processo attende il maggiore intervallo di aggiornamento policy fra UDP e Semantic Registry, ricavato dalle rispettive configurazioni correnti, più12 secondi; default30 solo se assente, come negli SDK verificati. Generazioni e route restano vincolate. Dinieghi espliciti401/403 e risultati di mutazioni incerti arrestano il flusso senza replay automatico. Nessun riavvio di servizi, aggiornamento immagini, modifica IAM o riattivazione scheduler.

Il comando prosegue fino al readback finale: commit del job, ledger13/13,11 CREATE_NEW storici e oggetto originario conservati,13 ACK e lineage Ingestion/UDP concordanti. Solo questo risultato può attestare la tappa3 e portare il contatore a3/6. A fine operazione o STOP il worker termina. La sessione finita **non dimostra il rinnovo credenziali continuativo** richiesto per future sorgenti e scheduler.

[Qualifica completa 39076417852](https://github.com/GioNob/ouf-deploy/actions/runs/39076417852), job117524391524: **22 PASS, zero errori/fallimenti/skip**, sintassi launcher valida, query selettiva su PostgreSQL17 reale. Verificati import isolato della chiusura di sorgenti senza effetti, tutte le impronte della consegna, versioni/identità/baseline alterate, una sola approvazione operativa e nessun replay di mutazioni ambigue. I trasporti owner dei test sono simulati e le sorgenti onboarding esterne sono stub solo per la prova d'import: questa CI **non prova l'esecuzione sul VPS**. [Impronte e limiti](csv-last-row-composed-recovery-qualified-20261018.json).

La consegna eseguibile è fissata al commit `d51d2ea0b663ea0cfc6c8b1a9cde086bcc56e906`, launcher SHA256 `a5fe60b324eb62005f39a0e35e1a8ba6e93575dcd6819f9884bbe287e0190bbf`. Il comando locale `OUF_Tappa3_Recupero_Operativo_VPS.txt` scarica e verifica tale launcher nella sessione VPS esistente. Atteso login nuovo perché la sessione è scaduta e un consenso runtime composto secondo [AGENTS.md](../AGENTS.md), «Development delegation is not runtime HUMAN authority». Nessuna nuova autorizzazione ai repository richiesta. In attesa del risultato target; nessun effetto runtime attribuito alla CI o alla preparazione.


## Preparazione nativa qualificata e consegnata — 18 ottobre 2026

[Qualifica finale 39075109515](https://github.com/GioNob/ouf-deploy/actions/runs/39075109515): **7 PASS, zero errori/fallimenti/skip**, sintassi launcher valida. [Impronte e limiti](csv-last-row-private-preparation-qualified-20261018.json). Il comando è consegnato per creare sul VPS la revisione privata del recupero, ancora senza autorità runtime. In attesa di percorso/impronta del piano e contatori HUMAN raccolti dal target; nessun nuovo login, worker, grant o retry dell'agente. Il contatore318/444 non viene né azzerato né aumentato nella preparazione.


## Causa del blocco e preparazione del recupero — 18 ottobre 2026

Il [preflight target completo](csv-semantic-policy-channel-failure-target-20261018.json), log `/home/oufadmin/ouf-csv-reference-read.P7fk3eF0/read.log`, identifica il diniego nel Semantic Registry: `SEM_CAPABILITY_REQUIRED:ouf.semantic.read`. Il token UDP non è scaduto alla lettura, contiene lo scope richiesto e corrisponde ad audience/guard della route conservata. Nella **policy pubblicata 41** esiste un grant `ouf.semantic.read` valido che corrisponde all'identità UDP; descrittore SERVICE/READ corretto. Il token con cui il Semantic Registry legge tale policy è invece **scaduto**, e il canale configurato della policy risponde **401**. Il contenuto effettivamente caricato in memoria non è provato; la disponibilità del trasporto policy è certamente interrotta.

Il fence corrente punta al worker `e787ac35…`: CANCELLED_BY_OWNER, una pubblicazione/tentativo nella sessione, predecessore317, cumulativo **318**, tetto **444**, residuo **126**, lock non detenuto. Non è consentita la ripartenza automatica del worker cancellato. La preparazione riusa il compilatore nativo `compile_governed_session` della sorgente esistente hash-verificata, per una **nuova sessione ancora da autorizzare**, mantenendo tetto, fence e intera cronologia. Nessun primo grant viene ripetuto.

`prepare-csv-last-row-recovery-20261018.py` vincola il piano al rollout55, al solo job `c5692362-8a22-4656-97b6-46b5ba8ce17f` versione11 e ai record cancellati esatti. Produce un documento privato root-owned con proposta di scope nativo318→444, metadati della sessione HUMAN senza stamparne credenziali, template del permesso limitato a job/sorgente/run/tipo/access label verificati e prerequisiti dell'applicazione. Non apre login, modifica permessi, avvia worker o riprende job. **readyForExecution=false e runtimeAuthorityIssued=false**; la sola scrittura è il nuovo artefatto privato di preparazione.

[Qualifica del compilatore e della selezione 39075042131](https://github.com/GioNob/ouf-deploy/actions/runs/39075042131): **7 PASS**, cronologia immutata318/444, cancellazione/admission/conteggi alterati rifiutati, sorgente nativa e prima ricevuta non sostituibili, un solo job identico ammesso. Il SQL del record è quello già qualificato nel preflight v2 su PostgreSQL17; non si dichiara una nuova prova runtime.

Dopo la preparazione privata servono le autorità runtime correnti: nuova decisione HUMAN dopo cancellazione; eventuale solo grant job-specifico tramite API owner preservando la policy; ripristino del credential owner già esistente; review nativa con contratto disponibile e baseline identica; una ripresa con versione/snapshot e operationId durevole; readback13/13. La delega ai repository non sostituisce tale autorità. La sessione finita di recupero **non dimostra operatività continuativa** del rinnovo credenziali per future fonti o scheduler: quel requisito rimane esplicito nell'accettazione end-to-end.

**Tecniche 8/8; funzionali 2/6; 12/13 commit. Nessuna decisione d'identità da ripetere.**


## Consegna qualificata del preflight completo — 18 ottobre 2026

[Run 39074601464](https://github.com/GioNob/ouf-deploy/actions/runs/39074601464), job 117519046015: **8 test PASS, zero fallimenti/errori/skip**, SQL su PostgreSQL 17 reale, sintassi launcher e corrispondenza dell'impronta della sorgente consegnata. [Prova di qualifica](csv-semantic-access-full-preflight-qualified-20261018.json). Il lettore include anche tipo sorgente, run e access label RAW richiesti per circoscrivere l'eventuale recupero del singolo job, senza indovinarli.

L'utente ha ricevuto il comando hash-verificato per la sessione VPS esistente. In attesa del riscontro v2: nessun nuovo login, grant, worker, job retry o decisione d'identità. Il 403 resta un diniego da spiegare, non un transitorio da ritentare automaticamente. Il preflight non attesta il contenuto effettivamente caricato in memoria dal registry, l'inventario live delle route o una nuova autorità HUMAN; espone le rispettive prove e lacune. Se il canale owner non è verificabile, le letture SQL indipendenti vengono comunque raccolte, senza adottare un'altra identità o generazione.

**Avanzamento invariato: tecniche 8/8, funzionali 2/6.** La decisione CREATE_NEW è risolta; il commit dell'ultima riga non è ancora provato.


## Ultimo record: pubblicazione accessibile, riferimento semantico negato — 18 ottobre 2026

Il [riscontro VPS](csv-last-row-semantic-access-target-20261018.json), log `/home/oufadmin/ouf-csv-reference-read.TDxght8L/read.log`, prova **HTTP 200** per la pubblicazione storica e **HTTP 403** per il suo unico riferimento semantico. Il token UDP non risultava scaduto al momento della lettura; questo non prova la validità futura né identifica ancora lo strato che nega l'accesso. `ownerAuthorizationDeniedDetail=false` non esclude un diniego owner con un altro formato di errore.

Il job è `c5692362-8a22-4656-97b6-46b5ba8ce17f`, versione **11**, QUARANTINED con cinque tentativi e cinque controlli di integrità già consumati. RAW VERIFIED, nessuna lease, nessun binding, contributo o osservazione; la decisione CREATE_NEW è RESOLVED. Baseline storica `sha256:0a276d062d3447a243d6e2611d9a618dd1ba2b8cf64668d02dad7aa5c75eccdb`. Restano **tecniche 8/8, funzionali 2/6**, con 12/13 commit.

Il preflight v2 riusa i componenti già presenti di `read-teatri-reference-recovery-preflight-20261017.py`: metadati scope/audience/guard della route conservata (esplicitamente non prova live della route), errore semantico redatto con allowlist, canale policy configurato nel Semantic Registry, confronto dei grant pubblicati con l'identità UDP e cronologia del worker puntata dal fence esistente. Nessuna modifica di accessi o avvio sessioni. I contatori cumulativi sono verificati, non rinnovati. Se la generazione del registry o la catena del fence non coincidono, si dichiara la parte non provata; non si adotta un container arbitrario. Limiti: 120 secondi, nove letture engine, tre sessioni SQL read-only, due file di credenziali, quattro GET.

Ordine del recupero: identificare il diniego preciso; ripristinare solo l'accesso previsto dalla configurazione approvata attraverso il proprietario competente; ottenere una review nativa aggiornata del singolo job con `contractReady=true` e baseline identica; usare l'API governata esistente con versione/snapshot attesi e identificativo idempotente; provare osservazione/revisione/contributi e 13/13 commit. Nessuna scrittura SQL correttiva, cambio di semantica, ripetizione della decisione di identità o reset di tentativi. Un 403 non viene ritentato automaticamente. Qualunque nuova autorità o budget runtime rimane distinto dalla delega allo sviluppo.

[Qualifica v2 39074407807](https://github.com/GioNob/ouf-deploy/actions/runs/39074407807): 7 test PASS, zero skip, PostgreSQL 17 reale, confronto di grant validi/scaduti e isolamento tenant, redazione del diniego, metadati route e verifica dei contatori cumulativi. Nessun recupero runtime ancora eseguito.


## Qualifica finale e prossimo riscontro — 18 ottobre 2026

**Stato runtime invariato: tecniche 8/8, funzionali 2/6; 12 righe committate e una quarantena tecnica dopo CREATE_NEW risolto.** [Qualifica finale 39073880515](https://github.com/GioNob/ouf-deploy/actions/runs/39073880515) PASS: 4 test, zero skip su PostgreSQL 17 reale e sintassi del launcher verificata. La readiness del database di test ora attende il server TCP finale, evitando la finestra del socket provvisorio d'inizializzazione. Il codice lettore consegnato è quello già qualificato al commit `37e7150ca150ab861ee1b5794e8091b8776cca51`; il launcher è fissato al commit `ce0c86d727040441fe0cac412896232c93e81095` e all'impronta documentata nella [prova normalizzata](csv-post-resolution-continuity-qualified-20261018.json).

Anche [CI completa UDP 39073660012](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39073660012) PASS per tutti e quattro i job (Java/PostgreSQL, supply chain, disaster recovery, prestazioni). La PR UDP 45 è pronta per revisione, sovrapposta alla PR 44, senza dichiarare installazione. Il comando della diagnosi è stato consegnato all'utente per la sessione VPS esistente. **In attesa dell'output host; nessuna ripresa del job eseguita dall'agente.**


## Qualifica della continuità e diagnosi mirata — 18 ottobre 2026

[UDP PR 45](https://github.com/GioNob/ouf-udp-object-resolution/pull/45) conserva il profilo delle proprietà nel percorso pubblicato prima della review HUMAN. Test integrati APPROVE e CREATE_NEW verificano la conferma THS, la ripresa del medesimo job, binding, contributi, osservazione/revisione e assenza di duplicati al tick successivo. Configurazione pubblicata e reference gate sono confini simulati dichiarati; PostgreSQL e servizi di dominio reali. [Run 39073660064](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39073660064): **95 test PASS, zero errori/fallimenti/skip**, inclusi 18 della suite di candidati. Questo fix è separato dal blocco dei riferimenti e non è ancora installato.

Il nuovo `read-csv-post-resolution-references-20261018.py` riusa i lettori installati e gli adattatori di accesso già esistenti, vincolati al rollout journal 55. Legge metadati del solo job residuo (versione, tentativi, hash mancanti, baseline, assenza/presenza effetti) e verifica la pubblicazione storica più al massimo due riferimenti semantici tramite l'identità di servizio già configurata. Nessun token o valore della fonte stampato, nessun rinnovo OAuth, grant, mutazione, decisione o retry. Limiti: 90 secondi, due sessioni SQL read-only, sette letture engine, un file di credenziale, tre GET. La copertura semantica limitata è dichiarata; non prova da sola l'intero catalogo.

[Qualifica sorgente 39073782611](https://github.com/GioNob/ouf-deploy/actions/runs/39073782611): **4 test PASS, zero skip**, SQL realmente eseguito su PostgreSQL 17, isolamento tenant e redazione delle risposte, incluse risposte 401/403/302 senza redirect. SHA256 sorgente `30f10c26a9d51265b1941d048845b51ae5c77510bd0b888f060333cfff19c52e`, commit `37e7150ca150ab861ee1b5794e8091b8776cca51`. Il launcher non apre login; usa la sessione VPS esistente. La lettura del token configurato resta in memoria. L'esecuzione host richiede la sessione VPS dell'utente perché il runner ha già provato che sudo non interattivo richiede password: nessun nuovo tentativo del rifiuto.


## Riscontro VPS dopo la decisione THS — 18 ottobre 2026

La decisione HUMAN **CREATE_NEW** per il caso `e16fec6e-311d-49f3-b1de-f274cb5a92d1` è **RESOLVED**. Il job del medesimo handoff `9fde61f1-8d3c-4de7-b3fe-b534b32e45e3` resta però **QUARANTINED / UDP_REFERENCE_INTEGRITY_MISSING**, intake DURABLE, nessun binding, osservazione, contributo o oggetto creato. La ripresa ha raggiunto il controllo dei riferimenti; il riferimento preciso e la causa del mancato accesso non sono ancora provati.

Il log `/home/oufadmin/ouf-csv-stage3-read.KsMUTYp4/read.log` conferma 13 handoff ACKED con lineage coerente, 12 job SUCCEEDED e 12 oggetti, tutte le 11 precedenti creazioni conservate. Nessuna review d’identità aperta. **Tecniche 8/8; funzionali 2/6; tappa 3 non completa.** Il contatore `unprovenRows=1` del reader v3 include questa quarantena tecnica: `quarantinedRows=0` non significa che non vi siano job in quarantena.

Prova normalizzata: [csv-functional-stage3-reference-block-20261018.json](csv-functional-stage3-reference-block-20261018.json). Non ripetere la decisione THS, non importare nuovamente il CSV e non riarmare lo scheduler. Il recupero deve usare il job esistente e il percorso tecnico governato già implementato, dopo verifica dei riferimenti storici e dello stato/versione attesi. Nessun reset dei contatori o cancellazione dello storico. Pubblicazione del profilo e prova funzionale restano fasi distinte.

# Tappa3 — ultima review chiusa, verifica del commit finale in corso,17ottobre2026

**Tecniche8/8; funzionali2/6 verificati.** L'utente ha trattato il caso residuo nella THS; la pagina conferma0casi incerti aperti. La ricerca MCP restituisce ancora i12oggetti precedenti, revisione1. Questo è compatibile con più esiti: la tappa3 richiede13righe committate e provenienza, non13oggetti distinti, e non si chiude sulla sola scomparsa della review.

Il lettore v3 aggiunge azione HUMAN più recente e codice sicuro del job per handoff. CI39073074291:12test PASS,0skip, con controesempi reali PostgreSQL17 e13commit verso12oggetti. Il nuovo END riporta functionalStage3Proven=true e funzionali3/6 soltanto dopo la prova dei13commit e del lineage. Nessun nuovo tentativo sudo sul runner: consegna verificata per la sessione VPS esistente.

[Stato della verifica](CSV_FUNCTIONAL_STAGE3_20261017.md), [THS e ricerca dopo la decisione](../evidence/csv-functional-stage3-after-ths-20261017.json), [qualifica v3](../evidence/csv-functional-stage3-final-reader-qualified-20261017.json). Il readback precedente12commit+1quarantena resta prova storica, superabile soltanto dal nuovo riscontro.

---

# Tappa funzionale3 — rendiconto e provenienza verificati,17ottobre2026

**Tecniche8/8; funzionali2/6. Tappa3:12commit+1eccezione conservata, tutte13le righe rendicontate.** Readback VPS del lettore v2 qualificato:13handoff ACKED con ricevuta e lineage,12job SUCCEEDED e12oggetti distinti con revisione/osservazione verificata,20contributi ciascuno; una quarantena DURABLE senza binding/contributi. Tutte11le decisioni CREATE_NEW risultano materializzate e l'oggetto originario è conservato. Gli ID coincidono esattamente con la ricerca MCP precedente.

ENDcomplete=true,readbackProven=true,upstreamHandoffsAndLineageMatch=true,allRowsAccounted=true,unprovenRows=0. Il criterio storico13commit resta aperto:allThirteenMaterializedProven=false,historicalCriterionChanged=false; il contatore non viene aumentato tacitamente. L'intenzione di mantenere la quarantena è documentata nella chat.

Schedule MANAGED DISABLED per pubblicazione1 consumata;0failure. Generazioni coerenti col rollout linked-property/journal55 e UDP35. Nessuna mutazione, pubblicazione, riacquisizione o ripetizione di decisioni. Il readback operatore supera il precedente limite sudo del runner per questa sola lettura; non occorre ripeterla.

[Evidenza target](../evidence/csv-functional-stage3-target-readback-20261017.json), [rendiconto per handoff e limiti](CSV_FUNCTIONAL_STAGE3_20261017.md). Prossimo controllo: tappa4, riscontro dal chatbot sulle proprietà autorizzate; la ricerca degli ID è già riuscita ma restituiva properties vuoto. Pubblicazione del profilo di riconciliazione ancora distinta e non provata da questa lettura.

---

# Resolution: rollout UDP completato dall'operatore; lettura browser da provare — 2026-10-17

**Tecniche8/8; funzionali2/6.** Operatore riporta `OUF_UDP_RESOLUTION_UPDATE_RESULT`: contesto `/etc/ouf/deploy-snapshots/udp-resolution-execution-65h5kjt8`, journalVersion31, complete=true, applicationReady=true, maximumGatewayWrites=0, newPolicyWorkerStarted=false, identityDecisionsPerformed=false e semanticDispatchPerformed=false. Evidenza di esecuzione del percorso qualificato, non readback indipendente della generazione target o dell'accesso autorizzato al pacchetto.

Il rollout ha raggiunto la verifica finale del solo UDP. `sourceActivationProven=false` significa che questa operazione non prova l'attivazione della sorgente, non che abbia revocato la precedente attivazione. Nessun avanzamento milestone3 sulla sola health. Prossima verifica: pagina THS Resolution nella sessione HUMAN corrente, Aggiorna i casi, ispezione delle proposte prima di confermare. Non riavviare il rollout o riaprire un worker policy senza un errore corrente che ne dimostri la necessità. Un eventuale403 richiede il corpo dell'errore owner; snapshot/token browser correnti restano distinti dalla correzione codice installata. Ultimo readback dati resta1materializzato+12quarantene.

---

# Resolution: comando UDP qualificato e pronto per esecuzione operatore — 2026-10-17

**Tecniche8/8; funzionali2/6.** Correzione applicativa UDP a4d432d7… gia qualificata; preparato il rollout del solo UDP con sorgente executor `198d0bd9c2968f1fa5bfa61d1c7da8efab2c13bb`. Profile installation-specific `releases/udp-resolution-update-selection-20261017.json`: baseline UDP b49c0d6f…, candidato artifact12101592347, predecessore Resolution q91d2ut7/journal37/source d830, tre route conservate. I valori dell'installazione rimangono nel caso versionato e negli input conservati, senza nuovi default di rete/issuer/tenant.

CI [39035231628](https://github.com/GioNob/ouf-deploy/actions/runs/39035231628), job117403587830: **23PASS,0skip**. Docker reale/root e firme dei due ruoli esistenti, archivio con prefisso UDP/hash completo/identita nativa senza tag, migrazioni identiche, sostituzione con IP/MAC/mount/ambiente conservati, peer e route immutati, autorita breve/scaduta/revocata, outage, doppia invocazione e risposta mutativa persa senza replay. Fixture HTTP e dati sintetici: non sono prova di accesso browser/owner target.

La preparazione verifica la catena review/plan/scope/authority/effects del rollout q91 e la generazione attuale dei peer; legge l'immagine UDP corrente confrontandola con l'audit conservato. Verifica/copia tutti i byte prima di OAuth e APPROVO. Se necessario riapre esplicitamente il login, preservando cumulativo e vecchio journal; un refresh permanentemente rifiutato non viene ripetuto, un esito ambiguo/transitorio non apre login successori. APPROVO autorizza solo import immagine e lifecycle UDP, massimo900s e un tentativo per effetto. Zero nuovi worker policy, Gatewaywrite, migrazioni nuove, grant o decisioni di identita. Un esito ambiguo blocca per riconciliazione.

Delivery [39035578424](https://github.com/GioNob/ouf-deploy/actions/runs/39035578424): **3PASS**,46file checksum/manifest, rifiuto byte modificati, esatto inoltro archivio e download prima di sudo/login. Launcher pubblicato `0b35f5b77809cf2c3b3f3446a25fbea09e0ea24e`, SHA256 **6f053134dca15c5ebc9464db017bbdd8d4868879a9a6c04f73862da3502d1b8a**, byte riletti da GitHub e ricontrollati. Manifest commit9c0c4b44…, SHA72069684…. Download313246590byte senza aprire finestre OAuth; eventuale copia locale viene riusata solo dopo verifica esatta.

**Target non ancora modificato da questo rollout.** Atteso operatore sul VPS: login/APPROVO solo dopo preparazione, poi `OUF_UDP_RESOLUTION_UPDATE_RESULT`. Il processo termina al risultato; non lascia worker policy da mantenere un'ora. Dopo serve rilettura della pagina con sessione browser e policy owner correnti, prima di qualunque scelta di identita. Il token policy precedente puo essere scaduto: nessun refresh/grant viene implicitamente avviato per dimostrare readiness. Casi12in quarantena e milestone3 non avanzano su CI o sul solo health UP.

Evidenza `releases/udp-resolution-update-native-qualification-20261017.json`. Profilo conservato su singolo host; nessuna qualifica distribuita multi-host o accettazione PET generale dichiarata.

---

# Resolution: correzione contesto owner qualificata, non installata — 2026-10-17

**Tecniche8/8; funzionali2/6.** Il readback target `ouf.resolution-owner-policy-metadata-read.v1` mostra bundle40: entrambi i grant HUMAN Resolution sono validi, subject corretto, resourceType nullo e attributi risorsa vuoti. Non è un mismatch capability/resolution-issues. I grant vincolano però tutte5etichette e tutti4livelli; il valutatore SDK richiede i rispettivi attributi, assenti nel vecchio contesto servlet.

UDP [PR41](https://github.com/GioNob/ouf-udp-object-resolution/pull/41), sorgente `a4d432d7788cc1c205c0eaafa5ae3b46036de09f`: GET browser, POST delegato di lettura e conferma pacchetto valutano risorse owner sullo stesso snapshot autenticato. Il pacchetto attuale comprende evidenze miste dell'intero tenant senza classificazione per issue: richiede copertura completa delle5etichette×4livelli, con attributi solo server. Nessuna etichetta permissiva predefinita o presunta gerarchia; accessi parziali negati. Nessuna modifica grant, SDK, migrazione o scelta di identità.

CI boundary [39034028566](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39034028566):13PASS,0skip (7nuovi+6pairwise), più10test SDK. CI modulo [39034028565](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39034028565):successo; Maven216test,0errori/fallimenti,2skip preesistenti (GovernedGridRuntimeTest e ObjectSearchReceiptFilterTest); recupero PostgreSQL/MinIO, prestazioni, build nonroot/packaging SDK e supply-chain completati. Ulteriori workflow push continuità, recovery e CRS completati.

Candidate [39034093831](https://github.com/GioNob/ouf-deploy/actions/runs/39034093831):SUCCESS, artifact12101592347, ZIP SHA256 e87f068a879fa996a91fa518c5ad3a114008e23e0e28b13dde5a7476ae7b1f42 (313246590byte); imageId3040e430…, scansione HIGH/CRITICAL/UNKNOWN inclusi unfixed superata e attestazione publisher verificata in CI. Identità nativa target/tagless ancora da qualificare sullo store del VPS.

**Non installato.** Nessun token/grant/worker/riavvio/decisione target eseguito da questa correzione. Lo snapshot UDP effettivamente caricato e il token browser restano da verificare nel percorso finale: il test riproduce il bug con i vincoli osservati, non prova da solo il recupero target. Occorre predisporre rollout del solo UDP con conservazione container/mount/rete/ambiente e senza nuove decisioni; preparare pacchetto e input prima di nuovo login/APPROVO. Non rinnovare il worker per attendere CI. Milestone3 ferma a1materializzato+12quarantene dall'ultimo readback.

Evidenza: `releases/resolution-owner-context-qualification-20261017.json`.

---

# Resolution: rifiuto owner UDP confermato; confronto vincoli grant — 2026-10-17

**Tecniche8/8; funzionali2/6.** Screenshot operatore del GET autenticato `/trusted-human/resolution/api/package` restituisce ProblemDetail `title=Forbidden,status=403,detail=Owner authorization denied,instance=/api/udp/v1/governance/resolution/issues/package`. Raggiunto l'owner UDP tramite il proxy browser; non è il precedente404Gateway. La tabella vuota non dimostra assenza di issue. Nessuna decisione confermata, nessuna nuova mutazione.

Nel sorgente UDP b49c0d6f… il GET browser TrustedHumanApi.reviewPackage usa trusted(request), che chiama ServletAuthorization.resolve senza ResourceContext specifico: default `capability`. Il percorso delegato interno dello stesso package usa OwnerAuthorization.require con `resolution-issues`, tenant da principal e attributi vuoti. Differenza di contesto dimostrata dal codice; incompatibilità con i grant target ancora da provare. Non cambiare permessi o riavviare worker sulla sola ipotesi. Risposta OwnerAuthorizationErrors indica SecurityException owner, non specifica da sola quale constraint neghi.

Reader `scripts/launch-resolution-owner-policy-read-20261017.sh`, SHA7549fd5c149c9dcdaf3f23ff07d3df15e5409e8551b61c2307e38f0b2b7a545d; sorgente `e9616724d8f608b06e1bb354c5828659c5e0a4e6`, readerSHAce2dae60…. CI39033405393/job117398338540:3PASS,0skip, SQL su PostgreSQL17 reale. Il primo testfixture39033358709 era fallito per socket temporaneo initdb; corretto soltanto il readinessTCP del fixture, reader immutato byte-per-byte.

Diagnosi installation-specific entro40s: contesto rollout q91d2ut7/journal37/source d830, scope resolutionConfigurationUpdate e13effects APPLIED; generazione Onboarding corrente e PostgreSQL due volte. Una sola transazione BEGIN READ ONLY/ROLLBACK, statement timeout10s/lock3s, cap2/grant≤32, database/OID/ruolo esatti da piano conservato. Legge solo i metadati della policy attiva nell'owner Authorization Onboarding: descrittori, matching subject/tenant/validità e constraint pubblicati, confrontando i resourceType capability/resolution-issues e attributi vuoti. Non è prova dello snapshot UDP caricato o del JWT browser. Zero token/OAuth/IAM/grant/Gatewaywrite/readiness/decisioni e nessun segreto/rawSQL stampato. Attende output VPS prima di scegliere correzione contesto o altra causa.

Il connettore MCP permissions.read non ha effettuato la lettura: adattatore ha richiesto link_id non fornito dalla superficie tool. Nessuna proposta/permesso pubblicato. Si usa il reader target già autorizzato, senza probing di sessioni browser o estrazione di cookie/bearer.

---

# Resolution: aggiornamento completato, lettura browser403 — 2026-10-17

**Tecniche8/8; funzionali2/6.** Operatore ha confermato `OUF_RESOLUTION_CONFIGURATION_RESULT`: contesto `/etc/ouf/deploy-snapshots/resolution-config-execution-q91d2ut7`, journalVersion37, complete=true, applicationReady=true, newRouteCount3, sameImageOnly=true, newPolicyWorkerStarted=false, identityDecisionsPerformed=false, semanticDispatchPerformed=false. Dal percorso qualificato: stesso binario Onboarding ricreato con JSON browser additivo, tre route applicate/verificate, inventory finale e probe anonimi completati. È evidenza di flusso eseguito, non nuovo readback indipendente target o accettazione dati.

Screenshot successivo mostra la pagina `/trusted-human/resolution/?continue` renderizzata, titolo Casi incerti di identità, tabella vuota e `Lettura non disponibile (HTTP403)`, pulsante conferma disabilitato. Non interpretare la tabella vuota come zero issue: l'elenco non è stato letto. Pagina esposta e sessione browser arrivata alla UI; accesso package non provato. Nessuna decisione di identità confermata in questa operazione.

Codice owner UDP b49c0d6f…: TrustedHumanApi.trusted risolve principal e snapshot SDK; LocalAuthorization rifiuta NO_POLICY_BUNDLE/STALE_POLICY_BUNDLE, poi package.prepare richiede resolution.issue.read. Scope/token/Gateway/actor/tenant/grant restano possibili livelli di rifiuto. Onboarding34488428 ResolutionThsApi.prepare inoltra corpo e status upstream, mentre la UI riduce il messaggio a HTTP403. Worker policy scaduto è un possibile fattore, non causa provata da screenshot. Non aprire una nuova sessione worker o cambiare grant alla cieca.

Prossima osservazione minima: risposta del GET `/trusted-human/resolution/api/package` nello stesso browser HUMAN autenticato, riportando il solo corpo errore. Non ripetere approvazioni, import, rollback, container replacement o conferma pacchetto. Distinguere blocco Gateway da owner e policy stantia da permesso prima del rimedio. Deep link per caso/source resta non implementato; `?continue` non seleziona casi nel controller. Restano1materializzato+12quarantene dall'ultimo readback acquisizione; nessun avanzamento milestone3 senza13materializzazioni e provenienza.

---

# Continuazione esatta dopo refresh HUMAN bloccato — 2026-10-17 13:32 CEST

**Tecniche8/8; funzionali2/6.** Target: preparazione privata completata in `/etc/ouf/deploy-snapshots/resolution-config-execution-e1zic7co`; stessa immagine9da9e4d4…,3scopepreservati+2Resolution. STOP al refresh `HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN`, prima del review/APPROVO e di authority/effects. Non interpretare il codice come revoca indipendentemente provata. Nessuna nuova route/container mutato da questo tentativo. La prosecuzione non chiama il vecchio refresh.

Nuovo sorgente `d830edbcdbf41c495672833b86aa698546e215a6`, package `d2cbd3d27cb0e6486b67258152a322bb2e3c2453` SHA2262cd31…; CI39029245665/job117386201568:26PASS,0skip. Confronta per uguaglianza l'intero prepared-plan conservato con gli input correnti, cambia solo authorityDirectory e riusa candidate-review originale con hash. Mantiene il medesimo retiredName/logicalUpdateRef, rifiuta presenza di autorità/review/claim/effects precedenti. Fallisce su drift; nuova directory non permette replay. Il vecchio piano e journal HUMAN restano intatti.

Dopo questa preparazione: `RIAPRO LOGIN` esplicito per una nuova finestra device HUMAN7200s, ereditando il numero effettivo di tentativi OAuth e tetto128. Non si copiano bearer/refresh token; il vecchio journal resta BLOCKED e un claim one-use impedisce un secondo successore. Sono respinti errore di trasporto ambiguo, richiesta interrotta, operazione diversa da REFRESH, budget128 esaurito e consenso/storia cambiati. Seguono autenticazione issuer nuova e APPROVO separato per lo stesso intervento infrastrutturale, due firme correnti, massimo900s. Nessun worker policy o suo budget viene riaperto. Authority scope e limiti dell'aggiornamento invariati.

Launcher corrente `scripts/launch-resolution-ths-configuration-20261017.sh`, SHA113bedf981f820a70985b483e45905da55054fce0ab20482c264b706d13293b0. Sostituisce il precedente pin02dc7c9b…, da non rilanciare. Prima riapertura locale e browser; poi APPROVO infrastruttura. Incollare `OUF_RESOLUTION_CONFIGURATION_RESULT`; in caso diSTOP conservare il log. Il risultato non prova ancora decisioni identità, binding IAM live, policy owner corrente o13materializzazioni conprovenienza. I limiti fixture descritti sotto restano validi.

---

# Resolution: pronto aggiornamento stessa immagine e scope browser — 2026-10-17

**Tecniche8/8; funzionali2/6.** Readback proprietà13:15 CEST: la lista Spring JSON contiene3scope e non richiede resolution.issue.read/resolution.match.approve; enabled resta inconclusivo per YAML flow. Non cambiare grant o rigiocare import/approvazioni. [Procedura concreta](../releases/RESOLUTION_THS_CONFIGURATION_20261017.md): conserva tutti gli scope, aggiunge i due e rende THS esplicito nel JSON; stessa immagine Onboarding, precedente conservato, Ingestion invariato; poi3route. Nuovo profilo infrastrutturale firmato/HUMAN, nessun nuovo worker/budget o autorizzazione decisioni dati. Non dipende da worker scaduto per il provisioning; policy corrente e autorizzazione owner restano obbligatorie per i successivi atti THS.

Sorgente `e6fa281acc7be3e6d8f0a0db7066535c455e4697`, CI39028393385/job117383811364:19PASS,0skip, replacement Docker e namespace reali, fixture Admin/app sintetici. Target apply pendente; milestone3 non avanzata. LauncherSHA02dc7c9b…; package5ea6a324…. Prima tutta la preparazione, poi HUMAN attuale o RIAPRO LOGIN esplicito a finestra scaduta e APPROVO infrastruttura separato. Nessun rollback/replay automatico. Binding IAM live e token browser effettivo non ancora provati; richiesta scope non equivale a grant.

---

# Resolution: STOP prima del consenso, dichiarazione THS da riconciliare — 2026-10-17 13:00 CEST

**Tecniche8/8; funzionali2/6.** Operatore: executor resolution-route-executor-code-5r6p38we, nuova directory resolution-route-execution-zt7l5a8h. Bootstrap PREPARED poi STOP `EXPLICIT_THS_AUTHENTICATION_ENABLED_REQUIRED`, runtimeAuthorityIssued=false. Dal flusso entry.py configuration() precede inventario Gateway, piano/review, decisione e ogni PUT: nessuna autorità o nuova route emessa da questo tentativo. Non rilanciare il launcher route. Non attribuire ancora il problema a THS disabilitato: il parser letterale non prova il valore Spring effettivo. Codice owner34488428 in GioNob/ouf-source-onboarding conferma chiave `ouf.authorization.ths.enabled` e la catena OAuth/CSRF HUMAN.

Reader successivo `scripts/launch-resolution-ths-property-shapes-20261017.sh`, SHA25628e7de587077e4ac60d57cee2e9d85b13524e0a74f24e1ce6921ae2cb50df1c5. Sorgente70b13be02eda847008b9391623cbc3959a938b2c; reader82d2c386…; CI39027224121 PASS5test,0skip, custodia root/no-follow reale. Entro35s,2EngineGET,1configurazione THS esatta montata RO, nessun token/OAuth/grant/SQL/Gatewaywrite. Riconosce forma booleano, maiuscole, placeholder, riferimenti env con solo booleano risolto, lista scope, proprietà JSON annidate/piatte e canali discordanti. Stampa solo categorie/booleani/conteggi, nessuna stringa config/secret. Non è valutatore completo YAML/Spring: segnala flow syntax e non dichiara effectiveConfigProven. Può essere eseguito a worker scaduto, nessun reset/rinnovo. Attende output operatore per correzione concreta; route e accesso Resolution ancora non provati target.

---

# Pubblicazione Resolution THS qualificata; attende APPROVO sul VPS — 2026-10-17

**Tecniche8/8; funzionali2/6.** [Procedura tre route](../releases/RESOLUTION_THS_ROUTES_20261017.md), sorgente `90c59b5d437ce85fbd8d72d72024b6bf914dca7d`, CI39025774179/job117376342948:21PASS,0skip. Package hashc5e56f24…; launcherSHA1e605d83…. Nessuna azione target eseguita dalla CI. Correzione limitata a tre route nuove, nessun import/grant/DB/container/decisione UDP; pagina per ultima. Conserva mappe complete e sessione worker corrente248+68≤316, verifica Spring JSON, richiede nuova revisione HUMAN e due firme. Timeout PUT blocca su claim senza replay; riconciliazione readonly qualificata con namespace reale e Admin fixture. Caso/source nel deep link resta gap UX; link comune protetto da login/tenant. Milestone3 resta aperta:13ACK,1materializzato e12quarantene dall'ultimo reader.

---

# Reader Resolution THS qualificato; pronto per dati configurazione — 2026-10-17

**Tecniche8/8; funzionali2/6.** Comando successivo scripts/launch-resolution-ths-bindings-read-20261017.sh, SHA256 a9d5670a54087e2436ca46ff8ceb706d82184d3228775ea7b46932b8c84f44aa. Sorgenti f771762981c79c24754e584ee0201b2734aa9b2f: reader c1a6ca54dbf16cc7abf2e33218a1ca26f45a34ca02eeeb3ba55ecd1dfef6e724 e gateway custody5e7182d8… confrontati byte per byte remoto. Qualifica GitHub39024872193/job117373777165:4 test PASS,0skip con custodia root reale/no-follow/stale binding, parser letterale/ambiguità/env/indici, nessun segreto stampato e riconoscimento route catch-all. Non prova caricamento effettivo Spring, route live né disponibilità target della pagina.

Il reader usa contesto ybmis4le/reviewb258 e generazione Onboarding esatti; legge una configurazione THS montata RO con custodia preesistente, due letture Engine,35s,0SQL/0token/0IAM/0grant/0Gatewaywrite. Le route vengono dallo snapshot storico firmato31ad562f…: prima di un apply occorre comunque inventario Gateway corrente completo. Nessuna modifica di servizi o decisione UDP è autorizzata dal reader. La correzione concreta deve coprire pagina browser, configurazione conditional THS e backend package GET/confirm POST con owner scopes; non basta inventare un link case/challenge non previsto dal codice. Domanda UX sul collegamento al caso specifico conservata.

---

# Pagina Resolution non instradata; URL comune autenticato, nessun challenge implementato — 2026-10-17

**Tecniche8/8; funzionali2/6.** Screenshot operatore image(9).png osservato direttamente nel workspace: https://api.ouf-lab.it/trusted-human/resolution/ restituisce APISIX JSON error_msg404 Route Not Found. Non attribuire a login/permessi owner né inventare un URL personale. La pagina era stata proposta sulla base del codice, senza prova di esposizione target: indicazione prematura riconosciuta.

Il codice Onboarding34488428 contiene ResolutionThsApi @RequestMapping /trusted-human/resolution, pagina GET/, GET/api/package e POST/api/package/confirm. Non riceve query param challenge/source/issue né restituisce link personalizzato. PermissionThsSecurity richiede OAuth2 server session ouf-ths e principal HUMAN. UDP TrustedHumanApi/ResolutionReviewPackageService applicano permission e tenant, snapshot/hash/versioni. URL pubblico conoscibile non equivale ad accesso anonimo autorizzato; né la segretezza di un link sostituisce l'autorizzazione. La superficie attuale elenca l'intero pacchetto autorizzato del tenant: riferimento visibile al singolo caso/source e un deep link selettivo non risultano implementati. Non aggiungere un parametro arbitrario fingendo che sia interpretato.

Il materializzatore Gateway425a0377 tools/materialize_onboarding_review.py aggiunge le pagine Onboarding/Semantic, non Resolution. Le route package UDP e la proprietà condizionale ouf.resolution.ths.gateway-base-url richiedono verifica congiunta prima di una proposta concreta. Nuovo reader scripts/read-resolution-ths-bindings-20261017.py:35s,2EngineGET, zeroSQL/token/worker/grant/Gatewaywrites; verifica contesto ybmis4le e review b258d70a… esatti, legge solo metadati dalla configurazione THS montata RO con la custodia nominale preesistente e ispeziona lo snapshot route firmato del rollout31ad562f…. Snapshot storico NON inventario route live, proprietà dichiarate NON effective config/framework snapshot. Non stampa client secret, raw config, cookie o token. Helper custody5e7182d8… già qualificato e riusato tramite AST limitato. Qualifica parser/redazione/no-follow/version drift in corso; nessuna pubblicazione route eseguita.

Le13ricezioni durabili e12quarantene UDP restano quelle del checkpoint precedente. Prima delle decisioni HUMAN va ripristinato e verificato il percorso browser+owner completo; non confermare collegamenti preselezionati né fare POST da agente/VPS. La domanda operatore sul riferimento specifico al caso va mantenuta nel lavoro UX; non è prova che esista un URL personale nascosto.

---

# Prima acquisizione consegnata;12 identità UDP da verificare — 2026-10-17

**Tecniche8/8; funzionali2/6.** Reader target completo: contesto ybmis4le/review b258d70a9ec1e6257be8508bdce62b69b60e7b78a671356dd5defb8490796ca3/journal29. Ingestion run a3208f2f-ebfd-415d-bddc-79ab05dea78f SUCCEEDED/MANAGED_ONCE:13 processing attempt,13 lineage,13 handoff ACKED con receipt,0fail/0quarantena, sorgente HEALTHY. Schedule DISABLED con triggerOnce true e pubblicazione996d58ca… consumata: è esecuzione una tantum conclusa, non un errore di attivazione.

UDP:1handoff PROCESSED e12 DURABLE,1job SUCCEEDED e12 QUARANTINED,1binding/oggetto/revisione/osservazione,20 contributi,12 issue OPEN UNRESOLVED_IDENTITY. ACK di ricezione durevole non equivale a13 oggetti materializzati. Non rispedire import, cambiare idempotency key, cancellare issue o forzare collegamenti. Il risultato Cinema0 riguarda SOLO schema:MovieTheater: tipo baseline ancora da riconciliare; nessuna prova di perdita degli8Cinema.

Analisi sorgente UDP b49c0d6f: GovernedIdentityEngine considera distinti i candidati solo se tutti i segnali condivisi sono DISAGREE; accordo su alcuni e disaccordo su altri richiede HUMAN. ScopedIdentityCandidateRepository recupera l'unione dei match per ogni campo. Questa logica spiega un possibile percorso primo-oggetto/12revisioni, coerente col codice osservato; non è ancora lettura delle12evidenze target né motivo per allentare la policy approvata.

Percorso già implementato in Onboarding34488428: ResolutionThsApi /trusted-human/resolution/ con package owner UDP tramite Gateway e autenticazione HUMAN, conferma CSRF/expected snapshot e versioni. Pagina offre Collega a un oggetto, Crea un oggetto distinto (con coverage valida), Chiudi il caso. **La UI preseleziona APPROVE se il candidato è uno: non è una raccomandazione e può fondere Teatri distinti se confermata alla cieca.** Servono revisione concreta e scelta HUMAN; nessuna conferma da agente. Prima aprire la pagina nello stesso browser THS e osservare numero casi/opzioni/errori. Origine approvata https://api.ouf-lab.it. Runtime disponibilità di questa specifica pagina non ancora provata.

Limite da tenere presente: ResolutionReviewPackageService conferma tutte le issue visibili del tenant in transazione; IdentityGovernanceService e GovernedIdentityResolutionService ricontrollano coverage per CREATE_NEW e possono riaprire casi se cambia durante la materializzazione. Non promettere risoluzione automatica delle12 o successo in un unico batch; non indebolire il fence per evitare una seconda revisione. Restano da qualificare comportamento di batch CREATE_NEW e presentazione di dati utili alla scelta, se la superficie osservata non basta. Le decisioni sono dirette HUMAN, non endpoint chiamati da MCP/VPS.

---

# Controllo acquisizione pronto: sorgente ACTIVE, milestone2/6 — 2026-10-17

**Tecniche8/8; funzionali2/6.** La lettura owner source.onboarding.read conferma ACTIVE/lock4, pubblicazione996d58ca… attiva, compatibilità osservata, readiness ACTIVE/attempt3/generation5. Non ripetere approvazione/attivazione sorgente. Il worker policy resta nella finestra autorizzata dal nuovo login, senza reset/rinnovi automatici. Fonte di prova: evidence/chatbot-teatri-source-active-20261017.json.

Prossimo comando: launcher `scripts/launch-teatri-active-acquisition-read-20261017.sh`, SHA256 `ccfa579cae7e2375a543cfd250e2e6e97a6af7e8a30b920880b9bdaefecb8b9d`; reader sorgente `43a39d7dd48ed591ef31132d9ccade36536bbdf0`, SHA256 `7fb7dade825ac496d4bd19a7090fda53ea2d2a00f04d47840e718b71e62aa135`, verificato byte per byte remoto. [Qualifica query PostgreSQL17](https://github.com/GioNob/ouf-deploy/actions/runs/39024067444), job117371466286,3 test PASS: schemi da migrazioni Ing f869d8b8/UDP b49c0d6f, limite ultimi3run, ACK/lineage/binding/contributi corretti, proprietà/payload/receipt privati non esposti, conteggi binding filtrati per tenant e literal SQL chiusi. Questa qualifica copre le query su PG reale, non l'esecuzione completa del nuovo reader sul VPS; gli adapter root/CLI bounded sono conservati dal reader precedente.

Solo metadati amministrativi aggregati per contesto ybmis4le/PG OID e ruolo conservati,65s/6EngineGET/2 sessioni SQL READ ONLY, nessun token o chiave, nessuna modifica di servizi/dati/grant, nessun avvio/replay worker. Scopo specifico installazione conservata, non portabilità multi-host. Restano13commit/UDPprovenienza, ricerca proprietà autorizzata, secondo import/riuso e baseline8Cinema. Il fingerprint della sola classe schema:MovieTheater non dimostra uguaglianza storica degli8Cinema finché il tipo baseline esatto non è riconciliato.

---

# Sorgente Teatri ACTIVE: milestone funzionale2/6 provata — 2026-10-17

**Tecniche8/8; funzionali2/6.** Dopo OUF_ONBOARDING_AUDIT_FIX_RESULT complete/applicationReady, contesto `onboarding-audit-execution-ybmis4le`, journal29, nuovo worker avviato, l'operatore ha completato la decisione diretta THS. Lettura MCP source.onboarding.read sullo stesso link ouf-admin: source `teatri-csv-6609b245`, versione `9860853e-e8f3-4b93-b9d2-03521a039962` **ACTIVE/lock4**, configurazione ae7f46b4… invariata, challenge ecf36c5c… CONFIRMED. Pubblicazione996d58ca-43d6-42f5-a42a-311940e742f9 attiva, checksum sha256:c997e4ccdb1e97823e1a55f4e5a549ee6cecee80da865bb246bb297d8cbd7431. Compatibilità osservata, readiness ACTIVE/attempt3/generation5/lastCode null. La scadenza storica del challenge è riportata senza reinterpretarla come annullamento della fonte già ACTIVE. Nessun nuovo invio semantico/nuova approvazione dell'agente.

Lo stato ingestion via MCP restituisce authorization denied/retryable false; operations.summary restituisce403. Nessun retry né cambio grant. Il catalogo ROLES letto mostra admin nominale e non include ingestion.operations.read; non equivale a prova completa della causa nel Gateway/owner. urban.object.search sulla classe esatta schema:PerformingArtsTheater restituisce un solo oggetto ACTIVE/revision1, d6051381-934b-4a11-8e71-e1d89cee4e49, properties vuote, partial false. Non prova tredici righe, provenienza di quell'oggetto o assenza dei valori nel datastore.

Prossimo controllo: reader storico specifico di questa installazione, `scripts/read-teatri-active-acquisition-20261017.py`, contesto ybmis4le e generazioni Onboarding/Ingestion/PG esatte, zero token e zero proprietà/payload/evidence privati stampati; due sessioni SQL con transazione e default READ ONLY, due timeout SQL/lock, limite65s e sei EngineGET. Produce ultimi3run/conteggi lineage/handoff/ACK/quarantena, binding/materializzazioni UDP e fingerprint della sola classe MovieTheater (non attribuire il conteggio al baseline Cinema senza riscontro del tipo). Nessuna attivazione, grant, retry mutativo o worker nuovo. Il controllo amministrativo aggregato non sana il permesso MCP mancante. Restano milestone3 commit13/provenienza,4 ricerca effettiva,5 secondoimport senza duplicati,6 entrambe acquisizioni e baseline8Cinema preservati. Qualifica SQL del reader ancora in corso.

---

# Ripresa pronta dopo refresh HUMAN bloccato — 2026-10-17

**Fasi tecniche8/8; funzionali1/6.** Eseguire solo il launcher aggiornato `scripts/launch-onboarding-audit-fix-20261017.sh`, SHA256 `6ef642a3481be972825030801ebba9693da136ca79248a92924a014cd055389b`. Source closure `91738314175dc1f5c912a3f4a760a76b0b736476`; manifest `7e72b854366970d54b9bd41f1c144683415cc9f5` / SHA256 `6aa5285e71afe06a986cc8b382713964150f5b6a2c4f54240c7d0d12f8dbd506`. Tutti29 file sorgente confrontati byte per byte con GitHub e manifest remoto verificato. [GitHub qualification39023344933](https://github.com/GioNob/ouf-deploy/actions/runs/39023344933):41 test, zero skip, real root/signatures/Docker; issuer sintetico nei fixture, nessuna nuova prova funzionale sul VPS.

Il launcher riconcilia l'esatto contesto fz4p79t2 fermato prima dell'autorità (artefatti assenti), lega i suoi tre record di preparazione e la riga HUMAN bloccata a81 tentativi. Propone RIAPRO LOGIN con hash esatto, login browser nuovo, poi APPROVO worker residuo248+68=316, poi APPROVO solo Onboarding compatibilità. Il vecchio refresh non si ripete, il vecchio journal resta BLOCKED, nessun token precedente è copiato, nessun reset. Il nuovo login parte da81 con47 richieste OAuth residue; il nuovo journal NEW non costituisce autorità. Trasporto ambiguo/interruzione, drift, autorizzazioni preesistenti nel contesto fallito, mutazione conteggi o claim di nuovo login già consumato fanno STOP. Finestra7200s; worker massimo3600s entro scadenza HUMAN. Usare terminale PC e lasciarlo aperto per worker e successiva ripresa THS. Riusa cache candidato39020189836 già scaricata/verificata. Onboarding34488428 ancora da installare, sorgente ancora da attivare; nessuna nuova proposta semantica o approvazione sorgente.

In caso di STOP non rilanciare: conservare log e riconciliare. Dopo successo leggere configurazione e compatibilità con la medesima credenziale corrente; nel THS aggiornare stato/riprendere verifica, non riapprovare la sorgente. Il GET200 configurazione precedente non dimostra il GET compatibilità né il completamento della readiness.

---

# HUMAN refresh bloccato: nuovo login esplicito da qualificare — 2026-10-17

**Fasi tecniche8/8; funzionali1/6.** Readback operatore: contesto `/etc/ouf/deploy-snapshots/onboarding-audit-execution-fz4p79t2`; nessun review/decision/human/authority/issuance.claim/login-window-receipt presente. HUMAN BLOCKED, operazione REFRESH, motivo HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN,81 tentativi consumati,47 residui su128, finestra non ancora scaduta al controllo. Il motivo aggrega risposte OAuth ricevute non transitorie e non dimostra la causa di revoca. Il refresh non si ripete e il blocco non si cancella.

Implementato un percorso separato per nuova autenticazione device, con consenso locale esatto: conserva il journal BLOCKED, lega hash del predecessore e della preparazione fallita, inizializza un nuovo journal NEW a81 senza copiare vecchi token. Seguono autenticazione issuer/userinfo e nuove decisioni worker e Onboarding. Richieste interrotte o trasporto ambiguo sono escluse. La sola scadenza non sblocca il vecchio login. Worker cancellato:248 cumulativi,68 residui,tetto316. Onboarding attuale e02def25; correzione compatibilità34488428 scaricata ma non installata. Riutilizzare candidato39020189836 verificato; nessuna nuova immagine. Consegna ancora in qualificazione, nessuna autorità runtime emessa da questa modifica.

---

# Compatibilità owner corretta e sessione residua qualificata: pronto per due decisioni — 2026-10-17

**Fasi tecniche8/8; funzionali1/6.** Readback SQL dell'operatore: databaseouf_onboarding/OID21552, ruoloouf_admin, transazioneREADONLY, policy40. READ configuration.read SERVICE grantouf-ingestion vincolato a published-configuration/moduleONBOARDING; attestazione ingestion.configuration.attest SERVICE operationCOMMAND grantouf-ingestion presente senza vincoli aggiuntivi; configuration.write HUMAN operationCOMMAND presente per il soggetto selezionato. Revisione Teatri APPROVED/CONFIRMED, hash esatto, compatibilityCount0, readinessBLOCKED/ONB_READINESS_DEPENDENCY_403, attempts2/generation3. Worker precedente CANCELLED/expired,60 pubblicazioni,248 cumulativi,ceiling316. Nessun reset o riavvio eseguito dal lettore.

Sorgente Onboarding34488428ac8eee6b919cb1b5982cf9ba62361292: IngestionCompatibilityApi ora delega GET e POST al servizio owner transazionale. Lettura READ e attestazione COMMAND valutano il registry reale su published-configuration/moduleONBOARDING/versione, richiedono SERVICE/scope, riga managed review dello stesso tenant e hash frozen esatto. I valori risorsa sono costruiti dal metodo owner, non copiati dal grant. Attestazione mantiene la deduplicazione sul medesimo hash. Il contratto internal managed supporta frozen IN_REVIEW/APPROVED/ACTIVE/SUPERSEDED in lettura; il dominio limita già la scrittura a IN_REVIEW/APPROVED. La precedente GET configurazione approvata mantiene tutti i controlli APPROVED/CONFIRMED. Nessuna policy/grant/migrazione modificata.

GitHub Actions modulo39020168863 e browser39020168856 verdi. Due regressioni PostgreSQL reali in IngestionConfigurationAuditRuntimeTest passate: transazione audit/config invarianti e GET/POST HTTP del controller con grant vincolati reali; letturaABSENT, POST201, retry201 stessoattestation_id, letturaPRESENT/compatibletrue, un solo record, versione e approvazione invariate. Negativi su tenant/hash/scopes/actor/client preservano il record. Candidato39020189836 verde e firmato/scanPASS: artifact12096422563,554170847 byte,SHA25692e52ae392d52260f20c7e399d0c6e2c1a8825aa2c9c0ca3830568055d73081f; sourceLockSHAe95227a3a63d3c946295ebde966e394b5f735457280091f38402f16a87d859b3.33 migrazioni byte-invariate.

Esecutore0711079171645871e6a335a4f78b829b32edcb48, manifestSHA68e8a42f04f102061d7a7810c68e64d3fbe9c2ff2d6f3248d6d82c2910bcb602;29 file remoti confrontati byte per byte. GitHub Actions39020646143 verde:34test root senza skip, Docker reale/namespace/immagine, firme Ed25519 reali per i due nuovi scope, passaggio atomico del fence e installazione owner realmente composta; issuer TLS sintetico qualifica248->249 con una sola nuova richiesta e nessun replay del primo grant/storia precedente invariata. Operatività multi-host e accettazione target non provate.

Preparazione privata di immagine/piano/generazioni completata prima di qualunque nuova richiesta grant o consenso. Due APPROVO distinti: (1) nuova sessione worker con68residui,248precedenti,ceiling316 invariato, massimo3600s e comunque entro finestraHUMAN; fence/storia del worker scaduto immutati fino al passaggio autorizzato; (2) sostituzione del solo Onboarding, vecchio container conservato, stessi mount/env/rete/IP/MAC,900s/uneffetto per stage/maxGatewayWrites0, nessun DBschema/IAMgrant/semantica o ripetizione approvazioni. Se HUMAN corrente è valida viene riusata con conteggioOAuth128 preservato; se scaduta, RIAPRO LOGIN separato e browser espliciti prima dei due APPROVO, mai rinnovo automatico. Dopo il risultato il processo mantiene il worker in primo piano per THS: non chiudere il terminale. Nessun clock reset o estensione implicita del login.

Predecessore applicativo esatto onboarding-audit-execution-i220f2c0/review21ca88f1c5aa682eb74612ead95c9bc6154ddf79a18a52af8f5d281e32abc605/journal29. Target di questa nuova correzione non ancora eseguito. Dopo risultato occorre leggere la nuova review/policyContext e fare GETconfigurazione200 e GETcompatibilitàABSENT/PRESENT senza POST; poi ripresa esplicita HUMAN readiness nel THS e Verifica separata. Conservare challengeecf36c5c-10b2-4393-bf81-0ff7d28b8d5b, source/version/hash originali, attempts2/gen3 e approvazioneCONFIRMED. Mai semantic.propose aggiuntivo o resetclaim: budgettool2giàconsumato. Restano attivazione, UDP/provenienza, ricerca, secondoimport conriuso e Cinema8 invariato. Evidenza releases/ONBOARDING_COMPATIBILITY_OWNER_FIX_EVIDENCE_20261017.json.

# Compatibilità GET403 provata; worker concluso, nessun riavvio — 2026-10-17 11:07 CEST

**Fasi tecniche8/8; funzionali1/6.** L'operatore ha eseguito la GET compatibilità separata:403 ONB_CAPABILITY_DENIED sul contratto onboarding.compatibility.ingestion-runtime; policy200/bundle40, generazioni stabili, review21ca88f1c5aa682eb74612ead95c9bc6154ddf79a18a52af8f5d281e32abc605/journal29. La GET configurazione200 delle10:58 resta prova del primo passaggio corretto; non prova tutta la readiness. IngestionCompatibilityApi GET e POST usano ancora TrustedActorResolver.requireService/ServletAuthorization.resolve con contesto generico capability. La correzione deve coprire lettura e attestazione con contesto owner e controlli di tenant/hash/actor, senza ampliare grant.

Terminale1 concluso: attempts60/publications60 ACTIVE poi CANCELLED_BY_OWNER/CANCELLED e OUF_READINESS_SESSION_ENDED=NO_AUTOMATIC_RESTART_OR_RESET, prompt restituito.188 precedenti+60=248 cumulativi riportati; massimo316,68 residui nel limite approvato, ma nessuna autorità per ripartire alla scadenza. Gli aggiornamenti completati restano installati. Non riavviare né riusare autorità scaduta. Prima preparare correzioni, test reali dei grant e candidato; solo dopo eventuale sessione finita nuova con approvazione HUMAN, mantenendo storia e conteggi.

Nuovo lettore scripts/read-onboarding-compatibility-owner-db-20261017.py non dipende da token: stesso helper rootSHA b02d..., esatti prepared inputs firmati conservati, Onboarding corrente legato a review21ca/journal29, PostgreSQL a runtime binding e databaseOID/ruolo del piano originale. Un solo psql con BEGIN READ ONLY, PGOPTIONS default_transaction_read_only=on, statement_timeout10s/lock3s, comando20s, timeout globale40s; nessuna lettura credenziali, IAM, grant request, POST readiness o mutazioneDB. Proietta soltanto tre descriptor/grant del tenant (configuration.read, ingestion.configuration.attest, configuration.write), risorsa/constraint e stato della sola revisione/challenge/version/hash esatti. Legge anche il journal worker e authority scaduta per confrontare il conteggio persistito. Nessuna stampa di token o rawSQL output. Questo passaggio serve a preparare insieme i due endpoint prima di consumare un'altra finestra temporale.

# Tentativo THS successivo ancora bloccato403; verifica della seconda GET — 2026-10-17 11:00 CEST

**Fasi tecniche8/8; funzionali1/6.** Dopo la GETconfigurazione200/APPROVED/hash esatto delle10:58, l'operatore riporta nuovamente409 ONB_READINESS_DEPENDENCY_403 con0 decisioni confermate. Non è ancora noto se il rifiuto derivi dall'ingresso HUMAN in Ingestion, dalla lettura/attestazione compatibilità o dal successivo preflight UDP. Non ripetere automaticamente Verifica. ManagedActivationCoordinator conserva lo stato BLOCKED e il progresso; il lettore non chiama POST né attivazione.

Sorgente verificato: OnboardingReadinessService chiama prima frozenConfiguration, poi GET /api/internal/v1/onboarding/compatibility/ingestion-runtime e solo dopo eventuale probe e attestazione. IngestionCompatibilityApi usa ancora TrustedActorResolver.requireService -> ServletAuthorization.resolve, che valuta il contesto generico capability salvo binding server distinto; la GET configurazione corretta usa invece il registry sul contesto published-configuration/module ONBOARDING. Questo è un sospetto concreto per un ulteriore403, non causa target già provata. Nuovo scripts/read-onboarding-compatibility-dependency-20261017.py controlla la sola GET compatibilità e policy, stessi2GET/2token/4EngineGET/35s e review i220f2c0 già letta SHA21ca88f1c5aa682eb74612ead95c9bc6154ddf79a18a52af8f5d281e32abc605. Nessuna creazione attestazione o readiness. La lettura MCP ingestion_status in accountouf-admin è stata rifiutata authorization denied, senza retry e senza dispatch semantico.

Workerpolicy scade11:04:42 CEST; niente rinnovo implicito. Se termina, conservare journal e contatori e completare codice/qualifica/preparazione concreta prima di chiedere una nuova sessione finita HUMAN. Gli aggiornamenti Onboarding/Ing/MCP completati e la precedente approvazione sorgente non vanno ripetuti.

# Dipendenza configurazione ripristinata: GET200 APPROVED con hash esatto — 2026-10-17 10:58 CEST

**Fasi tecniche8/8; funzionali1/6.** Readback target indipendente del lettore post-resource-fix: journal29 completo, entrambe le generazioni stabili, rootArtifactReviewLinksMatch=true, nuova reviewSHA21ca88f1c5aa682eb74612ead95c9bc6154ddf79a18a52af8f5d281e32abc605 nel contesto onboarding-audit-execution-i220f2c0. Prova route conservata31ad562fa32c98472ee262bb0d8a800e3626443762e913b7863cce359e219d1d. GET SERVICE /api/internal/v1/onboarding/ingestion-configuration esatta ora200, approvedConfigurationReturned=true/exactConfigurationHashReturned=true; policyGET200/bundle40. Token non scaduti, expiry1792227727. Questo prova la risposta autorizzata dalla posizione host per questa richiesta, non il caricamento di snapshot nel processo Ingestion né l'attivazione della sorgente. La verifica locale di firme JWT/review non è stata eseguita e non viene dichiarata. Nessuna readiness, approvazione o proposta ripetuta dal lettore.

L'operatore è indirizzato al THS https://api.ouf-lab.it/trusted-human/onboarding/?challenge=ecf36c5c-10b2-4393-bf81-0ff7d28b8d5b : Aggiorna stato, ripresa esplicita della readiness BLOCKED e Verifica separata. Conservare approvazione già CONFIRMED, stessi source/version/configHash, tentativi e finestra readiness24h; nessuna re-approvazione sorgente, nuovo challenge o dispatch semantic.propose. La prima sessione worker resta aperta fino alla sua scadenza11:04:42 CEST; non viene estesa implicitamente. Milestone2 richiede lettura dell'esito persisted source ACTIVE/compatibilità e successivi invarianti; attualmente ancora1/6. Dopo attivazione: UDP/provenienza, ricerca chatbot, secondo import con riuso e Cinema8 invariato.

# Correzione risorsa SERVICE eseguita: lettura finale GET ancora da provare — 2026-10-17 10:56 CEST

**Fasi tecniche8/8; funzionali1/6.** L'operatore riporta OUF_ONBOARDING_AUDIT_FIX_RESULT complete=true/applicationReady=true/journalVersion29, contesto /etc/ouf/deploy-snapshots/onboarding-audit-execution-i220f2c0. maximumGatewayWrites0, newPolicyWorkerStarted=false, semanticDispatchPerformed=false, sourceActivationProven=false, acceptanceGranted=false. Non è ancora l'attivazione della sorgente.

Il lettore successivo scripts/read-onboarding-resource-fix-post-rollout-20261017.py lega esattamente il contesto nominato dall'operatore, la sorgente esecutore ed1fd76d5b77e4033f90b4010d4ca1e08f44ecea e la lineage b0e04a406ccda2dbfc6dd5743373866fa5ac1417b42ebfcbd57b2c3b6370e3ca; deriva l'hash review dagli artefatti root privati e verifica i legami review/decision/mandate/authority prima della lettura. L'operatore non ha fornito la SHA della nuova review: il report la rende esplicita, senza dichiarare verifica locale delle firme. Completo journal29, nuova generazione Onboarding e sorgente e02def25b47f653a1800db854594c73fadd9ba87, Ingestion invariata e route evidence31ad...; massimo4 EngineGET/2token/2HTTPSGET/35s, nessuna readiness, approvazione, emissione autorità o rinnovo. Solo dopo GETconfigurazione200/APPROVED/hash esatto: ripresa HUMAN nel THS e Verifica separata. Primo terminale policy ancora da mantenere aperto; scadenza11:04:42 CEST invariata.

# Correzione contesto risorsa SERVICE qualificata e pronta per review — 2026-10-17

**Fasi tecniche8/8; funzionali1/6.** Il readback target10:47 ha circoscritto il grant SERVICE: capability ouf.onboarding.configuration.read, READ/SERVICE/scope/tenant validi, resourceType published-configuration e unico attributo module=ONBOARDING. L'API aggiunta presentava source e soltanto onboardingVersionId. Correzione sorgente e02def25b47f653a1800db854594c73fadd9ba87: risorsa published-configuration con module=ONBOARDING e versione, costruiti dal metodo owner (mai copiati dal grant). Nessuna modifica della policy40 o dei grant. Restano i controlli SERVICE/scope, tenant della revisione, hash APPROVED e challenge CONFIRMED. Transazione audit corretta conservata.

GitHub Actions modulo39018776436 verde, incluso IngestionConfigurationAuditRuntimeTest con registry reale/PostgreSQL: grant vincolato a tipo/modulo/sorgente, vecchia risorsa negata, altro modulo e altra sorgente negati, API corretta APPROVED e hash esatto, audit+1 e approvazione/configurazione invariate. Browser39018776668 verde. Candidato39018776176 verde: artifact12095189192,554159333 byte,SHA256e83b63904b0fe05b67c82a61f1c6290a1ba3d0dfdd2334e65594d294629194cb, scansioneHIGH/CRITICAL/UNKNOWN incluse non corrette passata e attestazione publisher verificata nel workflow.

Esecutore e selezione ed1fd76d5b77e4033f90b4010d4ca1e08f44ecea; manifestSHA32ab03f9215fe9db7ef41589936527c993dfe0ce9dc2dca897bdd306cc8ee67e,29 file ripresi e confrontati byte per byte. La catena ora parte dal completato audit-fix md__yy6p/reviewb0e04a406ccda2dbfc6dd5743373866fa5ac1417b42ebfcbd57b2c3b6370e3ca/journal31, senza ripetere il primo aggiornamento. Test successore della singola app e vecchio piano due app passati, pin Ingestion conservato e inventario Gateway uguale. Qualificazione runtime27test root/Docker reali nel run39018828469; ripetizione sulla selezione finale39019042132. Fixture HTTP sintetiche: il target resta da eseguire e accertare, nessun milestone incrementato.

Consegna solo Onboarding, un APPROVO esatto, nuovo download554MB in cache separata39018776176; stessi mount/ambiente/rete/IP/MAC, vecchio container conservato. Nessun Gateway/Ing/DBschema/grant/dispatchsemantico modificato, nessun login o worker nuovo. Worker/HUMAN esistenti d0bmyv9g con scadenza policy11:04:42 CEST invariata; se finestra insufficiente blocco prima degli effetti, nessuna estensione implicita. Dopo il risultato occorre lettore legato a nuova review/generazione, GET200 con hash esatto, quindi ripresa HUMAN nel THS e Verifica separata. Non usare il lettore che lega ancora md__yy6p come generazione live dopo la sostituzione. Evidenza releases/ONBOARDING_CONFIGURATION_RESOURCE_FIX_EVIDENCE_20261017.json.

GitHub Actions39019042132 completata con esito success sulla selezione finale.

# Policy40: grant SERVICE esiste, risorsa API non corrispondente — 2026-10-17 10:44 CEST

**Fasi tecniche8/8; funzionali1/6.** Readback target: capability ouf.onboarding.configuration.read dichiarata, READ, SERVICE ammesso, scope presente nel token, tenant corrispondente, due grant ALLOW validi nel tempo. Primo grant: servicePrincipalMatchesToken=false. Secondo grant: servicePrincipalMatchesToken=true/subjectMatchesToken=true/tenantMatchesToken=true, resourceType published-configuration, resourceTypeMatchesSource=false, resourceAttributesMatch=false. Nessun vincolo su ruolo esterno/organizzazione/autenticazione/dataLabel/detailLevel. Token non scaduti, expiry1792226936, policy200/bundle40, GETconfigurazione403 ONB_INGESTION_CONFIGURATION_DENIED. Generazioni ancora stabili. Il metodo nuovo costruisce ResourceContext(source,sourceId,tenant,null,{onboardingVersionId}); non rappresenta la risorsa del grant SERVICE esistente. Non ampliare grant per aggirare questa differenza.

Il lettore v1 ometteva i valori dei vincoli; v2 scripts/read-onboarding-configuration-policy-constraints-20261017.py aggiunge soltanto nomi e valori limitati a una whitelist di attributi business, nessun dato di credenziale. Stessi due GET/read35s, nessuna mutazione. La correzione applicativa resta da implementare e qualificare dopo aver verificato gli attributi esatti: risorsa e attributi devono essere costruiti da stato dominio verificato, mai copiati dal grant o accettati senza confronto dalla richiesta. Non è ancora dimostrata l'attivazione della sorgente; milestone resta1/6. Scadenza worker11:04:42 CEST non estesa.

# Readback audit-fix: errore persistenza risolto, rifiuto policy da circoscrivere — 2026-10-17 10:39 CEST

**Fasi tecniche8/8; funzionali1/6.** Il lettore target verifica journal31, tutte le generazioni e la prova route31ad... stabili. La nuova GET SERVICE risponde403 ONB_INGESTION_CONFIGURATION_DENIED; il503 ONB_PERSISTENCE_FAILURE non si ripresenta. Token non scaduti (expiry1792226631); policy200/bundle40. Ingestion resta CID477ea664c97ebae2bf50a9fdb4d2ae92c20275cf28e5941f09c1133354908338, immagine63ed7299f85f57be676bd9633c08cc1dd87144fb84d3b13122e32f23f1e9370a e sorgentef869d8b86b892a0c03c147dac9bb40cd5f873ff2. Nessuna readiness né approvazione eseguita dal lettore.

Il metodo reale ingestionConfiguration emette lo stesso403 se AuthorizationPolicyRegistry nega la capability oppure se la riga di managed_onboarding_review non è unica o ha tenant diverso dal principal. La causa puntuale non è ancora dimostrata: non modificare grant né codice per aggirare il rifiuto. Prossimo controllo mirato in sola lettura scripts/read-onboarding-configuration-policy-metadata-20261017.py: stesse generazioni/review31, due token e due GET massimi, proietta soltanto descriptor/grant della capability ouf.onboarding.configuration.read e confronti con tenant/soggetto/servicePrincipal/tempi/risorsa dei metadati token. Nessun token, soggetto o servicePrincipal raw stampato; firma non verificata localmente e proiezione non equiparata ad autorizzazione effettiva. Non consulta né modifica DB, IAM, grant, worker o servizi. Se le policy non spiegano il rifiuto, resta da leggere il tenant della specifica revisione dal DB con sessione rigorosamente read-only. Worker corrente da mantenere aperto, scadenza11:04:42 CEST invariata.

# Correzione audit Onboarding completata sul target — 2026-10-17 10:36 CEST

**Fasi tecniche8/8; funzionali1/6.** Report operatore: OUF_ONBOARDING_AUDIT_FIX_RESULT complete=true/applicationReady=true/journalVersion31; contesto /etc/ouf/deploy-snapshots/onboarding-audit-execution-md__yy6p, revisione SHA256b0e04a406ccda2dbfc6dd5743373866fa5ac1417b42ebfcbd57b2c3b6370e3ca. maximumGatewayWrites0/newPolicyWorkerStarted=false/semanticDispatchPerformed=false/sourceActivationProven=false/acceptanceGranted=false. L'operatore ha approvato la review esatta; attese finite della sola health Onboarding concluse. Questa è evidenza del flusso esecutivo riportato, non ancora readback indipendente della GET configurazione.

Prossimo lettore in sola lettura: scripts/read-onboarding-audit-fix-post-rollout-20261017.py. Lega review/plan/scope/authority/journal31 e tutti gli11 effetti APPLIED; Onboarding alla nuova prova VERIFY_FINAL e sorgente c071be165a27fddbf73d9358d72dbf6448e34c85, Ingestion al pin esplicitamente conservato nel piano. Verifica l'hash della prova inventario Gateway conservata31ad562fa32c98472ee262bb0d8a800e3626443762e913b7863cce359e219d1d senza chiamare Admin API. Quattro Engine GET, due file token massimi da mount RO del processo Ingestion, due GET HTTPS verso l'origine già approvata,35 secondi; nessuna readiness o approvazione ripetuta. Rilegge entrambe le generazioni e journal dopo le richieste. GET configurazione200/hash esatto resta da dimostrare; dopo esito positivo segue ripresa HUMAN readiness nel THS e Verifica separata. Primo terminale policy da mantenere aperto fino alla scadenza già autorizzata11:04:42 CEST; nessun rinnovo implicito.

# STOP preparatorio riconciliato: pubblicazione policy corrente valida — 2026-10-17 10:31 CEST

**Fasi tecniche8/8; funzionali1/6.** Il primo lancio audit-fix ha restituito CURRENT_ACTIVE_POLICY_PUBLICATION_REQUIRED. Tutte le invocazioni di questo controllo precedono issue_action e gli effetti nativi: nessun aggiornamento Onboarding è stato eseguito. Il readback dell'operatore ha poi rilevato ACTIVE/RECOVERED, sessionHashMatches=true, attempts27, prior188, cumulative215, publications27, lastUpdateAgeSeconds7.619 e tokenRemainingSeconds291.946. Questo snapshot soddisfa tutte le condizioni precedenti; è compatibile con una lettura durante il rinnovo, ma lo stato esatto al momento dello STOP non è stato persistito e la causalità puntuale non è provata.

Esecutore corretto4f021a833a781df278ece094a1b30b347e5ebf8b: il lettore osserva soltanto NEW/SCHEDULED_RENEWAL_DUE, ATTEMPTING/FRESH_ATTEMPT o PUBLISHING/FRESH_EVIDENCE_READY già avviati dall'owner; massimo3 letture/30 secondi, attese5/15 secondi con jitter20%, nessuna chiamata grant o scrittura journal. Ogni lettura rivalida l'autorità firmata e hash/conteggi/pubblicazione/scadenza/freschezza. ACTIVE viene accettato soltanto con tutti i controlli validi. Stati terminali, ambigui, non conosciuti o campi incoerenti si fermano subito con codici distinti. Sei nuove regressioni coprono lo snapshot reale, tutti gli stati di rinnovo, stati bloccanti, integrità, limite di attesa e scadenza durante l'attesa. Manifest032b645c29493a705f064c7050954da9155a3d43751688173646e277f825caeb.

La nuova consegna riusa lo stesso candidato39016711997 già in cache sul VPS e ripresenta una sola review HUMAN per il solo Onboarding. Il worker corrente prosegue nello stesso primo terminale, con massimo316 cumulativi e scadenza11:04:42 CEST; nessun reset, nuovo login o sessione implicita. Il risultato target della correzione resta da ottenere e verificare.

GitHub Actions39017759772 verde:23 test root, incluso percorso Docker reale e6 regressioni della pubblicazione concorrente; due test import isolato verdi. La regressione applicativa PostgreSQL e l'immagine candidata restano quelle già qualificate.

# Audit Onboarding: correzione qualificata, esecuzione target ancora da fare — 2026-10-17

**Fasi tecniche8/8; funzionali1/6.** Il readback successivo al rollout conferma journal57 e le generazioni correnti. La nuova GET SERVICE configurazione esatta risponde503 ONB_PERSISTENCE_FAILURE; policy200/bundle40. Questo non prova ancora l'autorizzazione effettiva della GET né l'attivazione della sorgente. Nessuna approvazione o proposta è stata ripetuta.

Il metodo ingestionConfiguration era @Transactional(readOnly=true) e invocava il vero AuthorizationPolicyRegistry che registra obbligatoriamente un audit INSERT. La regressione con PostgreSQL e registry reale riproduce SQLSTATE25006 dentro una transazione read-only e passa dopo la correzione @Transactional, verificando audit+1 e configurazione/versione/approvazione invariate. Il precedente test mockava il registry. Non è stato letto lo SQLSTATE del target: il meccanismo è provato sul codice e nella regressione, il target resta da verificare.

Sorgente Onboarding c071be165a27fddbf73d9358d72dbf6448e34c85; CI applicativa39016712521 e browser39016712526 verdi. Candidato solo Onboarding39016711997: artifact12094604621,554159389 byte,SHA2567d20d2266d30c4647e52426af68ea24e8f908fa0fb4436bcc86b88d26e82b02c, scansione immagine superata. Esecutore0a665af6cb5c5d3b97744e61a277de8aa31410c5 qualificato in GitHub Actions39017241967:17 test root, firme reali, Docker/namespace reali con servizi HTTP sintetici, doppio avvio, perdita risposta senza replay, revoca/scadenza e attese finite.29 file sorgenti ripresi da GitHub e confrontati byte per byte con i pin del manifest d558467ddbae517ad4cb20ca6f95a07f0bfa7c76e17f180f574f06746d442317.

Il comando successivo riusa solo le sessioni HUMAN/policy correnti d0bmyv9g, scadenza policy1792227882 (11:04:42 CEST); verifica pubblicazione corrente, firme e fence prima della review. Un solo APPROVO per sostituire esclusivamente Onboarding, vecchio container conservato, massimo900 secondi. Ingestion e inventario Gateway devono restare identici; nessuna route scritta, migrazione, modifica grant, nuova sessione worker/login o replay approvazioni. Tenere aperto il primo terminale. Se il worker termina o la finestra residua è insufficiente, blocco prima degli effetti: nessun rinnovo implicito.

Dopo il risultato servono readback della nuova generazione e GET configurazione200 con hash esatto; solo dopo HUMAN riprende la readiness nel THS e usa Verifica separatamente. Non riusare il vecchio post-rollout reader che lega l'Onboarding precedente. Evidenza: releases/ONBOARDING_AUDIT_FIX_EVIDENCE_20261017.json. Trasporto specifico dell'installazione conservata, non qualifica multi-host; esiti mutativi ambigui restano da riconciliare.

# Rollout target completato; worker attivo per THS — 2026-10-17 10:08 CEST

**Fasi tecniche8/8; funzionali1/6.** Report operatore: OUF_READINESS_UPDATE_RESULT complete=true/applicationReady=true, journalVersion57, contesto /etc/ouf/deploy-snapshots/ingestion-readiness-execution-75a72ba23094c3c9; reviewSHA7ae31a7683794cba0209c006bd0699303fbd9890a5ef7a4c7000c48741ffd25b. Attese Onboarding/Ingres­tion superate. semanticDispatchPerformed=false/sourceActivationProven=false/acceptanceGranted=false: non è ancora il milestone2. Il processo è intenzionalmente in KEEP_POLICY_OWNER_RUNNING_FOR_THS_RESUME, non bloccato.

Sessione policy /etc/ouf/deploy-snapshots/ingestion-readiness-execution-d0bmyv9g; reviewSHA c42181ac012cd41417e2e9ec3c0f37908d3a5c0c379cc3805c918505f4bed5cd; authorityHash eec4345a68d09686909653238e5b0f9104b77f091f74084039a8f1666b01e39c; expiry1792227882. Journal semantic-functional-worker-ec7d462632c821d48dfc7aae409ff57282d77901ebd2991119bb6ebd00272748 sotto lo stesso intake/attempt.188 precedenti conservati, massimo316; quattro tentativi/pubblicazioni ACTIVE riportati dall'operatore, totale192 calcolato sul report (non ancora readback persistito del budget corrente). applicationReady=false del reporter policy descrive quel componente e non annulla applicationReady=true del rollout. OAuth67 era il conteggio prima del nuovo login; il conteggio corrente dopo login/firme non è ancora letto.

Prossimo controllo in sola lettura: lega review/plan/scope/authority/journal finale e le due generazioni live al VERIFY_FINAL; legge i due token già configurati in Ingestion senza stamparli; massimo due GET all'origine HTTPS approvata, nuova API interna di configurazione esatta e policy bundle. Non chiama readiness, non ripete conferme, non cambia budget o servizi. Poi ripresa esplicita HUMAN nel THS e Verifica separata, solo dopo aver accertato la dipendenza. Tenere aperto il primo terminale sul PC durante il controllo nel secondo.

# Consegna finale e riconciliazione iniziale verificata — 2026-10-17

**Fasi tecniche8/8; funzionali1/6.** Sorgenti esecutore finali a79a03558c5d470bcd6e8426ebc03e7f14093e19; la sola aggiunta dei test837919827eeda090fca15f9762604ce03e36b138 qualifica gli stessi byte runtime. GitHub Actions39015572693 verde:17 test root, compresa la regressione che rifiuta immagine cambiata dopo la review o inventario Gateway diverso durante la riconciliazione di VERIFY_INPUTS. Il percorso Docker/namespace completo resta verde. Manifest finale SHA25612852b05f10d95fbb6c7ab45a5f871de5ac611f8623a8ce419bf6bed3f2f88da. La revisione privata bovju9mj e i suoi native IDs restano identici. Sul target non sono ancora stati avviati né rollout né nuova sessione policy. Non usare il vecchio lettore di dipendenze per diagnosticare la nuova route: la GET SERVICE ora è /api/internal/v1/onboarding/ingestion-configuration con i tre parametri esatti sourceId/onboardingVersionId/configurationHash; il precedente endpoint HUMAN resta protetto.

# Revisione privata pronta ed esecutore readiness qualificato — 2026-10-17

**Fasi tecniche8/8; funzionali1/6.** L'operatore ha completato la preparazione sul VPS: revisione /etc/ouf/deploy-snapshots/ingestion-readiness-update-review-bovju9mj/review.json, SHA25613decb74cba1e54382a4493d80ff4a99c030f98d6afebd91beba61687f8a2898. Profilo Gateway uguale all'intero binding conservato, entrambe le immagini verificate, file delle migrazioni invariati. Nessun token, firma, grant, servizio, DB o Gateway è stato modificato dal preparatore. Native IDs: Onboarding sha256:d8adb455b34feb65daf31792a72ff71fbada14fafac14089da96c39556f95bf4; Ingestion sha256:63ed7299f85f57be676bd9633c08cc1dd87144fb84d3b13122e32f23f1e9370a.

L'esecutore limitato ha sorgenti in1b487b8d90ef54928adfd6156fee55e8e3cc7b2e e CI GitHub Actions39015170872 verde: import completo isolato senza effetti, firme Ed25519 dei due ruoli esistenti, revoca/scadenza/identità, doppio avvio, risposta persa senza replay, attese e contatori conservati, e prova reale Docker di due sostituzioni con mount/IP/MAC conservati e aggiunta HTTP nel namespace Gateway.16 test root passati, compreso il percorso Docker. Le applicazioni e l'Admin HTTP della fixture sono sintetici; i contratti applicativi e la route proiettata sono qualificati dalle CI dei tre repository candidati già registrate. Non è un readback o un'accettazione del target; resta limitato al trasporto locale al singolo host, senza adapter distribuito qualificato.

Consegna: nessun nuovo download908MB;21 overlay verificati del codice esistente/nuovo più bootstrap/loader/selection/package. Prima dei consensi, ricontrolla immagini selezionate, generazioni, intero inventario route e assenza del solo nuovo ID, Registry e autorità dei ruoli. Poi RIAPRO LOGIN con budget OAuth precedente conservato, browser, APPROVO per una nuova sessione policy128 su188 conservati (massimo316/3600s), primo token, APPROVO separato per Onboarding+Ingestion+una sola route GET. Due mandati e firme separati. Worker ed esecutore condividono il processo in primo piano; i lettori rollout osservano snapshot completati del worker senza contendere il suo lock CAS. Ctrl-C/scadenza cancellano; nessun rinnovo automatico.

Il rollout conserva i container precedenti, restituisce /actuator/health/readiness delle due nuove generazioni e confronta l'intera mappa Gateway prima/dopo una sola PUT. Nessuna migrazione DB, cambio grant, proposta semantica o approvazione sorgente. Ogni effetto ha un claim durevole e una sola esecuzione; STOP/esiti incerti richiedono riconciliazione del contesto, mai rilancio alla cieca. Il compilatore/journal espongono readback del claim; non è ancora consegnato un entrypoint generale di rinnovo/ripresa dopo ogni possibile guasto parziale. Dopo OUF_READINESS_UPDATE_RESULT resta un worker finito attivo per la ripresa HUMAN nel THS; non dichiarare sorgente ACTIVE o fine del percorso dal solo applicationReady. Prossimi passi: provare la GET M2M con credenziale Ingestion corrente, ripresa readiness nel THS con versione/generazione/codice esatti, Verifica separata; poi UDP/provenance/search/second import e Cinema8.

# Correzione della preparazione privata Gateway — 2026-10-17

**Fasi tecniche8/8; funzionali1/6.** Il preparatore precedente ha verificato entrambe le immagini, poi si è fermato con ROOT_INPUT_ANCESTRY_REQUIRED sul profilo Gateway selezionato. Nessun servizio, configurazione, grant, database o budget è stato modificato. Il pacchetto908MB resta nella cache verificata dell'operatore.

La correzione riutilizza le tre funzioni di custodia del modulo Gateway qualificato e le sue selezioni di proprietà già osservate, estraendole tramite AST da byte SHA256 fissati senza importare il publisher. Legge esclusivamente /opt/ouf/installation/active-projection.json e richiede uguaglianza dell'intero binding conservato (percorso, hash, identità e metadati). Tutti gli altri input protetti mantengono la custodia root. Nessun chown sul target. La verifica precede ora copia e analisi delle immagini e viene ripetuta alla fine. Il launcher riutilizza la cache e verifica quattro dipendenze prima di sudo.

La preparazione produce solo una nuova revisione privata: restano da qualificare l'esecutore limitato e la sua decisione HUMAN prima di rollout o nuova sessione worker. Le approvazioni semantiche e della sorgente restano conservate.

# Binding VPS confermati e profilo di collaudo rinnovabile esplicitamente — 2026-10-17

**Fasi tecniche8/8; funzionali1/6.** Il readback operatore delle09:07:13 CEST conferma le tre generazioni Onboarding/Ingestion/APISIX stabili e il worker terminato:60 tentativi/pubblicazioni,128 precedenti, **188 controllati cumulativi su197**,9 residui sotto la vecchia revisione. CANCELLED_BY_OWNER, autorità scaduta, lock libero, admissionBLOCKED; i quattro record hash sono in evidence/ingestion-readiness-current-bindings-and-test-profile-20261017.json. Ora il totale188 è provato dal readback, non solo calcolato sul report del terminale.

Chiarimento dell'operatore09:09:08 CEST: siamo in configurazione/collaudo e il budget non deve costringere a ripercorrere il bootstrap. Il nuovo profilo versionato consente una **nuova sessione da128 tentativi/3600s**, conservando188 e portando il nuovo tetto a316 solo dopo nuova decisione HUMAN corrente. Non modifica il vecchio tetto197 o i suoi record e non azzera contatori. Reviewv3 conserva il fence del predecessore, richiede il profilo esatto e la decisione esplicita di nuovo budget; niente rinnovo automatico né replay del primo grant. Rimangono separati storico OAuth e approvazioni di dominio già confermate.

CI native39013288278 **PASS**: test nuovi/precedenti, root custody, firme esistenti, handoff persistente del fence, primo grant TLS reale nella fixture,188->189 senza modifica del predecessore e rifiuto del replay. Questo qualifica il proprietario del nuovo budget, non ne avvia una sessione sul target. Il futuro entrypoint di esecuzione deve ancora integrare e qualificare questa nuova review.

Pacchetto candidati39011934307 **SUCCESS**, artifact12092994033, ZIP908091225 byte, SHA2560f744ae117672199ccf7309988122b75e48bf37fb5da98796a428abb70a30033, publisher88140b19828466c584432d3c793f7e09408ddff3; attestazione publisher verificata dalla CI. Due immagini e pacchetto Gateway a SHA esatti già riportati nella source lock. Nessuna migrazione nuova:33 fileSQL Onboarding e18 Ingestion identici al sorgente installato.

Preparatore privato: scripts/prepare-ingestion-readiness-update-review-20261017.py a16860a78811da6da60a645680a64df3d3ac08a0, SHA2568c2ddda5d90b7516ee5443468589bcc220119e5c125589996d6d1aa583fc6d4e. Selection SHA25618ff5a8436d2058c6e9c6820cf8b017facb58e42ce718eee4bf0c1591781ae40. Scarica/cache del solo artifact nuovo; verifica ZIP/hash completi, configura immagini tagless con image_custody già qualificato, deriva la sola route interna usando la proiezione target conservata e il materializzatore Gateway autentico. Nessun token, firma, grant, stop, load immagine, migrazione o PUT Gateway. Produce una nuova review root0600 con readyForExecution:false e i gate ancora necessari.

Prima di avviare login/worker: completare qualificazione entrypoint nativo ristretto per due immagini e una route, collegare la review privata prodotta sul VPS, guardare generazioni correnti/assenza della route e solo allora ottenere decisione corrente per rollout e nuova sessione di collaudo. Fonte APPROVED/CONFIRMED e semantica ACTIVE restano conservate. Dopo rollout: HUMAN riprende espressamente il blocco403 e avvia una verifica distinta; poi ingestione/UDP ACK/lineage/ricerca/seconda acquisizione/preservazione Cinema.

Nota di integrità: il nuovo codice del budget richiede l'aggiornamento dei due hash nella capsula corrente e del relativo pin nel deliverer. Le versioni Git storiche e i loro comandi restano immutabili; non rilanciare la consegna originaria delle8 fasi.

---

# Fonte Teatri approvata: verifica bloccata dal percorso SERVICE/HUMAN — 2026-10-17

**Fasi tecniche 8/8; funzionali 1/6.** La semantica è ACTIVE. La fonte teatri-csv-6609b245, versione9860853e-e8f3-4b93-b9d2-03521a039962, è **APPROVED/lock3**, challenge ecf36c5c-10b2-4393-bf81-0ff7d28b8d5b **CONFIRMED**, hash sha256:ae7f46b4214d09c55a9885530920026258f0dcd588462c353b06d82185e12c9b. La conferma è conservata anche se il termine originale della challenge è trascorso. Attivazione BLOCKED, attempt1/generation1, ONB_READINESS_DEPENDENCY_403; compatibilità Ingestion non ancora provata. Non ricreare source/versione/challenge né ripetere semantic.propose.

Il readback operatore delle08:49:47 CEST osserva Ingestion c48ee4b1873a474e81c6e1be70d393854021e2c1, generazione stabile, token non scaduti: GET configurazione frozen403, GET policy200/v40. Trasporto dal solo host: non prova lo snapshot caricato né identifica da solo ogni hop della chiamata originaria. Il sorgente conferma l'incompatibilità: PublicationGatewayClient usa il wildcard lifecycle /api/onboarding/v1/sources/*, materializzato solo HUMAN, con bearer SERVICE.

Correzioni draft coordinate: [Onboarding42](https://github.com/GioNob/ouf-source-onboarding/pull/42)382cbec4…, [Ingestion42](https://github.com/GioNob/ouf-ingestion-runtime/pull/42)f869d8b8…, [Gateway78](https://github.com/GioNob/ouf-api-gateway/pull/78)425a0377…. Nuovo GET interno con capability configuration.read esistente, solo identità Ingestion proiettata; owner verifica policy corrente, tenant del managed review, stato APPROVED, conferma e hash/versione. Nessuna estensione del wildcard HUMAN. Ripresa THS esplicita del solo blocco403 con hash/lock/generazione/codice attesi e audit; conserva tentativi e inizio budget, incrementa il fence, non attiva automaticamente. Esaurimento e ambiguità restano bloccati.

CI: browser THS39011677971 PASS; Ingestion39011682281 PASS (Java/PostgreSQL, restore drill, image/SBOM/scan); Gateway425a…39011806193 e39011806192 PASS. Onboarding39011677968 PASS, inclusi test Java/PostgreSQL, container non-root, scan e smoke di staging. Nuovo workflow ingestion-readiness-candidates produce solo due immagini e il pacchetto Gateway, da SHA esatti e con scan HIGH/CRITICAL/UNKNOWN inclusi unfixed, hash completi e attestazione publisher; **nessuna autorità target**.

L'operatore riporta policy remainder terminato al ciclo60 con CANCELLED_BY_OWNER e NO_AUTOMATIC_RESTART_OR_RESET. Storico controllato prima di questa sessione128, massimo197: 188/197 e9 residui sono solo calcolo sul report del ciclo60, da riconciliare sul journal prima di qualunque nuova review; non sono readback indipendente. OAuth HUMAN resta separato, nessun reset o rinnovo automatico. Prima di una nuova sessione preparare l'intervento concreto e i binding correnti, non consumare login durante build/CI.

Prossimi passi: completare qualification e pacchetto; leggere generazioni, route e ledger correnti in sola lettura; preparare revisione privata del rollout Onboarding/Ingestion e della sola route nuova senza migrazioni o grant; approvazione runtime secondo percorso esistente, poi HUMAN riprende e avvia la verifica. Restano ingestione13 righe, ACK/lineage UDP, ricerca chatbot e seconda acquisizione con riuso/no duplicati e preservazione degli8 Cinema. Nessun commit UDP o accettazione end-to-end provato.

---

# Fonte Teatri IN_REVIEW: pronta per decisione HUMAN e attivazione separata — 2026-10-17

Dopo autorizzazione esplicita dell'operatore alle08:33:51 CEST, una sola source.onboarding.create è stata eseguita con l'esatto createDraft della revisione695f12a4…: **DRAFT** sourceId teatri-csv-6609b245, onboardingVersionId9860853e-e8f3-4b93-b9d2-03521a039962, stesso asset6609b245… / profilo7984c39c…v1. Lettura owner corrente DRAFT/lock0 riconciliata prima della preparazione. Non ricreare fonte/versione né ricaricare il CSV.

source.onboarding.review.prepare, commandKey teatri-csv-6609b245-review-9860853e-v1, expectedVersion0, ha restituito **IN_REVIEW/lock2**, configurationHash sha256:ae7f46b4214d09c55a9885530920026258f0dcd588462c353b06d82185e12c9b. Challenge ecf36c5c-10b2-4393-bf81-0ff7d28b8d5b CREATED, scadenza2026-10-17T06:44:56.899Z (**08:44:56 CEST**); reviewUrl owner https://api.ouf-lab.it/trusted-human/onboarding/?challenge=ecf36c5c-10b2-4393-bf81-0ff7d28b8d5b. humanApprovalRequired:true; ingestionCompatibilityObserved:false; activation readiness NOT_STARTED/attempt0/generation0. Nessuna approvazione, attivazione o commit UDP eseguiti dall'agente.

ExecutionProposal preparato e incluso nella configurazione revisionata:13 righe/20 colonne/maxCellChars4096;20 valori STRING lessicali IDENTITY e access label RESTRICTED, chiave locale nome_teatro. Riferimenti esatti alla revision a1db3912… e publicationSet9fe7d1ee… attivi. Politica GOVERNED_IDENTITY proposta con confronto TEXT_V1 su tutte20 le proprietà, una regola sufficiente che le richiede tutte, max100 candidati, allowAutoNew:true; nessuna proprietà dichiarata uniqueWithinScope o excludesOnDisagreement, nessuna equivalenza Cinema. Assertion/policy URN contengono proposal e non rappresentano grant/autorità esistenti: diventano configurazione operativa soltanto dopo la decisione diretta HUMAN. Materializzazione conserva stringhe, autorità ordinata soltanto della fonte entrante, nessun bitemporalProperty inferito, checkpoint1. Preparazione strutturale non prova matching positivo né execution/compatibility.

Prossimo passo HUMAN nella pagina THS: leggere configurazione, proprietà/accesso/chiave/politica UDP, selezionare la proposta e **Approva la configurazione**; poi azione separata **Verifica e attiva la fonte approvata**. Non eseguire queste decisioni tramite agente/VPS/MCP. Se risposta interrotta, rileggere source.onboarding.read con stessi IDs prima di ripetere qualunque azione. Le letture provano stato corrente, receipt/storico non approvazione. Evidenza completa con gli argomenti della preparazione: evidence/chatbot-teatri-source-native-human-review-20261017.json.

**Tecniche8/8; funzionali1/6.** Sei milestone stabili: (1) semantica approvata THS PROVATA; (2) onboarding approvato HUMAN pendente; (3) commit UDP effettivo13 righe/provenienza; (4) nuova ricerca chatbot effettiva; (5) secondo import CSV senza duplicati; (6) entrambe acquisizioni e tutti8 Cinema baseline invariati. Non confondere creazione DRAFT con milestone2 completata. Worker policy corrente resta finito alla scadenza1792219616, nessun rinnovo/reset. Se la finestra scade, riconciliare e preparare soltanto il passo autorizzato; non rilanciare grant/installer già completati.

---

# Semantica Teatri ACTIVE verificata; onboarding DRAFT richiede consenso esplicito — 2026-10-17

L'operatore ha completato le azioni nella THS. Verifica indipendente MCP semantic.search + semantic.get con pin esatti: **ACTIVE**, artifacte34887ee-e101-4a2c-9ecc-7927a15f795c, revisiona1db3912-2b72-42eb-af88-a775fcd0e2ab, publicationSet9fe7d1ee-9e13-40bc-ad50-53e36ea0076b, checksum632fe084bdb359afe419bbf5651fc4711930c31e5cf1503c8da19cace803af28. Hash contenuto governatoc96bb4c8…, snapshot Turtle6e4668ea… completo105 triple, partial:false/dependencies_partial:false. Tutte20 proprietà della mappatura e la classe schema:PerformingArtsTheater sono presenti come termini RDF asseriti in questa revisione/pubblicazione. **Prima milestone funzionale provata:1/6; tecniche8/8.** Nessuna classificazione Cinema inferita.

Preview MCP attuale dell'asset6609b245-86ed-4315-8ce0-73f2a8555bf3 e profilo7984c39c-7396-4248-ab0a-f2efc390b49c v1 conferma13 righe20 colonne; preview redatta, nessuna lettura dei byte CSV. Le inferenze LONG/DECIMAL/DATE del profiler non autorizzano coercizioni: usare IDENTITY e stringhe lessicali per CAP, coordinate, capienza e date; preservare note e qualificatori.

Predisposta bozza fonte teatri-csv-6609b245, nome Teatri di Trieste - CSV, ownerHUMAN b93d8cf6-cd14-4ee6-91d7-84cd76c4f500, stesso asset/profilo, riferimento TeatriOntology@1.0.0, chiave locale nome_teatro,20 field decisions INCLUDE/RESTRICTED/IDENTITY con IRIs della revisione verificata. **Creazione non eseguita:** la revisione automatica ha rifiutato source.onboarding.create prima dell'esecuzione perché il consenso verificabile copriva la bozza semantica, non la nuova configurazione fonte e i suoi metadati RESTRICTED. Non aggirare via Gateway/VPS, account alternativo o nuova chiave; nessun retry eseguito. Occorre autorizzazione esplicita dell'utente a creare questa DRAFT e prepararla per sua revisione THS, senza approvarla/attivarla. Revisione concreta releases/TEATRI_MANAGED_CSV_ONBOARDING_REVIEW_20261017.json; evidenza evidence/chatbot-teatri-active-semantic-onboarding-review-block-20261017.json.

Dopo consenso: inviare esattamente createDraft della revisione sul link ouf-admin; una sola richiesta, poi leggere la versione owner corrente. sourceId rimane stabile per la riconciliazione. Nessuna ri-upload o nuova profilazione. Preparare executionProposal con binding revision/publicationSet esatti e dati lessicali, limiti finiti e politica UDP esplicitamente proposta per decisione HUMAN nella THS. Non inventare equivalenze/autorità/claim o dichiarare matching positivo da questo solo CSV. Chiave nome_teatro valida soltanto finché resta stabile; classificazione RESTRICTED è proposta per revisione umana, non prova di accesso pubblico. Resta THS diretta per approvazione/attivazione della fonte, poi ingestione/UDP, verifica oggetti e matching positivo separato. CSV E2E e release acceptance non provati.

---

# Bozza Teatri creata e validata; decisione umana THS pendente — 2026-10-17

Dopo il blocco automatico, l'operatore ha autorizzato esplicitamente alle08:20:52 CEST l'invio dell'esatto Turtle a OUF MCP con ouf-admin per una sola DRAFT. Una sola chiamata eseguita di semantic.propose dopo quel consenso, stesso commandKey teatri-semantic-draft-be74308e098aa3a6-20261016 e requestHash b8bc4ccb… originale: **DRAFT creata**, artifactId e34887ee-e101-4a2c-9ecc-7927a15f795c, revisionId a1db3912-2b72-42eb-af88-a775fcd0e2ab, semanticId https://api.ouf-lab.it/semantic/teatri#TeatriOntology,105 triple, hash Turtle6e4668ea42cf1c75b822e17a8ca9cb71fb2c4d8f500eed628282fa6039a6dbaa. Lettura della receipt riconciliata: snapshot storico, non stato corrente. Non ripetere CREATE o cambiare key.

semantic.review.prepare con expectedRowVersion0 e key teatri-semantic-validate-a1db3912-20261017 ha restituito **PASS**, zero errori, un warning VAL-008 su description: Descrizione mancante. validationRunId e6f4c019-6cf5-4a6f-91f6-34f018747937, validator ouf-sem-validator/1.0, validated row0. Hash dell'intero contenuto governato c96bb4c80f2c5b32616b2c8632438213dd7e269728e005612acb46970830da1f è distinto dal digest dei soli byte Turtle e non va sostituito con esso. Non modificare ora la descrizione per eliminare il warning: cambierebbe il contenuto revisionato.

semantic.approval.request con key teatri-semantic-review-a1db3912-20261017, row0 e quel validationRunId ha prodotto **UNDER_REVIEW / challenge OPEN**27efcfc3-0c51-4715-a92f-1f371c7ab19b, trustedApprovalRef ths://semantic-approval-challenges/27efcfc3-0c51-4715-a92f-1f371c7ab19b, scadenza2026-10-17T06:37:19.743Z (**08:37:19 CEST**). Nessuna approvazione/pubblicazione semantica eseguita dall'agente. Occorre la decisione diretta HUMAN nella pagina THS OUF, che rilegge il contenuto corrente e usa CSRF; approvazione e pubblicazione sono azioni separate dell'utente.

Pagina browser verificata nel sorgente Onboarding WorkflowThsApi/workflow-review.js: /trusted-human/semantic/?challenge=27efcfc3-0c51-4715-a92f-1f371c7ab19b. Origine da derivare dalla selection.origin del bundle privato firmato già sul VPS, non inventare host e non estrarre/copiarvi token dalla chat. Fornita lettura locale dei soli metadati per stampare il link. Restano HUMAN approvazione/pubblicazione e verifica revision/publicationSet esatti prima del mapping Onboarding; poi source review/attivazione, ingestione/UDP e verificaCSV. Non effettuare ulteriori richieste create/validate/review automaticamente se la finestra scade: prima riconciliare lo stato owner corrente.

Evidenza evidence/chatbot-teatri-native-draft-human-review-20261017.json. **Tecniche8/8, funzionali0/6**: la prima milestone richiede la configurazione semantica approvata tramite THS, ancora pendente. Worker policy9xl_yy2c resta finito, scadenza1792219616, nessun rinnovo o reset. MCP target già aggiornato con applicationReady:true; nessuna nuova operazione su infrastruttura è necessaria per aprire la pagina umana.

---

# Aggiornamento MCP target completato; invio DRAFT bloccato dalla revisione automatica — 2026-10-17

**Esito VPS fornito dall'operatore:** OUF_SINGLE_MCP_UPDATE_RESULT complete:true, applicationReady:true, journalVersion35, semanticDispatchPerformed:false, acceptanceGranted:false. Launcher v3 al commit0ea11443… / codice800b62fd…; aggiornamento del solo MCP completato, senza dispatch semantico. Il path del nuovo context non era incluso nella sola riga finale ricevuta: non attribuire il successo ai context precedenti molgvvlx/wuh0r5kr che si erano fermati prima delle approvazioni. Nessun nuovo login/reset/riarmo o cancellazione claim.

Dopo il completamento, una lettura MCP indipendente semantic.proposal.read con account ouf-admin e stessa chiave teatri-semantic-draft-be74308e098aa3a6-20261016 ha restituito404 PROPOSAL_RECEIPT_NOT_FOUND. Integrità del payload verificata prima dell'azione: importCommand canonico f7d2b21a…, Turtle6e4668ea…, hash argomenti MCP b8bc4ccb0f8fe48764ecf87340fd2ff209520c0b5b947a3ee6a1e461fc57a112 uguale al claim originale, riproducendo l'escaping HTML di encoding/json Go. Nessun cambio di contenuto, account o commandKey.

**Blocco attuale:** la chiamata semantic.propose con quell'esatto importCommand è stata rifiutata dalla revisione automatica PRIMA dell'esecuzione MCP: l'autorizzazione utente verificabile non copriva chiaramente il trasferimento del Turtle locale a quella destinazione e la creazione di una receipt DRAFT durevole. Non aggirare tramite VPS/Gateway, altro account, tool o nuova chiave; nessun retry è stato eseguito. Completato il lavoro non bloccato e richiesta all'utente autorizzazione esplicita sul payload/destinazione/DRAFT. Un consenso all'infrastruttura o un permit non equivale all'approvazione del contenuto. Anche dopo autorizzazione dell'invio, nessuna approvazione/pubblicazione semantica fuori THS. Conservare tetto massimo una ulteriore chiamata/totale2 e scadenza del permit; se la finestra scade non ricreare o rinnovare automaticamente.

Proposta esatta già presente: releases/teatri-reuse-semantic-proposal-20261014.json, proposalHash be74308e098aa3a65396f3df739dd8f2837e9f8e27b6e49deb0e49d04506cb1a. Solo importCommand+commandKey costituiscono il payload, con link ouf-admin per selezionare l'account; nessun valore CSV o credenziale. Evidenza evidence/chatbot-semantic-mcp-target-update-and-draft-review-block-20261017.json. **Tecniche8/8; funzionali0/6; chatbot/CSV E2E non provato.** Tenere il worker policy attivo nel terminale corrente durante il passo autorizzato; non rilanciare i vecchi comandi né azzerare i contatori.

---

# Segreto PostgreSQL dell'operatore: lettura dal mount attivo qualificata — 2026-10-17

Il secondo ingresso MCP_UPDATE `semantic-mcp-update-execution-wuh0r5kr` si è fermato con STOP sanitizzato ROOT_CONTROLLED_ADMIN_SECRET_ANCESTRY_REQUIRED, ancora prima delle revisioni/authority infrastrutturale. Il nuovo readback metadata target (zero file di credenziali letti) prova file regolare/nlink1/0600 UID:GID1000:1000, stesso inode visto da host e processo PostgreSQL, bind in sola lettura; antenati host1000:1000/0700 e0750. Non mutare ownership, password o mount per aggirare il controllo.

Source `800b62fd1a03781efefb38e5c2f1595ab27f9206`: canale esplicitamente selezionato nel case v3 con schema `ouf.postgres-mounted-secret-custody.v1`, route PINNED_POSTGRES_ROOT_FD, UID/GID1000 e mode0600. Verifica generazione Docker PostgreSQL prima/dopo, PID/start ticks e mount namespace, apre la root kernel del processo e attraversa componenti con fd e O_NOFOLLOW, verifica il mount ID del file contro mountinfo e ro effettivo, proprietario/permessi/nlink/dimensioni, identità stabile e mount invariato dopo la lettura. Non legge il file tramite gli antenati host dell'operatore e non allenta il ramo host legacy. Il segreto non viene stampato; DSN amministrativo solo al migratore.

[CI scoped39009094649](https://github.com/GioNob/ouf-deploy/actions/runs/39009094649) job117327538762 PASS. [CI native39009094657](https://github.com/GioNob/ouf-deploy/actions/runs/39009094657) job117327538722 PASS: PostgreSQL reale con directory e file1000:1000/0600, vecchio ramo host rifiutato, proprietario errato rifiutato, namespace/fd/mount ro verificati; tutte16 fasi, backup, migrazione atomica e bootstrap del vero MCP. HUMAN/Authorization/chiavi della CI sono fixture sintetiche, zero operazioni target o tool semantici. Evidenza `evidence/chatbot-semantic-mcp-namespace-secret-custody-20261017.json`.

Lettura owner indipendente ripetuta quando il codice corretto era pronto:404 PROPOSAL_RECEIPT_NOT_FOUND sulla stessa connessione ouf-admin, observedAt1792217651, massimo300s. Case/package `semantic-mcp-scoped-update-v3-…-20261017.json` sigillano questa prova e il tokenContext attivo9xl_yy2c; nessun nuovo login o rinnovo automatico. Non rilanciare v1/v2. Nuovo ingresso esplicitamente rivisto: due APPROVO separati, permit massimo un ulteriore tentativo/totale2 e poi singolo aggiornamento MCP+backup+migrazione12->13; nessun dispatch semantico. Lasciare aperti entrambi i terminali. **Tecniche8/8, funzionali0/6: aggiornamento target ancora non provato.** Tutti i journal, le scadenze e i budget precedenti restano vincolanti.

---

# Canale PostgreSQL FILE qualificato; prossimo aggiornamento MCP separato — 2026-10-17

Worker policy avviato sul VPS nel context `semantic-mcp-update-execution-9xl_yy2c`, authority5a0ed585… con scadenza1792219616; OAuth61 al suo avvio, tetto128 mantenuto. Predecessore controllato128, massimo69 ulteriori entro197. Non rilanciare il launcher policy: mantenerne aperto il terminale. Il controllo live `ouf-semantic-policy-refresh-v3.ir6MSer4/read.log` ha provato token non scaduto e GET200 della policy40 attesa, solo dal trasporto host; snapshot caricato dal Registry ancora non provato.

Primo ingresso MCP_UPDATE nel context `semantic-mcp-update-execution-molgvvlx` fermato prima delle revisioni/firme/authority infrastrutturale: PostgreSQL usa POSTGRES_PASSWORD_FILE, non POSTGRES_PASSWORD. Un refuso nella gestione dell'eccezione ha prodotto un secondo traceback. Sourcecorretto `8a50e878c74a3c1ab131aa57d1366887b089803d`: legge solo il bind esatto in sola lettura della generazione PostgreSQL selezionata, verifica root ancestry/mode/nlink/dimensioni/identità prima e dopo, non stampa segreti e li usa solo nel DSN del migratore. Trim LF coerente con l'entrypoint PostgreSQL. Gestione STOP corretta e verificata. Il readback target dei soli metadati ha confermato amministratore e canale FILE senza leggere file di credenziali.

La prova completa ha inoltre rilevato l'ordine variabile di Docker Mounts: l'ingresso e il piano conservano tutti gli oggetti mount e confrontano la proiezione canonica per destinazione; la generazione e tutti i metadati devono coincidere. Nessuna sorgente o permesso può cambiare. [CI scoped39008633533](https://github.com/GioNob/ouf-deploy/actions/runs/39008633533) job117326176308 PASS; [CI native39008633524](https://github.com/GioNob/ouf-deploy/actions/runs/39008633524) job117326176353 PASS16 fasi con vero PostgreSQL configurato FILE e vero MCP, backup, migrazione atomica, salute e rifiuti delle firme/profili errati. Fixture HUMAN/Authorization/chiavi sintetiche; zero tool semantici, zero effetti target dalla CI.

Nuova lettura owner indipendente sulla connessione ouf-admin dopo la correzione:404 PROPOSAL_RECEIPT_NOT_FOUND, observedAt1792217190 (limite conservativo), valida300s. Selezione `releases/semantic-mcp-scoped-update-v2-selection-20261017.json`, package v2 abbinato, stesso context policy attivo e revisione atomica69e052d9… già presente. Due decisioni APPROVO separate restano necessarie: permit di massimo una chiamata aggiuntiva/totale2, poi singolo aggiornamento MCP+backup+migrazione12->13. Il launcher non invia la proposta; contenuto e approvazione semantica rimangono nel THS. Non rilanciare il primo ingresso fermato e non azzerare/rimuovere/rearmare alcun claim. **Tecniche8/8, funzionali0/6; aggiornamento target ancora non eseguito.** Evidenza `evidence/chatbot-semantic-mcp-admin-file-channel-recovery-20261017.json`.

---

# Ingresso policy finito qualificato e pronto al login — 2026-10-17

**Fasi tecniche 8/8; milestone funzionali 0/6. Nessun nuovo effetto VPS provato.** Il readback HUMAN conferma sessione precedente READY/USERINFO scaduta, 49 richieste OAuth cumulative su128, 79 residue, nessuna richiesta ambigua o stato bloccato, lock libero. Worker precedente CANCELLED_BY_OWNER, 128 tentativi controllati cumulativi; massimo69 ulteriori entro il tetto197. Nessun azzeramento e nessun rinnovo automatico.

**Comando successivo concreto:** `scripts/launch-semantic-mcp-policy-remainder-20261017.sh` al commit `517bb3b39ad71cc6ea193b1c4215cec84e1b2d8c`, SHA256 `f65beb40eda3cab111e6e81b13b0b4978db04035ddee85e417574a9b589cc99a`. Scarica sorgenti chiusi da `c651d4d6d404facc96d8455180a95103c8059152`, package da `a7ab4891cfc43fd68654e7506659b5c9a42fa805`, li verifica nuovamente sotto root e usa Python -I -B -S. Solo TOKEN_SESSION: consenso esatto RIAPRO LOGIN, autenticazione browser HUMAN, poi APPROVO separato del worker policy per massimo3600s. Passaggio del fence monouso, senza cancellare il journal precedente. Nessun aggiornamento MCP o dispatch semantico da questo launcher. Dopo STARTED e primo ACTIVE continuare subito; il reporter conserva applicationReady:false e non prova readiness applicativa.

[CI GitHub Actions39004051839](https://github.com/GioNob/ouf-deploy/actions/runs/39004051839), job117312759000: PASS26 esecuzioni di test in sei suite (quattro test authority ereditati anche nella suite permit). Custodia stdlib reale, due firme dei ruoli esistenti, grafo completo chiuso, composizione root con TLS e richiesta token reale nella fixture, custodia del launcher con rifiuto di bytes alterati/symlink/hardlink. HUMAN e consensi terminale sono confini sintetici espliciti: non sostituiscono login/approvazione sul VPS. Anche il sorgente congelato c651 ha CI scoped39003696449 e backup reader39003696503 PASS. Evidenza `evidence/chatbot-semantic-mcp-scoped-execution-qualification-20261017.json`.

**Dopo policy ACTIVE:** ottenere la prova corrente di policy dal trasporto selezionato e una nuova lettura indipendente della receipt owner sull'account ouf-admin/link_6aafef96b4148191b767e9af7b756a07. L'ultimo403 non prova assenza e non va ripetuto automaticamente. Solo con nuova prova di recupero e receipt404 verificata, produrre selezione sigillata MCP_UPDATE legata al nuovo context: revisione separata del permit (massimo una chiamata aggiuntiva, due cumulative, stessa chiave/richiesta), poi revisione infrastrutturale separata del singolo aggiornamento MCP. Il codice composto è presente e qualificato ai confini dichiarati; l'ingresso MCP_UPDATE completo sul target e le milestone CSV restano aperti. Usare la revisione atomica VPS69e052d9… già presente, non ricrearla. Nessuna approvazione semantica fuori THS.

---

# Avvio MCP reale qualificato; revisione atomica presente sul VPS — 2026-10-17

**Fasi tecniche 8/8; milestone funzionali 0/6.** Il VPS ha prodotto la revisione privata `/etc/ouf/deploy-snapshots/semantic-mcp-atomic-update-review-kes27w1j/review.json`, SHA256 `69e052d9bfab8607bc871af3027c1da3a09781faa1f2778b365d0779af0cf9e8`, immagine nativa `sha256:b11b656d22e2ab42a304d251ead2d04f301a1f3481b1925ca1a5d29dc545eeac`. Predecessore `02590e54…`; cumulativo controllato128 preservato. Nuova directory privata soltanto: nessuna firma, grant, stop, migrazione o modifica ai servizi. `readyForExecution:false` e nessuna authority. Evidenza `evidence/chatbot-semantic-mcp-atomic-review-target-20261017.json`; log `/home/oufadmin/ouf-semantic-mcp-atomic-review.zWYQ0Ae6/prepare.log`.

**Chiuso il precedente limite del processo sostitutivo sintetico nella qualifica.** [CI GitHub Actions39001335478](https://github.com/GioNob/ouf-deploy/actions/runs/39001335478), job117304709858, source189b1c6a06459d77f65fa70895ddb365c94e0354: PASS11 fixture firmati e16 fasi con il vero binario MCPf00e. Effetti Docker/PostgreSQL17 reali e usa il migratore atomico, backup verificato con pg_restore, stesso endpoint, vecchia generazione fermata. Il server reale persiste il manifest embedded, verifica i metadati root0440 e le due firme Ed25519, carica una policy tramite TLS verificato e risponde204 a live/ready con UID/GID10005:10005. Rifiuta ingresso senza contesto Gateway, hash profilo errato, firma alterata e profilo scrivibile. Membership retention0, nessuna sessione di reprocessing aperta e claim precedente invariato. Authorization HTTPS, HUMAN e chiavi sono fixture usa e getta, non istanze di produzione. Chiamate semantiche0 e operazioni VPS0. Evidenza `evidence/chatbot-semantic-mcp-real-bootstrap-qualification-20261017.json`.

L’entrypoint autenticato di produzione resta da completare. Il prossimo dato necessario è il contatore **OAuth HUMAN**, distinto dai128 grant controllati del worker. I reader precedenti non aprivano quel journal. Il reader specifico `scripts/read-chatbot-human-oauth-budget-20261017.py` apre in sola lettura l’authority nota e il journal `human-session-window2/recovery.json`, ne verifica il binding contro l’hash HUMAN dell’authority e la discendenza dalla finestra con42 tentativi, restituisce soltanto conteggio/stato/scadenza/ambiguità. Il journal contiene credenziali: nessun valore o hash del journal viene emesso, nessun bearer file viene aperto, nessun login o rinnovo viene iniziato. Lock condiviso non bloccante e doppia lettura; mutazioni/rete0.

[Qualifica reader GitHub Actions39001548806](https://github.com/GioNob/ouf-deploy/actions/runs/39001548806), job117305351358: PASS8 test, inclusi canary credenziali, richieste ambigue, contatori, cambio boot, custodia/lock e CLI reale isolata. Wrapper locale verificato contro byte alterati. Occorre il readback VPS prima di decidere se una nuova finestra sia ammissibile; non riaprire né azzerare automaticamente OAuth. Un REQUESTING mutante resta da riconciliare. Anche il fence persistente della sessione policy precedente deve essere governato: non cancellarlo per rilanciare il vecchio launcher e non assumere che cap197 autorizzi da solo69 tentativi ulteriori. Restano decisione separata sul reprocessing, receipt owner fresca, compilazione del piano con i byte firmati, revisione infrastrutturale esatta e firme dei due ruoli installer esistenti. Nessun semantic_propose aggiuntivo e nessun retry403.

---

# Journal token recuperato e candidato MCP atomico — 2026-10-17

**Fasi tecniche 8/8; milestone funzionali 0/6.** Readback VPS fornito dall’operatore: `CANCELLED/CANCELLED_BY_OWNER`, 59 tentativi e 59 pubblicazioni; 69 tentativi controllati precedenti, cumulativo **128**. Authority scaduta, ammissione `BLOCKED`, journal stabile e reporter coincidente; lock di invocazione non detenuto dal worker durante la lettura. `liveStateProven:false`: non trasformare il vecchio campo `live` in prova di processo attuale. Evidenza: `evidence/chatbot-semantic-expired-worker-target-20261017.json`, log VPS `/home/oufadmin/ouf-expired-worker-read.SGJH8IdL/read.log`. Chiusura terminali non ha cancellato questi registri.

Il tetto precedente 197 non è una nuova autorizzazione: la capacità numerica residua 69 non è automaticamente riutilizzabile. Il conteggio OAuth HUMAN e la storia legacy completa restano non provati; nessun azzeramento o rinnovo implicito.

Nuovo preparatore `scripts/prepare-chatbot-semantic-mcp-atomic-review-20261017.py`: preserva la revisione privata `02590e54312e90c27093adfa1bea057a2111c4702cf3e50507a7af07d4833c9a`, verifica i quattro hash del worker recuperato e collega una nuova revisione al pacchetto atomico MCP `f00e7e3bfcaee9272b9b6d204a7fa3ea79a563a4` (artifact 12062235842, run pacchetto 38938286063). Migrazione: solo CLI nativa, GRANT/DDL/checksum/REVOKE nella stessa transazione; membership committata vietata. Preparazione limitata a nuova directory privata: nessuna lettura credenziali/HUMAN, firma, import immagine nel VPS, stop, grant, migrazione o chiamata semantica.

[CI GitHub Actions 39000091791](https://github.com/GioNob/ouf-deploy/actions/runs/39000091791), job117300988947: PASS19 controlli reader +6 test revisione con pacchetto reale e derivazione tagless per entrambi i profili archivio; import e verifica nativa sul runner `overlay2` PASS. Non è un readback della nuova revisione sul VPS né un test del bootstrap applicativo MCP.

**Restano da completare** l’entrypoint autenticato di produzione e la qualifica del bootstrap MCP reale; quindi decisione finita separata sul reprocessing, prova fresca owner receipt e revisione esatta infrastrutturale con i due ruoli installer esistenti. Preparare prima il percorso eseguibile; aprire il login solo quando serve, senza lasciare scadere una finestra durante lo sviluppo. La nuova revisione resta `readyForExecution:false` e non autorizza il deployment. Il vecchio claim MCP resta immutato; nessun nuovo `semantic_propose`, retry403 o reset.

---

# Recupero del journal dopo chiusura terminali — 2026-10-17

Stato invariato: **fasi tecniche 8/8; milestone funzionali 0/6**. L’operatore ha chiuso i terminali dopo la scadenza della sessione; le ultime righe del reporter non sono più disponibili. Non assumere che questo abbia cancellato il journal o che `live:true` salvato in precedenza rappresenti un processo attuale.

Il reader specifico dell’installazione `scripts/read-chatbot-semantic-expired-worker-20261017.py` recupera esclusivamente la precedente authority con hash noto e i quattro record del worker esatto. Lock di invocazione condiviso non bloccante, solo file già esistenti aperti in lettura, doppio snapshot e controlli di custodia/hash/conteggi. Distingue journal e ultimo reporter; il cumulativo è il conteggio **controllato**, non la storia legacy sconosciuta. Nessuna lettura del journal HUMAN/credenziale, rinnovo, restart, reset, grant, chiamata MCP o mutazione DB/servizi. Il budget OAuth HUMAN corrente rimane non provato.

Qualificazione: [CI GitHub Actions 38998389486](https://github.com/GioNob/ouf-deploy/actions/runs/38998389486), 7 test su file privati reali, esclusione del worker, drift, conteggi, redazione e CLI. Il primo run 38998355985 ha correttamente rifiutato l’ancestry del checkout appartenente al runner; il fixture è stato spostato sotto `/root`, senza indebolire il reader. Wrapper locale: byte verificati eseguiti, byte alterati rifiutati. Questa evidenza non costituisce readback del VPS; occorre l’output del nuovo comando prima di stabilire i conteggi finali o preparare un’altra sessione.

---

## 2026-10-16 — Native single-component adapter qualification passed; token history input still needed

GitHub Actions run38941859703/job117111207270 passed on source d2e91c5c75ab2df52127836c201647c845063db8: eleven signed fixture tests plus sixteen ordered native fixture stages with real Docker, PostgreSQL17 atomic migration, completed custom backup/native restore-list verification, endpoint preservation, retained stopped old generation and public metadata custody. The replacement HTTP process is explicitly synthetic BusyBox; this is not actual MCP server bootstrap, production target OCI/lease acceptance, current owner policy or E2E proof. No target operation, native semantic call or live runtime authority was performed by this qualification. Evidence: evidence/chatbot-semantic-mcp-single-update-qualification-20261016.json. This supersedes only the earlier pending-adapter qualification status; production authenticated entrypoint/fresh reviewed package binding/permit and current authority remain incomplete.

Operator input required next: final JSON lines of the finite policy-token worker that expired18:47:18 Europe/Rome. Actual new-worker attempts/publications/cumulative count and terminal disposition remain unobserved here. Do not restart it or reset69 historical attempts,197 cumulative cap, or the separate HUMAN OAuth journal/window. One current receipt read returned403 as recorded below; no retry or proposal mutation follows. Preserve root private review02590e54312e90c27093adfa1bea057a2111c4702cf3e50507a7af07d4833c9a as immutable predecessor of the changed atomic package. Stable progress remains8/8 technical,0/6 functional.

## 2026-10-16 — Root private candidate retained; atomic migrator and new package qualified

Actual root preparation succeeded: /etc/ouf/deploy-snapshots/semantic-mcp-update-review-8eoy5rm0/review.json, SHA256 02590e54312e90c27093adfa1bea057a2111c4702cf3e50507a7af07d4833c9a, native candidate image sha256:04a905f6b93d111bca1d9b368182860b36ebbad98dcbe7a7ee91018dccd75d50. User log /home/oufadmin/ouf-semantic-mcp-update-review.eaWL8K1h/prepare.log proves complete private-only preparation, no grant/signature/keys/credential files/service/DB/config effects and readyForExecution:false. Preserve this predecessor unchanged: it names the previous 1cbc image and cannot authorize a replacement package.

The migration plan was strengthened before any approval: separately committed GRANT/REVOKE could leave membership after interruption. New native command migrate-semantic-reprocessing performs grant, SET LOCAL application role, packaged migration 13, ledger insertion, RESET and REVOKE in one serializable transaction under the existing migration lock. PostgreSQL 17 run38937982021/job117098173074 passed success, cancellation during blocked DDL with no membership visible to another connection, rollback, wrong database/function and replay denial, plus race tests. Source f00e7e3bfcaee9272b9b6d204a7fa3ea79a563a4, draft PR70. No target migration occurred.

New unsigned package run38938286063, artifact12062235842, ZIP SHA256 0d15454fbf7914c1b8270cfee67fd3c97db1419d2e29e1ec81f43e867085161c. Configuration image sha256:e61bc9e3bd6f7e2bbf25cca285bfd4319d1addf43b67918961a7a90fc37e78f8; tar SHA256 6a86142d73de255ba8037fe8a36e7c2408071f11645119d31f8ca5ffff73a543; binary SHA256 07efce1f1360da9ddf1ded5c03ab626cde4b5a913b1893d2eb0dd37eed34d66e. Scan passed HIGH/CRITICAL/UNKNOWN including unfixed; archive checksums verified independently. Native target import/generation for this new image is not yet proved. See evidence/chatbot-semantic-mcp-atomic-package-20261016.json.

New deployment owner/adapters in tools/semantic_mcp_update are development only, source d2e91c5c75ab2df52127836c201647c845063db8. Eleven local tests pass with actual existing-format Ed25519 fixture signatures and synthetic ports: ordered one-use effects, CAS/double invocation, revocation/expiry/hours outage, lost response reconciliation without replay, durable bounded readiness, insufficient remaining authority and incomplete backup rejection. A persistent logical fence binds old CID/database/predecessor attempt independently of new candidate paths. Native Docker adapter qualification is still pending; earlier fixture runs exposed startup/API projection/stop-time/created-endpoint differences and are not acceptance. The fixture uses actual PostgreSQL/native MCP migrator but a synthetic BusyBox readiness process; even success does not prove MCP server bootstrap, live Registry/owner policy, complete target OCI/lease or E2E. No production entrypoint or new signed runtime approval has been delivered.

Functional blocker: one current read of the same Teatri receipt using ouf-admin returned403 SEM_CAPABILITY_REQUIRED:ouf.semantic.proposal.read. No receipt absence was established by that call; do not infer a proposal, retry mutation, switch account/key or repeat permanent denial. The last finite policy-token worker expired at its original18:47:18 deadline; user final terminal receipt/cumulative counts are still required before proposing any new bounded token session. Preserve69 historical controlled attempts plus the actual expired-worker count; never reset197 cumulative ceiling or the separate OAuth journal/window budget. Original authority/human/session references remain in earlier sections. No automatic renewal/restart. Next operator input needed: final JSON lines of the expired token worker; a reader can be prepared if the terminal output is unavailable.

Outstanding work: complete native Docker adapter qualification; bind the new package and atomic admin invocation into a fresh private review rather than modifying02590e54; implement/qualify the closed authenticated entrypoint with current HUMAN and existing two installer-role signatures; obtain fresh owner receipt evidence after explicit finite token continuation; issue a separate bounded one-call reprocessing permit and final runtime metadata/mount review; then finite single-component backup/migration/cutover and owner readback. Do not involve new keys or creation-attestor signing in the permit, replay four-component installers, restore old DB snapshots, rearm/delete claims or claim functional acceptance. Stable roadmap:8/8 technical,0/6 functional; semantic HUMAN decisions remain in THS.

## 2026-10-16 — Actual migration role facts and private one-component review preparer

Target log /home/oufadmin/ouf-semantic-mcp-reprocessing-preflight-read.YZ0cQW57/read.log confirms unchanged MCP generation, all 12 checksums, expected denial and unchanged original claim. The only observed missing migration privilege is ownership access to the retention function: application lacks SET/inherited retention-role access; that role is NOLOGIN/non-superuser with zero members. Function hash 95c25f228184ee59e6f2f9deb31575d67a257da8ce91aa148c0e0507b020cc47. No privilege or schema change occurred. Proposed plan must stop MCP during one temporary membership and clean it before starting the application; development permission is not runtime authorization.

Source e055287fbe1842512434f7a3b553f52fc962ceb2 now provides a private review preparer. CI run 38936636346/job117093682787 passed 19 reader tests, five preparation tests using actual candidate bytes, tagless derivations for both archive profiles, and native overlay2 runner image import. Native containerd import is not proved by this run. Source also passed native PostgreSQL preflight run38936636206. Package source1cbc496e1632ec3b1f2f0d9bf1e1f59a308278ef/artifact12059844351 remains unchanged and qualified; no target import/deploy.

Next user command: pinned scripts/launch-chatbot-semantic-mcp-update-review-20261016.sh from this delivery. It authenticates the 14MB artifact/source hashes, re-observes the exact installation, creates only a new private root candidate and derives the store-specific tagless image. Up to 180 seconds, five Engine GETs, one read-only SQL session. No credential files/private keys, tokens/grants, image import, lifecycle effect, signature, runtime authority, migration, claim rearm, semantic dispatch or existing configuration write. It intentionally returns readyForExecution:false until native executor, current authenticated exact review, fresh owner receipt absence, separate finite reprocessing consent, existing-role signatures and final runtime mounts/configuration are qualified. See releases/SEMANTIC_MCP_REPROCESSING_DELIVERY_20261016.md and evidence/chatbot-semantic-mcp-role-target-20261016.json.

Token worker remains expired at its original deadline; final terminal receipt/counts still pending. No automatic renewal/restart/reset. Roadmap remains 8/8 technical, 0/6 functional; HUMAN semantic approval stays in THS.

## 2026-10-16 — Target MCP binding confirmed; one-component package qualified

Target log /home/oufadmin/ouf-semantic-mcp-binding-read.wkknNUge/read.log confirms exact installed source f249b3dcc58c2a96742092d90fa09fd90b705bd0 and stable reviewed native image/container. Retained claim is HUMAN, workload ouf-chatgpt, FAILED/ACKNOWLEDGED version 2 with one reconciled owner call and exact expected semantic authorization denial proven. Evidence: evidence/chatbot-semantic-mcp-binding-target-20261016.json. No claim rearm/deletion or semantic mutation by reader.

Draft source PR https://github.com/GioNob/ouf-mcp-server/pull/70 is not merged/deployed. Exact candidate source 1cbc496e1632ec3b1f2f0d9bf1e1f59a308278ef passed final signed-session CI run 38934531605. Unsigned one-component MCP package run 38934847558 passed; artifact 12059844351, ZIP SHA256 4924985e236c03976287c7dcb130c4cc579c71499e6c53371b05f3a0cb5ce359, image-bound scan PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED. Independent checksum/image/source/migration-prefix verification passed. Hashes in evidence/chatbot-semantic-mcp-reprocessing-package-20261016.json. No target image import, signing, runtime permit, migration or application cutover occurred.

Next user action: separately pinned scripts/launch-chatbot-semantic-mcp-reprocessing-preflight-20261016.sh. Source at 322dc531499d9a57d024aba6931bf829de7e25fd; reader SHA256 8657ee955a11fd5f84a6002842743bab7314a92dfaa49a7706f675eb3c752f9b. Qualification run 38935354487/job117089357855 PASS: 19 bounded reader tests plus actual PostgreSQL 17 baseline migrations, read-only native catalog query and temporary membership visibility in a synthetic fixture only. The first qualification failed because its fixture compared an OID string to the target reader's bigint; fixed in fixture, product SQL unchanged. Actual target role facts remain pending. No automatic privilege grant follows a missing privilege.

Token worker authority deadline 18:47:18 Europe/Rome has elapsed; user reports expiration. Final terminal receipt and exact new cumulative counts are pending; no automatic restart, renewal, budget reset or acceptance. See releases/SEMANTIC_MCP_REPROCESSING_DELIVERY_20261016.md for retained scope, next least-privilege review, separate existing-role permit and remaining target gates. Stable roadmap: 8/8 technical, 0/6 functional.

## 2026-10-16 — Exact MCP claim observed; release binding required before deployment

Target readback /home/oufadmin/ouf-semantic-mcp-claim-read.zuAdwY5t/read.log proves one retained claim: attempt 9d676b80-8f5f-4160-ac9e-57f0935f78be, requestHash b8bc4ccb0f8fe48764ecf87340fd2ff209520c0b5b947a3ee6a1e461fc57a112, FAILED / ACKNOWLEDGED, lockVersion 2, reservation RECONCILED, actualToolCalls=1, reservedToolCalls=1. Database OID 21560 and role matched. No claim rearm/deletion or database mutation occurred. Owner receipt remained absent for the exact same HUMAN/key; the authorized reprocessing call returned SEMANTIC_RECEIPT_READ_REQUIRED and did not dispatch a new owner proposal.

Development source is on GioNob/ouf-mcp-server branch fix/semantic-governed-reprocessing-20261016, based on the cohort lineage f249b3dcc58c2a96742092d90fa09fd90b705bd0, not main. Existing two role signatures reuse the existing installer key and exact trust-policy/frame formats; attestor remains excluded. No new keys, runtime permit or deployment has been issued. Signed sessions preserve old history and owner command key, add at most one call (1+1=2), enforce current authorization, expiry, capacity and UNKNOWN blocking. See source branch docs/SEMANTIC_GOVERNED_REPROCESSING.md. This remains development evidence, not target readiness.

Next user action: run scripts/launch-chatbot-semantic-mcp-binding-readback-20261016.sh from this delivery. Source pinned at 2ec7baf4bbd79e22f832df892d5614116e2c964f; SHA256 08559a2bcec0b7ec29ab6adabd3253d5ae2f1d1bb18ac9d05fa1d89d2d97d01c. CI GitHub Actions run 38934302504 passed 12 reader tests; target observation is still pending. The bounded reader uses up to four Engine reads and one read-only SQL session, no credential files/grants/MCP calls/service writes. It projects exact source/image/generation, current manifest/workload/HUMAN and whether retained audit proves the expected denial; drift stops the read. It does not rearm any claim or deploy a correction.

The token owner session's original deadline remains 2026-10-16 18:47:18 Europe/Rome. No automatic renewal, restart or budget reset is authorized. Technical phases remain 8/8; functional milestones 0/6. Deployment requires exact target lineage, role/migration preflight, a pinned package and a concrete finite backup/migration/cutover review; token-only authority does not authorize it. Semantic approval remains in THS.

## 2026-10-16 17:58 Europe/Rome — explicit semantic reprocessing authorized; MCP retained claim blocks dispatch

Operator explicitly authorized ONE new unchanged Teatri DRAFT submission using the same account and commandKey. One semantic.propose tool invocation was made with the exact retained importCommand, ouf-admin link and `teatri-semantic-draft-be74308e098aa3a6-20261016`. Result: `SEMANTIC_RECEIPT_READ_REQUIRED`, retryable=false; no DRAFT/owner receipt was returned. One subsequent receipt reconciliation read returned owner404 `PROPOSAL_RECEIPT_NOT_FOUND`. No further create invocation, alternate key, account switch, claim deletion or admission reset was performed. Operator authorization is recorded; it does not bypass MCP admission or authorize THS semantic approval.

Source analysis: ouf-mcp-server `f7ecaeb210d8fcead478b90c62645db13a7d8226`, internal/adapter/postgres/store.go Reserve/reserveOnce returns Replay for an existing matching idempotency claim unless outcome UNKNOWN/UNRESOLVED; internal/orchestration/service.go returns empty Replay before Gateway dispatch; internal/kernel/kernel.go maps that empty semantic replay to SEMANTIC_RECEIPT_READ_REQUIRED. Receipt READ is independent and does not rearm that claim. This source-level path explains the observed marker, but exact persisted claim state and deployment source still require target readback. Do not clear the claim or invent a fresh key. A native governed reprocessing path may need implementation/qualification after state is known.

Prepared installation-specific metadata reader:
- Source commit `72923e0bfd5a8d7a1e72afd4684784446ce5d57b`, script `scripts/read-chatbot-semantic-mcp-claim-20261016.py`, SHA256 `2e775c9c47fd42f410fa975a5341087f30112e9ab25412800e471984f48c589a`.
- Reuses the current signed16e5 retained source/review/authority/prepared bundle and exact PostgreSQL runtime/database OID, Docker executable and Engine socket. No external credentials are read or printed. Existing signed database administrator selected explicitly, no role fallback.
- One bounded psql session through the existing pinned PostgreSQL container. PGOPTIONS default_transaction_read_only=on plus BEGIN READ ONLY, statement10s/lock3s/CLI15s, total reader120s, SELECT only and ROLLBACK. No container lifecycle, token issuance, IAM/MCP request, SQL mutation or rearm.
- Exact tenant from retained HUMAN selection, exact subject/owner/capability/COMMAND/key. Up to4 claims, explicit total count checked against returned rows; no silent truncation. Only attempt UUID/hash, safe states, lock version, reservation counts and context-presence flag can be emitted. Unknown/redaction-invalid data fail closed.
- Two Engine observations fence the PostgreSQL generation before/after. Other records/processes may change independently; this is not a global atomic snapshot or runtime authority.
- GitHub Actions run38928870195/job117067391349: **PASS6**, including exact SQL scope/injection refusal, projection limits/redaction, full main with synthetic SQL/metadata port, post-read generation drift, SQL failure and real bounded CLI output. These tests do not execute actual target PostgreSQL; target operator readback remains required. Launcher bash -n passed.
- Launcher `scripts/launch-chatbot-semantic-mcp-claim-readback-20261016.sh` SHA256 `c78b7f3bd49fd56ff2f1f4d07d4916e0876f9be32e99d53b0dd582b81a5f7de9`. Downloads exact pinned reader, verifies before sudo, private root copy and safe error output. Use second terminal while original finite policy-token worker continues; do not stop or renew it.

**8/8 technical,0/6 functional**. No semantic draft creation, approval or publication proven. Next: acquire EXACT_MCP_CLAIM/END target metadata, then prepare a governed owner-side correction with retained history and finite authority if required. The explicit semantic reprocessing instruction does not permit unreviewed deployment/SQL resets.

---

## 2026-10-16 17:55 Europe/Rome — policy token recovered; original semantic receipt read reconciled

Roadmap remains **8/8 technical;0/6 functional**. Operator is now on PC and can use multiple SSH terminals; keep the finite token worker active in its original foreground terminal while running diagnostics in a second.

Target execution observed: explicit login-window consent succeeded, HUMAN login completed, exact token-worker review `3c5eab698b2ed59f5a454b6bf93a4eba54a8cea0198c968401e09ad8784d4c63` approved; existing dual-role issuance and guarded installation reached STARTED. Authority hash `ccac6ea4c195de2c65937fb0df581adee5a610f167cb2c125662733932312eed`, file `/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem/authority.json`, expiry epoch1792169238 = **18:47:18 Europe/Rome**. First two reported attempts each published one policy token; later operator status reports attempts6, ACTIVE/RECOVERED/live true. No claims beyond those observations. Reporter applicationReady=false and runtimeAuthorityIssued=false are fixed projections of the owner status, not proof that the separately signed execution authority was absent. The worker does not prove application readiness.

Second-terminal v3 readback complete: current token nonexpired (observed expiry1792166368), root:10001 mode0440 and one link; approved HTTPS endpoint binding exact; one GET returned200, active bundleVersion40, expected contentHash matched, computed compact bundle hash matched envelope, semantic.propose and semantic.proposal.read declared, configured grant counts2 and1 respectively. Registry generation stable across bounded Engine reads. This resolves the observed expired-token/host401 path; host transport still does NOT establish JVM transport or the exact in-memory policy hash.

One bounded MCP `semantic.proposal.read` was performed using ONLY `ouf-admin` link_6aafef96b4148191b767e9af7b756a07 and original commandKey `teatri-semantic-draft-be74308e098aa3a6-20261016`. Result: owner404 `PROPOSAL_RECEIPT_NOT_FOUND`, not the prior403. In pinned Registry source eccef11a97367f20e278db40b9ed6f45dd980c37, SemanticAuthorizationBoundary checks semantic.proposal.read on the request snapshot before service receipt lookup. This supports successful current owner admission for the read path. It does not expose the exact loaded snapshot hash, prove semantic.propose is allowed or grant semantic approval; receipt-not-found is caller/tenant/key scoped and does not enumerate every artifact.

No semantic.propose mutation was repeated. Prior403 remains a stopped attempt. The approved token-only mandate explicitly excludes semantic-proposal retries and does not authorize them. Prepared exact reprocessing review is `releases/TEATRI_SEMANTIC_REPROCESSING_REVIEW_20261016.md`: one operator-authorized resubmission of the unchanged DRAFT payload using the SAME commandKey/account, no automatic retry, ambiguous outcome reconciled via same receipt, approval/publication only through THS. Proposal canonical hash recomputed from all fields except proposalHash matches be74308e098aa3a65396f3df739dd8f2837e9f8e27b6e49deb0e49d04506cb1a; RDF bytes match declared SHA256. Await explicit instruction before this new mutating attempt.

---

## 2026-10-16 — expired HUMAN login window; explicit reopening candidate

Target operator readback after the continuation STOP classified only as `PlanDenied`: original private HUMAN journal is `DEVICE_POLL`, attempts **42**, expiresAt **2026-10-16T15:18:13Z** (**17:18:13 Europe/Rome**), wall and monotonic expiry both true, same boot true. No continuation receipt, authority.json or issuance.claim.json was present. This confirms the time window is exhausted; it does not prove live Registry policy or functional acceptance. Roadmap remains **8/8 technical; 0/6 functional**. Do not rerun the previous generic or same-deadline continuation launchers.

Source `29363efbaf1d509aae02e7b7819ef3f57e1593da`, sealed delivery `fc6021e21ed564cf13b7ab8ac8e65be90e2b79b3`:
- `scripts/reopen-chatbot-semantic-login-window-20261016.py` binds the exact usx0tsem preparation, its original inode, same retained private review/candidate/predecessors/Registry generation and the observed 42 requests / original expiry. Closed memory loader and original external owner bytes remain enforced.
- `scripts/launch-chatbot-semantic-login-window-20261016.sh`, SHA256 `337502183f63f3e972a82f8e8c1aa76e9978d2d302dd04abbb402634edbc8ef6`, downloads eight hash-pinned files from the source commit, verifies before sudo, takes a root-owned private copy and runs Python unbuffered. Preserve all historical launchers and their immutable commits.
- BEFORE opening another authentication window, show exact terminal review and require `RIAPRO LOGIN <reviewHash>`. This is local operator consent to the authentication window, **not authenticated HUMAN authority or a THS semantic decision**. It allows a single new 7200-second login window, with **42 already consumed requests, maximum86 additional, total128**. No automatic renewal, no cumulative budget reset.
- Original `human-session` journal/binding/deadline remain byte-for-byte unchanged. After consent, publish one-use `login-window-reopening.json` and create `human-session-window2` with counter42, predecessor row/binding hashes and exact consent. Partial/consumed artifacts block automatic retry; never delete or reset them.
- Reopening is restricted to an expired, known pre-token DEVICE_POLL challenge. In-flight ambiguous mutations, already received/published tokens, boot/identity/history drift, exhausted request budget or existing reopening are rejected without new OAuth calls. A renewed window cannot silently renew again.
- Browser authenticates the SAME pinned `ouf-admin` HUMAN identity. Then publish the exact token-worker review, including reopening receipt, and independently require `APPROVO <hash>` before existing dual-role signatures or runtime authority.
- Workload budget remains independently **69 prior controlled attempts +128 new =197 cumulative, maximum3600 seconds**. No first-grant replay, credential rotation, container/database/Gateway mutations or semantic proposal retry. Registry effective policy still unproven; semantic HUMAN approvals stay in THS.
- Phone / ONE terminal: launch, read and approve the login-window request if intended, open provider URL/code in the phone browser, return to the same SSH terminal for exact final review. Keep the terminal open after STARTED. If STOP appears, retain output and reconcile; do not rerun.
- Active development capsule updated for human_session, continued_owner and review; hash `9087bca11c933fd72f04b55696569eb28b2fe4ec248f1a42d100dbd5b16ae855`. Historical capsule bindings stay immutable.

CI GitHub Actions: source run38925807331 / job117056915019 **PASS89** (11 interrupted/expired-login tests,10 dispatcher,6 closed bootstrap,15 HUMAN-session,6 composed owner,7 scope,10 native signatures,6 installation,18 installed owner). Sealed delivery run38925896612 / job117057212529 **PASS11** (2 launcher /9 interruption-reader). Local fixture runs are supporting evidence only (ownership/boot/Unix adapters); native CI uses real root custody/UID/GID/Unix socket and synthetic OAuth/TLS services, not target authentication or acceptance. No new target execution has yet been observed. Whole-repository/cohort checks are separate and must not be inferred from these targeted results.

## 16 ottobre — candidato target verificato; composizione token-only in qualifica

## 16 ottobre 15:34 — readback pre-autorità acquisito; continuazione senza reset pronta

L'operatore ha un solo terminale sul cellulare. Il readback target ENDcomplete
ha riportato PRE_AUTHORITY_PREPARATION_ONLY_OBSERVED: processi0, fence assente,
nuovo journal presente/vuoto, worker non inizializzato, nessun file di review,
decisione, mandato, autorità, claim di emissione o firma. Predecessori immutati,
69tentativi controllati. Contesto esatto
`/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem`, device65028/inode1322063;
human-session presente con3entry, journal presente, contenuti OAuth non letti dal
reader. Questo ha lasciato budget e stato OAuth non dimostrati fino alla nuova
validazione locale nella continuazione; non autorizza un budget nuovo.

Nuovo comando per LO STESSO TERMINALE:
`scripts/launch-chatbot-semantic-token-continue-20261016.sh`, commit
`bb98e42254c24983a55a8f64fd9012babfee3c25`, SHA256
`a08112326cab8e254bfdb195d1a51f9a40860abcbdd219c8689d5068e7023d5f`.
Sorgente immutabile `e7e0b1c543c278672eb99870d1dab118721649be`.

La continuazione verifica ancora assenza di altri esecutori, contesto/inode,
predecessori, fence assente e journal vuoto; non cancella o ricrea directory.
Consuma una distinta claim privata di riconciliazione pre-autorità, conservando
hash della riga OAuth precedente, tentativi e scadenza originale. Riusa lo stesso
journal HUMAN, sessionId, massimo128richieste e deadline7200originale: nessun reset.
Se la richiesta mutante/rotante era rimasta REQUESTING o lo stato era BLOCKED,
resta bloccata senza replay. Le letture interrotte restano nel profilo esistente.
Se è scaduta SOLO una challenge DEVICE_POLL, senza credenziali ricevute e senza
esiti ambigui, conserva hash/storico e prepara una nuova challenge nello stesso
budget. Rispetta Retry-After e scadenza; non crea due challenge concorrenti.
Il nuovo codice conserva anche URI/codice da mostrare per evitare un altro
prompt perso. I bearer/refresh/device_code restano privati; solo link e user_code
previsti per l'operatore sono visualizzati. -u e flush esplicito rendono immediati
i messaggi attraverso tee. La continuazione legge il journal OAuth privato per
validarlo; il precedente reader di sola metadata non lo aveva aperto.

CI GitHub Actions sorgente [38910246917](https://github.com/GioNob/ouf-deploy/actions/runs/38910246917),
job117003968326:82test PASS, inclusi7casi OAuth di continuazione su vera socket,
8casi composti con firme/TLS/custodia,5bootstrap e15regressioni OAuth.
CI consegna [38910546838](https://github.com/GioNob/ouf-deploy/actions/runs/38910546838),
job117004978656:PASS,2test launcher attivo e9test reader. Il test launcher segue
ora la consegna attiva a8file; le vecchie versioni/pin restano nei commit storici.
Capsula sviluppo d86348bd6918d6e39755020928a3124041f8d132e46b78bf29b991aa27a941d9.

Nessuna autorità runtime nuova inferita: dopo login è ancora richiesta
APPROVO<hash-esatto> della nuova review, con due firme dei ruoli esistenti.
Finestra workload massima3600secondi,128nuovi tentativi, cumulativo massimo197,
69controllati precedenti e gap legacy UNKNOWN conservati. Nessun primo grant,
rotazione, lifecycle, DB, Gateway, modifica grant, MCP o semantic.propose automatico.
La sessione foreground va lasciata aperta dopo APPROVO; riportare STARTED e primo
STATUS, oppure STOP completo. Con un solo telefono il login usa il browser dello
stesso dispositivo; non è richiesto un secondo terminale.8/8tecniche,0/6funzionali.

## 16 ottobre 15:23 — Ctrl-C osservato; prossimo passo solo readback

L'operatore ha riportato BEGIN seguito da ^C, senza STOP o prompt HUMAN.
Questo non prova l'uscita del figlio né zero effetti. Non ripetere il launcher
operativo, neppure quello corretto con -u, prima della riconciliazione.

Comando successivo: launcher `scripts/launch-chatbot-semantic-token-interruption-readback-20261016.sh`
dal commit immutabile `32605941a0295bb870878be1f4719273a8d08370`, SHA256
`c6176140271e392052e81268138df416e0bb1b0532a8371f197f6e586560d924`.
Lettore nel commit89521f6d8a69ca3a62caab888ac74cce0b0f838b,
SHA2563c8dc3a3d81d53e2a8e04466e42e2ece5822c57b4ae7049e15f1d376023bfebb.
Eseguirlo in un secondo terminale VPS. Legge solo metadata e record storici
hash-bound: processi Python del namespace esatto/della directory CajgP8EI,
predecessori, presenza dei file di autorità/firme, nuovo journal, fence e directory
OAuth. Non apre recovery.json/token della sessione HUMAN, non legge environ,
non mostra argv, non chiama Engine/systemd/IAM/MCP/DB, non cancella o riparte.
PRE_AUTHORITY_PREPARATION_ONLY_OBSERVED è una classificazione locale vincolata,
non una concessione di riavvio; budget e stato OAuth restano esplicitamente
non dimostrati. Nessuna scelta automatica del contesto più recente.

CI Linux [38908406629](https://github.com/GioNob/ouf-deploy/actions/runs/38908406629),
job116997739972:11test PASS, inclusa scansione procfs con vero figlio Python,
wrapper root con byte verificati e rifiuto di manomissione. Sei prove metadata
PASS localmente; procfs indisponibile in Work, obbligatorio e superato nella CI.
Qualifica precedente del fix buffering:38907391680 PASS. Sorgente runtime72test
invariato. Stato target8/8tecniche,0/6funzionali, nessuna nuova authority provata.

## 16 ottobre — arresto operatore prima di ripartenza dopo buffering del login

Output target mostrato dall'operatore: solo BEGIN, nessun login visibile.
Difetto del launcher riprodotto: il figlio Python che passa in tee bufferizza
le istruzioni device flow emesse tramite print. Correzione: avvio figlio con -u,
con nuova regressione sul wrapper realmente eseguito. Due test locali PASS;
CI di consegna da rileggere. Sorgente runtime c3e39aaf resta invariato.
Nuovo SHA256 launcher: aba71a62a9455d78ce7cc7dc137180e627ef7cb8c0f9732a33a03d14b8400e9d.
Il comando storico fissato a3a500b resta immutabile e NON va ripetuto.
L'operatore deve interrompere una volta con Ctrl-C e riportare l'output.
Prima di qualsiasi ripartenza riconciliare la preparazione privata, lo stato
OAuth, eventuale issuance claim, nuovo journal e fence; il journal deterministico
può esistere già dalla preparazione. Non cancellare directory o claim, non
presumere zero grant dalla sola schermata, non azzerare il budget OAuth.
Autorità e grant target non dimostrati da questa schermata. Stato8/8tecniche,
0/6funzionali; nessuna approvazione, accettazione o nuova esecuzione inferita.

## 16 ottobre — consegna del solo token policy pronta alla decisione HUMAN

Stato target: **8/8 fasi tecniche, 0/6 risultati funzionali**. Il candidato v2
è completo ma non conferisce autorità: SHA256 `0f89461b7ec0d34078dbacc28d3281c935ca2f5c60dd185f2f763f4ffd3650b4`.
Il nuovo esecutore è confezionato; usare esclusivamente la consegna descritta in
[CHATBOT_SEMANTIC_TOKEN_SESSION_EXECUTION_20261016.md](../releases/CHATBOT_SEMANTIC_TOKEN_SESSION_EXECUTION_20261016.md).
I precedenti riferimenti a entrypoint mancante sono superati dalla nuova consegna.

Sorgente immutabile: `c3e39aaf5783be6428fdb95dff1a3836748c0ce3`.
Launcher pubblicato nel commit `3a500b77081d9ee109468748db55e2d99954b55c`:
`scripts/launch-chatbot-semantic-token-session-20261016.sh`, SHA256
`df509e9c44b7b1e08ce6acc3e4e0847aa18d0bcda7eadc525a808d3ba806f7ac`.
CI del sorgente [38902222309](https://github.com/GioNob/ouf-deploy/actions/runs/38902222309):72test PASS;
CI della consegna [38902296302](https://github.com/GioNob/ouf-deploy/actions/runs/38902296302):2test PASS.
La prova OAuth e il consenso terminale sono fixture nelle prove composte;
nessuna decisione HUMAN target o esecuzione VPS è inferita dalla CI.

Sul VPS: nuovo login selezionato e `APPROVO <hash della revisione finale>`
prima di emissione con le due firme esistenti. Foreground, massimo3600secondi
dalla decisione; Ctrl-C/HUP/TERM e scadenza impediscono anche pubblicazioni
tardive. Vecchio CANCELLED_BY_OWNER e69tentativi controllati immutati; massimo128
nuovi, cumulativo controllato197, gap legacy UNKNOWN. Fence persistente unico,
nuovo journal, nessun primo grant ripetuto, rotazione, lifecycle, DB, Gateway,
modifica grant o MCP/proposta. Non rilanciare dopo STOP senza riconciliazione.

L'operatore deve ancora eseguire il comando: riportare STARTED e primo STATUS,
lasciando aperto il terminale. ACTIVE del worker non prova policy effettiva
Registry, receipt semantica, approvazione THS o risultati CSV. Riconciliare lo
stesso commandKey prima di riprendere semantic.propose; nessun retry403 o cambio
account. Tutte le precedenti prove e i sei traguardi funzionali restano validi.


Fasi tecniche8/8 conservate; funzionali0/6.
Preparatore candidato v2 ENDcomplete=true. Artefatto privato:
/etc/ouf/deploy-snapshots/semantic-session-candidate-048rn2ec/candidate.json,
SHA256 0f89461b7ec0d34078dbacc28d3281c935ca2f5c60dd185f2f763f4ffd3650b4,
reviewbeefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803.
Prova nativa target: VERO AtomicTokenFile.publish, dati sintetici,
UID/GID/modo reali PASS, fixture rimossa. Nessuna credenziale/grant/autorità,
readyForExecution=false. Questa prova non è readiness applicativa o avvio.

Nuovo componente GovernedSemanticOwnerContinuation in continued_owner.py:
riusa AggregateAction/CutoverAuthority e verifiche esistenti di doppia firma,
mandato finito, root custody e sorgenti chiuse. Nessuna funzione di primo grant,
rotazione credenziale, IAM admin, lifecycle container, DB o Gateway è invocata.
Costruisce solo scope. install richiede NUOVA autorità esatta, consuma prima
un record-fence O_EXCL deterministico per scope logico, poi stage dei sorgenti e
inizializzazione di un NUOVO journal bloccato con cumulativo69. Primo tick del
worker può consumare un nuovo tentativo: cumulativo70, mai un nuovo primo grant.
Claim o inizializzazione parziali restano reconciliation-only, senza reset.
Directory inode e review privata sono vincolati. Predecessori cancellati, primo
receipt e gap legacy UNKNOWN restano immutati.
Guardia runtime nuova: il record di fence deve corrispondere, authority/firme
correnti, scope esatto e hash source. In più legge SOLO i metadati dell'esatto
Registry tramite socket Engine root/inode/mode vincolato: PID/start/image/config/
mount/network devono corrispondere alla generazione firmata. Nessun fallback
endpoint o allowlist ampliata. Il vecchio ramo di recupero rimane invariato.
Prima di effetti anche il vecchio budget viene controllato:59<=128. Non si
ridenomina un profilo precedente né si deduce contabilità dalla versione.

Cinque prove composte locali PASS, senza callback come autorità:
installazione senza grant/rotazione o mutazioni predecessori; tick69→70;
deny prima della claim per scope mancante/generazione diversa; fence assente e
mandato revocato; due installazioni concorrenti/una sola claim; budget197 fermo.
Le cinque funzioni test raggruppano questi casi. Firme Ed25519, TLS issuer mock
e file I/O sono reali; Work richiede ADATTATORI ESPLICITI per UID/GID, boot_id e
AF_UNIX→loopbackTCP. Non è qualifica nativa Linux di questi tre boundary.
Driver locale tests/run_governed_owner_local_metadata.py etichetta il limite.
Dieci test esistenti di firma reali PASS; sei di regressione owner installation
PASS con stessi adattatori.32test locali precedenti continuano PASS.
Nuova CI governed-semantic-owner.yml usa runner Ubuntu24.04 root, veri gruppi,
boot_id e Unix socket, OUF_NATIVE_UIDS=1: nessun adapter locale/skip consentito per
gruppo nativo. Nessuna connessione a VPS/IAM target: solo fixture locali sintetiche.
Esito CI ancora da leggere prima di dichiarare qualifica nativa composta.

NON pronto all'esecuzione: manca ancora confezionamento/entrypoint e review
sigillata dell'esatto nuovo comando, nuova decisione HUMAN e prova di effettiva
policy Registry. NON riusare il vecchio applicatore a8fasi né firmare da questa
documentazione. Nessun comando operativo nuovo consegnato da questa qualifica.
Le approvazioni semantiche rimangono esclusivamente nel THS; riconciliare
teatri-semantic-draft-be74308e098aa3a6-20261016 prima di riprenderne l'intento.


---

## 16 ottobre — candidato fermato sulla fixture umask; correzione preparatore

Fasi tecniche8/8, funzionali0/6. Output operatore:
STOP NATIVE_PUBLICATION_CONTRACT_FAILED nel preparatore8bcd9165….
Il flusso aveva già verificato reviewbeefc7f2…, quattro record, ricevuta originale,
generazione Registry e compilato lo scope puro; non ha raggiunto save_candidate.
Nessun candidato, sessione, firma, token grant o runtime authority è stato creato.
La stringa sintetica non è un token reale; nessuna credenziale è stata aperta.

Errore riprodotto localmente: launcherumask077 e directory.mkdir(mode0750)
producono directory0700. protected_directory del publisher richiede0750.
Il preparatore corretto applica chmod0750 ESCLUSIVAMENTE alla nuova directory
tokens della fixture temporanea, dopo creazione e chown0:10001.
Nessun permesso esistente/live o ancestor viene cambiato.
Il produttore, i suoi vincoli e i componenti runtime candidati restano invariati.

Aggiunta regressione che esegue tutta qualify_native_publication con umask077,
I/O/mode/fsync/rename reali e SOLTANTO metadati UID/GID emulati per il limite
del filesystem Work.25test locali chatbotsemantic +7contratto =32PASS.
Non è ancora prova kernel nativa sul VPS; quella è il prossimo input necessario.
Stessi limiti: sola preparazione privata, massimo120s, due GET Docker metadata,
nessuna IAM/API/DB, firma, credential read, modifica servizi/grant o avvio.
La qualifica/composizione completa dell'esecutore rimane aperta; nessuna nuova
decisione HUMAN va chiesta da questo preparatore non eseguibile.
Review target e cumulativo69 conservati. Usare il launcher candidato v2,
non rieseguire la v1. Preparatore SHA256
6524065f69f8c45e5190435b369673b8b5a54e7efbdd09f260f9bac9c547f556.


---

## 16 ottobre — review privata disponibile; candidato di continuazione da compilare sul target

Fasi tecniche8/8 conservate, funzionali0/6.
L'operatore ha completato la preparazione: review privata
/etc/ouf/deploy-snapshots/semantic-functional-session-review-e8ced3ui/review.json,
SHA256 beefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803.
Contatori precedenti69, limite proposto nuovi tentativi128/cumulativo197,
durata3600s. ENDcomplete=true, credentialFilesRead0, grantRequests0,
runtimeAuthorityIssued=false, humanApprovalGranted=false, readyForExecution=false.
Questo NON è un'autorizzazione di avvio, un nuovo budget concesso o un grant.

Sviluppo candidato (non installato): installed_owner.py aggiunge un compilatore
puro e un ramo di guardia per schema ouf.policy-token-governed-worker-session.v1.
Conserva i rami storici. Il totale deriva dai record hash-bound: base10+59=69;
verifica sessione/policy/first receipt/boot e il gap storico UNKNOWN, senza
dedurre contatori dalla versione schema o riaprire il vecchio journal.
Scope nuovo: cap197, policy finita, stessa chiave della proposta, reviewHash,
e fence persistente per logicalOwnerScopeHash nel parent del journal precedente.
Directory nuova deterministica dal reviewHash; la guardia nega senza il record
di fencing esatto. Il nuovo ramo scheduler controlla aritmetica e max attempts;
il vecchio profilo continua a rifiutare69. Nessuno di questi sorgenti è installato.

Sette test del contratto sui corpi AST candidati PASS, più due test di packaging/
compilazione e22 precedenti:31test locali PASS. Questi isolano le funzioni pure,
NON provano la composizione di firme, source-stage, installer e worker sul target.
Il publisher è invariato; la qualifica locale UID/GID resta simulata.
Mancano ancora composizione esecutore sigillato, qualifica completa firme/fencing,
decisione HUMAN corrente ed effettiva readiness policy Registry. Nessun apply
o domanda di approvazione runtime va emessa prima di chiudere questi gate.

Prossimo comando: scripts/prepare-chatbot-semantic-session-candidate-20261016.py.
Richiede la review privata ESATTA e gli stessi record hash-bound, legge anche la
ricevuta originale owner-first-grant.json, controlla hash input e generazione
Registry prima/dopo. Usa SOLO il compilatore puro estratto dai sorgenti hash-bound;
non importa né esegue il runtime owner. Compila un candidato root600/dir700
con source hashes, scope e pending gates, readyForExecution=false.
Sul solo scratch privato root crea una fixture temporanea root:10001/0750,
invoca il VERO AtomicTokenFile.publish su una stringa sintetica scaduta,
verifica file root:10001/0440 e readback, poi rimuove la fixture. Non tocca
output token live, directory/journal precedenti o permessi esistenti.
Nessuna credenziale, token live, firma, chiave privata, IAM/API/DB, grant,
unità o lifecycle viene usata. Due GET Docker metadata e due systemctlshow.
Massimo120s. Chown avviene SOLO nella nuova fixture temporanea.
Il launcher crea anche copie temporanee root600 dei sorgenti verificati, poi
le rimuove; producer originale invariato. Non eseguire file runtime direttamente.

L'output di compilazione target è necessario: la ricevuta privata originale
e i suoi valori completi non sono disponibili in questa chat. Non inventarli.
Se drift/contratto/custodia non corrispondono, STOP: non adattare contatori o
permessi e non riusare vecchi launcher/claim. Dopo la compilazione qualificare
la composizione firmata e l'esecutore prima di una nuova decisione HUMAN.
La review preliminare e il candidato non diventano mandato o accettazione THS.
Chiave teatri-semantic-draft-be74308e098aa3a6-20261016 conservata.
Preparatore candidato SHA256 ca9bd95d898e05109ef6f0277ce57f1625f18ce55a9a55d7979eb45882fc7506.


---

## 16 ottobre — diagnosi refresh completata; review di nuova sessione semantica da preparare

Fasi tecniche 8/8 conservate; funzionali 0/6.
Reader v3: tutti i vincoli endpoint e custodia PASS; file UID0/GID10001/0440,
regolare, singolo link, dimensione bounded. Un solo token letto senza stamparlo.
Metadato exp1792148493 = 2026-10-16 13:01:33 Europe/Rome; expiredAtRead=true.
La firma JWT non è verificata localmente. Un unico GET policy via binding HTTPS
approvato restituisce401; ENDcomplete=true, nessun retry o mutazione.
Questa è prova del rifiuto corrente sul percorso dal VPS con quel token.
È coerente con la scadenza del token dopo la cessazione del worker, ma non è
prova autonoma del motivo server del401, del trasporto JVM, dello snapshot
in memoria o della causa esatta del PRIMO403. Non forzare refresh con nuovi grant.

Il vecchio worker resta CANCELLED_BY_OWNER con cumulativo69 (59nel worker);
authority scaduta, admissionBLOCKED. Nessun rinnovo o replay autorizzato.
I componenti continued_owner/installed_owner sono vincolati a precedenti
specifici di recupero: NON usarli direttamente con count69 né cambiare i numeri
per adattarli. Serve un percorso distinto di nuova sessione finita con HUMAN
autenticato, stesso incidente/logical scope, nuova autorità e fencing,
preservando cancellazione e ogni journal precedente.

Preparatore nuovo: scripts/prepare-chatbot-semantic-session-review-20261016.py.
Scrive SOLO una nuova review privata root600 in directory root700.
Legge review/authority/bundle custoditi, i quattro record conservati
recovery/session/admission/status (hash canonici esatti già osservati), due GET
metadati dell'esatto Registry e due osservazioni dell'unità precedente ferma.
Non apre credenziali, non fa GET policy/IAM/MCP/DB, non prende claim di runtime
e non riavvia nulla. File o generazioni mutati bloccano la preparazione.
È readOnly=false esclusivamente perché crea il nuovo snapshot privato;
existingConfigurationWrites=0 e runtimeAuthorityIssued=false.

La review PROPOSTA contiene budget finito1ora/max128 nuovi tentativi di token
grant, massimo cumulativo197=69+128, interval60s, backoff5/15/60/300/900,
jitter20%, Retry-After, nessun rinnovo automatico.197 è un LIMITE PROPOSTO,
NON un contatore osservato. DecisionRef/timestamp/authority restano null,
readyForExecution=false. Richiede esplicita continuazione dopo cancellazione;
non riapre quel worker e non tratta la delega di sviluppo come autorità runtime.
Gli effetti proposti sono solo nuova sessione token e verifica readiness policy;
vietati primo-grant replay, fasi1–8, lifecycle applicativo, grant Authorization,
route Gateway, DB, reset e retry automatico della proposta semantica.
La chiave teatri-semantic-draft-be74308e098aa3a6-20261016 e il proposal hash
be74308e… sono conservati; riconciliare la ricevuta prima di una ripresa identica.
La review non è esecutore qualificato, autorità, approvazione THS o accettazione.

Quattro nuovi test locali PASS: nessuna autorità implicita, contatori non inferiti
e negativi, hash predecessori vincolati, scrittura/readback nativi root600/700 e
due snapshot esclusivi senza sovrascrittura. Totale22 PASS. Resta il limite
della qualifica precedente UID/GID10001 simulata, non accettazione target.
Evidenza: evidence/chatbot-semantic-policy-refresh-v3-target-20261016.json.
Reader/preparatore SHA256: 5fcf39579f2d81b9a916b0ed849d38896e9765b3b8c76f4320169f28553ab7f5.
Prossimo input esterno necessario: output del preparatore sul VPS; l'output
espone soltanto percorso/hash della review e limiti. Poi qualificare l'esecutore
e sottoporre l'esatto piano alla decisione HUMAN prevista; non attivare da questa
review non firmata. Non dichiarare la tappa1 completata.


---

## 16 ottobre — reader refresh v2 bloccato sulla custodia; v3 allineata al produttore

Fasi tecniche 8/8 conservate; funzionali 0/6.
L'output operatore v2 supera tutti i predicati URL: uguaglianza review,
HTTPS/hostname, nessuna credenziale/query/fragment, contratto Gateway esatto,
stessa origine approvata. Poi STOP PRIVATE_WORKLOAD_TOKEN_REQUIRED.
L'esecuzione si ferma prima di os.read(token) e di fetch_policy(): zero byte
token letti e zero GET policy. Il file è aperto per fstat, senza leggere contenuto.
Il marker composto non prova da solo quale proprietà del file sia diversa.

Il reader richiedeva erroneamente UID==GID e modo0400/0600.
Il produttore effettivo tools/semantic_policy_token_owner/producer.py,
AtomicTokenFile.publish/check_custody, pubblica invece UID0/GIDoutput_gid,
modo0440 in directory UID0/GIDoutput_gid modo0750; owner_installation.py
vincola output_gid10001. Sono contratti già esistenti, non una nuova eccezione.
La v3 richiede ESATTAMENTE file(0,10001,0440), directory(0,10001,0750),
antenati root senza scrittura group/other, file regolare singolo link,
custodia no-follow e drift; limite file65536 del produttore e token16384.
Non ammette più i vecchi formati diagnostici UID==GID/0400/0600.
Prima di leggere il contenuto espone soltanto UID/GID/mode e predicati
regular/singleLink/sizeBound/tokenBytesRead0. Nessun chmod/chown target.

Diciotto test locali PASS. La prova invoca il VERO AtomicTokenFile.publish
con open/chmod/write/fsync/rename reali e poi il reader sul file prodotto.
LIMITAZIONE: chown/fchown del filesystem Work restituiscono EINVAL; soltanto
ownership e metadati UID/GID sono simulati nell'adapter di test. Non è una prova
nativa kernel di ownership10001, né accettazione target. Test negativi coprono
UID/GID/modi errati, directory errata, symlink, path/origine/mount, risposta
troppo grande e redazione. Il sorgente del produttore è invariato.
bash -n del launcher viene verificato prima della consegna.

V1 e v2 restano storiche e non vanno rieseguite. Usare il nuovo launcher v3.
I vincoli v2 su endpoint/review/mount restano; massimo un token già montato e
un GET HTTPS, senza retry, emissione token, rinnovo worker/sessione, installazione
policy, grant, modifiche DB/Gateway/servizi o reset. Cumulativo69 conservato.
La causa runtime del403 e lo snapshot caricato restano non provati.
DRAFT, riconciliazione ricevuta e HUMAN THS ancora non completati.
Reader v3 SHA256: f98f493a6bdaad7ed20f17f5e8e251ae73fd10713ab34e865ba74239a66babd5.


---

## 16 ottobre — reader refresh v1 fermato prima di token e rete; correzione v2

Fasi tecniche 8/8 conservate; funzionali 0/6.
Output operatore: STOP SELECTED_AUTHORIZATION_HTTPS_ORIGIN_REQUIRED.
Lo stop avviene dopo l'uguaglianza dei riferimenti URL/token con la creationRequest
e prima di credential() e fetch_policy(): nessun token aperto e nessun GET policy
eseguito da questo tentativo. Zero nuovi grant, emissioni, reset o mutazioni.
Il cumulativo69 e la cancellazione del worker precedente sono conservati.

Errore nel reader: richiedeva path.startsWith('/api/'), ma il contratto Gateway
pubblicato è GET /internal/capabilities/v1/authorization/policy-bundle/active.
Fonte: ouf-semantic-registry eccef11a97367f20e278db40b9ed6f45dd980c37,
docs/installation/OUF_INSTALLATION_MANUAL.md, sezioni policy bundle e Gateway.
Il vincolo /api/ era un'assunzione diagnostica errata, non una regola PET.
Il marker composto v1 non distingue quale predicato target abbia fallito:
non dimostra origine diversa né un errore del refresh runtime.

Reader schema v2: percorso contrattuale ESATTO; HTTPS e assenza di credenziali
nell'URL/query/fragment obbligatori. Conserva origine della selection approvata,
uguaglianza con URL e token nella review, mount readonly e custodia.
Normalizza soltanto porta HTTPS implicita/esplicita443.
Espone separatamente i predicati URL prima dello stop, mai URL/credenziali.
Nessun fallback diretto all'owner o allargamento host/percorso.
Il launcher v1 resta storico e non va rieseguito; utilizzare il nuovo launcher v2.
Gli altri limiti diagnostici della v1 rimangono: un token workload già esistente,
un GET configurato senza retry, nessuna emissione/installazione policy o rinnovo,
TLS/hostname verificati, risultato dal VPS non equivalente al trasporto JVM
o allo snapshot policy in memoria. HUMAN THS resta il gate della tappa1.

Diciassette test locali PASS, inclusa regressione sul percorso Gateway canonico,
rifiuto dei percorsi /api/ e simili, origine diversa, mount diverso, symlink,
redazione e bound. bash -n launcher richiesto prima della consegna.
Prova v2 sul VPS ancora necessaria. Proposta originale non ritentata.
Reader v2 SHA256: 23515f3ffb879cfd8aeff078865f6898e0088b70751d909367dccc81ff5eebab.


---

## 16 ottobre — binding dinamico Authorization osservato sul target

Fasi tecniche 8/8 conservate, funzionali 0/6; tappa 1 ancora bloccata.
Il reader b8823885060654097bb43b635b8c664f031793c8 termina complete=true:
generazione Registry stabile tra due letture; authority precedente scaduta.
Nell'ambiente esplicito sono presenti REGISTRY_URL, REGISTRY_TOKEN_FILE,
REFRESH_SECONDS=30, MAX_STALENESS_SECONDS=300; riferimento token assoluto
coperto da mount readonly. Nessun BUNDLE_FILE/ID/VERSION/SHA256 esplicito.
SPRING_CONFIG_IMPORT presente, altri override Authorization non rilevati.
Il falso matchesObservedPolicy40Hash è dovuto al riferimento statico assente:
NON dimostra che il Registry usi una policy diversa dalla 40.
Configurazione dinamica osservata != successo del refresh o snapshot caricato.
Il reader non ha aperto policy o credenziali e non ha effettuato GET applicativi.

Una nuova lettura governata GRANTS sul subject ouf-admin conferma policy40 e
hash d4e2478c… con grant nominali semantic.propose e proposal.read, ancora
CONFIGURED_GRANTS_NOT_EFFECTIVE_PERMISSIONS. La prima invocazione incompleta
(senza selettore subjectId/externalRoleRef) è stata rifiutata dalla validazione
degli argomenti; la lettura corretta usa subjectId e non cambia grant.
Nessun altro tentativo semantic.propose/proposal.read è stato eseguito.

Prossima lettura: scripts/read-chatbot-semantic-policy-refresh-20261016.py.
È una diagnostica specifica dell'installazione, non un rinnovo runtime:
richiede URL e path token uguali alla creationRequest custodita, origine HTTPS
uguale alla selection Authorization già approvata, mount bind readonly con
source/target corrispondenti alla request. Apre un solo token workload già
montato (mai client secret, chiavi o credenziali alternative), controlla custodia
no-follow e drift, espone solo exp e scadenza come metadati JWT non verificati.
Esegue un solo GET al percorso configurato, con TLS/hostname verificati tramite
trust di sistema, senza redirect/proxy/retry/emissione token.
Un 401/403 non viene ritentato né aggirato. Risposta200: proietta solo versione,
conteggi dei due grant, presenza capability e confronti hash; nessun body grezzo.
Il confronto del JSON compatto è diagnostico, non prova che Java abbia installato
il bundle. Trasporto dal VPS != trasporto JVM del Registry. Snapshot in memoria,
causa precisa del precedente403, DRAFT e accettazione restano non provati.

Sei nuovi test locali PASS; sedici complessivi PASS. Nessun test locale prova il
target. Nessun grant, refresh forzato, restart, modifica DB/Gateway, nuovo worker,
budget reset o replay. Cumulativo69 e cancellazione precedente restano conservati.
La decisione HUMAN su Teatri rimane esclusivamente nel THS.
Attesa solo l'esecuzione VPS della nuova lettura pinned.

## 16 ottobre — lettura VPS completata, diniego anche sulla ricevuta

Fasi tecniche 8/8 conservate; tappe funzionali 0/6, tappa 1 sospesa.
L'output operatore del reader v1 termina con complete=true. Delivery inattiva
(MainPID 0, Result success), authority scaduta; il record WORKER è CANCELLED /
CANCELLED_BY_OWNER, attempts=59 e controlledCumulativeGrantAttempts=69.
Il totale 69 è presente nel record, non inferito. SESSION e ADMISSION non
espongono il cumulativo; ADMISSION è BLOCKED. Queste letture successive non
costituiscono snapshot atomico né liveness o accettazione applicativa.
Il motivo preciso di termine del processo figlio resta non provato.

Campione Registry: exitCode 0, stdoutBytes 596, stderrBytes 0; tutti i marker
cercati assenti. Questo non prova salute, grant effettivi o causa del 403.
Una lettura semantic.proposal.read con ouf-admin e la chiave originale
teatri-semantic-draft-be74308e098aa3a6-20261016 restituisce 403
SEM_CAPABILITY_REQUIRED:ouf.semantic.proposal.read. Nessun retry; riconciliazione
ancora non eseguita, DRAFT e review THS non provate.

Nel sorgente Registry eccef11a97367f20e278db40b9ed6f45dd980c37,
SemanticAuthorizationBoundary converte più SecurityException nello stesso
codice SEM_CAPABILITY_REQUIRED. Questo spiega il limite diagnostico del codice,
non dimostra il bundle/configurazione della generazione target.
Il nuovo reader installation-specific legge due volte soltanto i metadati
Docker dell'esatto Registry, usando il socket custodito del prepared bundle.
Espone presenza dei riferimenti Authorization, interi configurati, uguaglianza
con l'hash policy40 già osservato e copertura dei path da mount readonly;
non apre policy o credenziali e non interroga owner API.
Segnala canali di override Spring/JVM: la configurazione esplicita non equivale
allo snapshot in memoria; eventuali valori assenti restano sconosciuti.

Cinque nuovi test locali PASS (redazione, assenza di inferenze, alias duplicati,
authority scaduta, drift della generazione); dieci test locali complessivi con
il precedente reader PASS. Nessuna qualifica target del nuovo reader ancora.
Nessun grant, rinnovo, retry della proposta, restart, modifica Gateway/DB/IAM,
reset o replay dei claim. HUMAN THS resta necessario per approvare/pubblicare.
Evidenza: evidence/chatbot-semantic-denial-retained-target-20261016.json.
Prossimo passo: launcher pinned di lettura metadati Authorization; serve output VPS.

# Roadmap CSV/chatbot: 8 macrofasi tecniche e 6 tappe funzionali

Roadmap confermata dall'utente il 16 ottobre 2026. Numerazione stabile fino alla conclusione; non confondere queste macrofasi con i nomi interni del launcher. Aggiornare questo documento a ogni avanzamento o nuova evidenza. Negli aggiornamenti all'utente indicare fase tecnica N/8, stato, ostacolo, prossimo controllo e tappe funzionali completate N/6. Nessuna promessa sul numero di tentativi.

## Stato corrente

### Seguito: catalogo disponibile, proposta rifiutata dall'owner

Verifica del16 ottobre dopo l'handoff: tutti e quattro i tool semantici sono ora
callable nel catalogo di questa chat (24 tool OUF totali). Non è una lettura
indipendente del remote tools/list né una prova della causa del vecchio catalogo.
Un solo semantic.propose con ouf-admin e proposta be74308e… restituisce HTTP403
SEM_CAPABILITY_REQUIRED:ouf.semantic.propose; il wrapper classifica INVALID_ARGUMENT,
ma il corpo identifica un rifiuto di autorizzazione. Nessun retry automatico,
nessun artifactId/revisionId/ricevuta o review THS restituito.

La lettura governata Authorization mostra policy ouf-lab-authorization:40,
hash sha256:d4e2478ce91c0bb2d2d36144dab1305ad137b7ae4c74e218f07e70604ade57bc,
due grant configurati per ouf.semantic.propose e assegnazione nominale admin.
Sono CONFIGURED_GRANTS_NOT_EFFECTIVE_PERMISSIONS: non provano il bundle effettivo,
la freschezza o il contesto di decisione del Registry. Non aggiungere grant per
ipotesi e non dichiarare già individuata la causa. Chiave durevole del tentativo:
teatri-semantic-draft-be74308e098aa3a6-20261016; conservarla per riconciliazione,
non cambiare intento/chiave per aggirare il403.

Fasi tecniche1–8 conservate, funzionali0/6. La tappa1/6 resta sospesa prima della
creazione provata della DRAFT. Il nuovo reader scripts/read-chatbot-semantic-denial-20261016.py
legge stato conservato/processo/contatori presenti e un campione classificato dei
log Registry; ammette processo fermo e authority scaduta, senza riattivare nulla.
Cinque test locali PASS, inclusi output bound nativo e assenza di segreti nelle
proiezioni. Esecuzione VPS e causa effettiva del deny ancora non provate.
Evidenza: evidence/chatbot-semantic-proposal-denied-20261016.json.


**Aggiornamento13:02 Europe/Rome: correzione Registry Gateway COMPLETA sul target;
fasi tecniche1–8 conservate; CSV0/6.**
Review continuazione8d9ed8ebebf1937a091d45905a49019eb8c738f341a2522c290bd128a452cff3;
autorità830b072a37ef4d7689225acd39fd1ca4776f48e9a640f1405bb140ff8082d4da.
ENDcomplete:14nuove PUT e1modifica precedente adottata senza replay,
15tentativi cumulativi, zero DB/grant/lifecycle, journal precedenti immutati.
Mappa finale d4452956e84f19df0bc13b31b379985460a5fc60c9287d616757665229fc8e1b,
74route totali,15binding Registry corretti e59route estranee preservate.
Dopo ogni PUT: HTTP200, risposta immediata non uguale al route object richiesto,
ma GET integrale esattamente uguale alla mappa prevista. La forma della risposta
immediata non è una prova sostitutiva; la rilettura ha provato ogni effetto.

Verifica diretta MCP account ouf-admin dopo la correzione: semantic.search Teatri
risponde [] senza503; teatro []. Cinema restituisce l'ontologia ACTIVE con
artifact5ae731cc-e4c5-43a3-aa5e-a7576adbd3a1,
revision51706bed-81e4-4306-aca1-70119821727d,
publicationSet f92a2e17-30c9-456f-bb12-63afa84f41e6. Non prova gli8oggetti UDP
né alcuna nuova ricerca funzionale sul CSV Teatri.
Una quarta ricerca nello stesso minuto (PerformingArtsTheater) ha restituito
orchestration budget exhausted/retryablefalse. Nessun retry di quella chiamata,
reset o aumento budget. Il codice pinned MCP mantiene budget persistenti a
finestra per principal/manifest, distinti dal worker infrastrutturale; non
confondere questo errore con il503 corretto o con la finestra CSV scaduta.

Blocco funzionale corrente: manifest MCP f249b3dcc58c2a96742092d90fa09fd90b705bd0
pubblica semantic.propose/review.prepare/approval.request/proposal.read ACTIVE e
toolEligible, ma questi4tool non sono disponibili nel catalogo della connessione
in questa chat. Nessuna proposta/approval è stata creata. Verificare/aggiornare
la lista strumenti della connessione e poi proseguire attraverso il percorso
MCP→Gateway→owner e HUMAN THS; nessun bypass owner/backend diretto.
La proposta storica teatri-reuse-semantic-proposal-20261014.json resta NON
registrata/approvata: riuso PerformingArtsTheater,20campi lessicali, CAPtestuale,
coordinate/capienza qualificate e identità/access label da review HUMAN.
La finestra CSV originaria è terminata alle12:57:06; il suo output completo
riporta FINITE_DELIVERY_PROCESS_STOPPED_INSPECT_RETAINED_STATUS, non prova
indipendente del motivo interno. Nessuna nuova finestra applicativa/worker/grant
è stata emessa dalla correzione route. Serve riconciliazione dello stato conservato
prima di una eventuale ripresa governata. Non rilanciare installer/applicatori.

Gli aggiornamenti seguenti conservano la cronologia e non superano questo stato.


**Ultimo output VPS: fasi tecniche 1–8 superate nell'esecuzione; tappe CSV 0/6.**
Runtime d7bbb768970aad1a001ca4d085bcc87c58a29cec, review
07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc,
autorità a604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca,
unit ouf-file-cohort-16e5f80e40d09772048f1575850b643a.service.
Dopo l'attesa Ingestion il flusso ha superato sostituzione MCP, verifica completa,
nuova verifica autorizzazioni FINAL_COHORT e release_after_cohort_verification.
Stato COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE,
evidenza cohort 724b79922d99e1582f294ba9447011d713686fda7eaefa80575560b481b015aa.
È prova di esecuzione riportata dall'operatore, non una qualifica indipendente
permanente né accettazione CSV.

Il processo rimane nella stessa invocazione finita per osservare gli effetti
applicativi reali: controllo ogni 30 secondi, stampa soltanto se il digest cambia.
Perciò il silenzio dopo ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED è previsto e
non richiede rilancio. Il ciclo user CSV deve essere eseguito entro la finestra;
non viene creato automaticamente dal solo observer. Scadenza1792148226 =
2026-10-16 12:57:06 Europe/Rome; nessun rinnovo automatico o autorità permanente.
Prima osservazione owner: NOT_PROVEN, zero sorgenti/ACK/commit, nessuna nuova
ricerca chatbot; otto Cinema preservati ed asset Teatri riutilizzabile.
Prossimo obiettivo: review semantica Teatri e onboarding HUMAN nei THS,
poi commit13/ricerca/reimport senza duplicati/verifica finale. Dieci grant
predecessori conservati; il conteggio del nuovo worker non è stampato e non
va dedotto dal solo avvio. Non rinnovare né ripetere l'installazione.

### Diagnosi target della consultazione semantica

Readback operatore: finestra finita ancora attiva nello stato
ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED; 74 route finali stabili, Registry running
senza restart; riferimenti di firma presenti, chiavi della forma prevista e
variabili esposte da Nginx. Un accesso semanticSearch503 coincide nel campione
con un marker NO_LIVE_UPSTREAMS. Questo orienta il controllo verso l'upstream,
ma non identifica da solo la causa: nessuna correzione o riconciliazione eseguita.
L'osservatore può attendere regolarmente mentre il503 impedisce la consultazione
necessaria alla preparazione CSV. Le fasi tecniche completate non si ripetono.
Controllo successivo limitato: alias e DNS dal namespace APISIX, confronto con
il Registry corrente e apertura TCP senza payload solo verso i suoi indirizzi
indipendentemente riletti. Nessun valore DNS/IP o segreto pubblicato.

### Upstream target: alias storico non risolto, TCP corrente raggiungibile

Il successivo readback completo rileva una rete comune, un solo nodo, alias
configurato non corrispondente al Registry corrente e risposta DNS SERVFAIL
(rcode2), zero indirizzi. La porta del Registry selezionato indipendentemente è
raggiungibile da APISIX. Nessun healthcheck attivo/passivo configurato.
Questo supporta una correzione del binding, ancora da preparare, autorizzare e
applicare; non dimostra readiness HTTP o accettazione semantica. Il preparatore
Gateway selezionava il nome del Registry precedente prima del cutover: il
confronto con lo stesso piano non intercettava l'alias storico.
Nessuna ripetizione fasi1–8, nessun restore o rilancio installazione. Prossimo
passo: prova DNS/TCP del nome corrente e revisione privata del solo delta nodes
per tutte le route che usano l'esatto binding Registry storico. Tutte le altre
proprietà/route, grant e journal precedenti restano immutati. Nessuna scrittura
Gateway o autorità runtime emessa dal preparatore. Scadenza esistente invariata.

### Preparazione correzione: stop del probe, nessuna modifica

L'operatore riporta BOUNDED_NAMESPACE_DNS_READ_UNAVAILABLE prima della
pubblicazione della review; la causa interna del probe non è ancora dimostrata.
Nessuna route/servizio/database/grant modificato. La prima proposta basata sul
nome corrente non è qualificata sul target. Il controllo ora distingue lo stadio
del fallimento e propone esplicitamente un profilo diverso: indirizzo statico
già nel creationRequest approvato, accettato soltanto se NetworkID e IPv4Address
coincidono con il Registry corrente e la rete del Gateway. Non è fallback né
indirizzo hardcoded/default riusabile: è una nuova revisione privata da autorizzare.
Porta, pesi, contratti e proprietà delle route rimangono conservati. Nessuna
estensione della finestra o applicazione della correzione è stata eseguita.

### Revisione privata pronta:15 binding Registry,59 route invariate

L'operatore ha completato la preparazione: review71e8c444f6164cd077e25c13429f218c27bf909131b4031529c836e28687ccfa,
uno snapshot privato; nessuna scrittura Gateway/DB/servizio o grant. Il nome del
Registry ha un'unica etichetta di85caratteri (non DNS-valida). Il profilo
ouf.reviewed-retained-static-registry-address.v1 ha superato il controllo del
request approvato/rete corrente e TCP dal Gateway. Prevede15route con solo nodes
aggiornato e59route integre. Non è ancora applicato o accettato.
Prossimo passo: approvazione terminale dell'esecuzione esatta, firme dei due ruoli
infrastrutturali esistenti e applicazione con claim durevoli, fencing esclusivo
e GET dell'intera mappa prima/dopo ogni PUT. Nessun replay di claim ambiguo.
Scadenza esistente12:57:06 invariata; authority correzione massimo180secondi
entro tale limite. Nessun nuovo worker/grant, restart, backup o migrazione.

### Applicazione correzione sospesa: prima scrittura non confermata

L'operatore ha emesso autorità correzione
e1b672b93ba670849690860c99426683eee06fb88ff6c111f6428fde4ab0f496,
scadenza1792148012. Subito dopo: REPAIR_WRITE_ACK_UNPROVEN_NO_REPLAY.
La prima PUT può aver avuto effetto: nessuna scrittura è provata APPLIED e non
si deve rilanciare l'applicatore. Il claim durevole precede la PUT; occorre
rileggere journal e mappa Gateway, senza riconciliazione o replay automatico.
Il lettore dedicato distingue mappa prima/dopo il claim o drift estraneo,
con due letture e metadati limitati del log admin. Funziona anche dopo la scadenza
dell'autorità di correzione e non richiede che il processo finito sia attivo.
Non rinnova la finestra originaria12:57:06, non legge chiavi di firma e non firma.
Fasi tecniche1–8 conservate, CSV0/6; la correzione resta incompleta/non accettata.

### Prima PUT provata applicata:14 residue, vecchia finestra scaduta

Readback operatore: due mappe stabili coincidono esattamente con il risultato
della prima PUT, hash a58eb2bc7dc2c226eddd17e6b2b649129437e379ecd761326cda5a6a0b762ea0;
un solo admin PUT200 nel campione. Il journal precedente resta CLAIMED,
nextStep0; nessuna riconciliazione è stata eseguita dal lettore.
La risposta originale non è conservata: non sono provati i campi del confronto
immediato fallito. La continuazione conserva HTTP200/201 come requisito e rende
obbligatorio il confronto integrale della mappa dopo ciascuna PUT; la forma della
risposta immediata è solo metadato diagnostico.
La prima PUT non va ripetuta. Nuova sessione infrastrutturale da approvare:
riconciliazione separata della prima modifica,14PUT residue, massimo180secondi,
1tentativo storico conservato e15massimi cumulativi. Journal originario immutato,
nuovo journal/decisione/firme/fence; actor/reason/decisionRef/limiti persistenti.
La finestra CSV originaria è scaduta alle12:57:06: non viene rinnovata. Lo stato
effettivo del processo dopo la scadenza deve essere riletto, non dedotto.
Questa sessione corregge soltanto route; nessun worker/token/grant/start applicativo
o accettazione CSV. La ripresa funzionale richiederà autorità applicativa valida.
Fasi tecniche1–8 conservate, CSV0/6; correzione ancora da completare.

### Tappa funzionale 1/6: profilo confermato, consultazione semantica 503

Dal chatbot, account ouf-admin: source.file.preview conferma asset
6609b245-86ed-4315-8ce0-73f2a8555bf3, profilo7984c39c-7396-4248-ab0a-f2efc390b49c
versione1, CSV13righe/20colonne. Nessun nuovo upload/profiling. Il nome del teatro
è una chiave candidata proposta, non ancora approvata; CAP è profilato LONG e
richiede una mappatura che conservi la semantica testuale del codice postale.
Nessuna sorgente o proposta creata. semantic.search(q=Teatri,limit20) restituisce
Status503 e codice wrapper INVALID_ARGUMENT senza dettaglio: non è prova di
argomento invalido né della causa dell'indisponibilità. ouf.system.status restituisce
MCP HEALTHY/PUBLIC_OPERATIONAL: non certifica ogni dipendenza funzionale.
Fasi tecniche superate8/8, CSV0/6. Prima tappa funzionale bloccata sulla lettura
semantica; non riaprire la fase tecnica1 o ripetere l'installazione.

Diagnosi GET-only legata alla review07ee9e8... e autoritàa604f498..., invocazione
live3733354: due mappe route, stato Registry, presenza/forma/exposure dei riferimenti
signing NGINX senza valori, due letture log bounded con classificazione fissa.
Non ferma il processo, non esegue chiamate MCP/DB/IAM, grant, scritture o nuovi
mandati; scadenza esistente12:57:06 invariata. Eseguire in una seconda sessione.
Qualifica38886152124/job116924263413: 50test PASS senza skip.

### Cronologia precedente alla disponibilità tecnica

**Fasi tecniche 1–5 confermate complete; fase 6/8 sospesa su Ingestion; CSV 0/6.**
Readback VPS allegato il 16 ottobre: 28/28 nuove modifiche Gateway APPLIED,
74 route, due mappe uguali al piano finale (hash a6504c3d830019e84ca73e76fd62cb3a47ea6d07efe00d106a0e475fe770d574).
Undici effetti container APPLIED; ingestion.create CLAIMED, container
cbf3067d946cf21a8f4abbb03ed47a217f2f39624ed1a5fb23a642325129ee35
creato e mai avviato. Env è l'unica differenza: 8 voci richieste, 11 osservate,
composizione esatta dei 6 default immagine con la richiesta, zero chiavi o valori
estranei. Worker CANCELLED con 9 grant cumulativi (8 predecessori +1), admission
BLOCKED. Il prossimo effettivo sarà il decimo, in una nuova finestra HUMAN finita.
Backup COMPLETE e migrazioni COMPLETE/audit CLEAN confermati dal journal; UDP e
Onboarding nelle medesime generazioni, zero restart. MCP applicativo ancora fermo
nella vecchia generazione; fase 7 non eseguita, fase 8 pendente.
La correzione riconcilia la creazione esistente senza nuovo rename/create e
conserva anche le 28 modifiche Gateway: zero nuove scritture route. Qualifiche concluse:
494 test in 67 suite nella CI generale 38876888992; CI specifica
38877206131 e backup 38876889037 PASS. Launcher di fase 6 pubblicato
con sorgente runtime a2132d7ee330f9f0ce7d4fc9316dd880acad4f3f.
Questo rilascio non avanza lo stato target: serve la nuova esecuzione HUMAN
e la verifica del relativo esito sul VPS.
### Ripresa PATH qualificata, in attesa di esecuzione VPS

Runtime d7bbb768970aad1a001ca4d085bcc87c58a29cec: CI mirata 38882690699 PASS,
29 test di storico/ripresa e tre prove native Docker/APISIX; backup 38882690674
PASS. Nuovo controllo preventivo del PATH nel planner. Launcher
scripts/launch-chatbot-ingestion-image-path-20261016.sh pronto per nuova revisione
HUMAN. Suite generale aggiuntiva 38882690718 ancora in corso al rilascio.
Questa qualifica non avanza lo stato target, che resta fase6 sospesa/CSV0di6.
L'analisi dei possibili blocchi successivi è in
releases/CHATBOT_INGESTION_IMAGE_PATH_20261016.md e distingue prove e limiti.

### Causa del blocco di fase 6 provata: PATH ereditato

Secondo readback VPS: Entrypoint java coincide con immagine e richiesta,
Docker riporta executable file not found in $PATH; il PATH della richiesta
sovrascrive quello dell'immagine ed esclude JAVA_HOME/bin. JAVA_HOME coincide
con l'immagine. UDP e Onboarding hanno PATH/JavaHOME coerenti e restano attivi.
I dieci grant cumulativi sono confermati, senza ulteriori richieste dei due
lettori; il prossimo nuovo grant sarà l'undicesimo. Route 74 conformi,
backup e migrazioni precedenti conservati, stato fase6 sospesa/CSV0di6 invariato.
La ripresa preparata conserva il CID fallito tramite una rinomina prenotata,
poi crea un nuovo CID dalla stessa immagine, cambiando soltanto PATH secondo
i metadati verificati dell'immagine. Il vecchio start CLAIMED e i journal restano
immutati. Nessun nuovo dump/restore, migrazione MCP, replay UDP/Onboarding/Registry
o scrittura route. Nuova revisione HUMAN finita, non rinnovo del mandato precedente.

### Readback VPS: start Ingestion fallito prima del processo

Diagnosi allegata: stesso CID cbf3067d946cf21a8f4abbb03ed47a217f2f39624ed1a5fb23a642325129ee35,
status created, PID 0, neverStarted=true, ExitCode 127, restartCount 0.
Docker State.Error presente (224 byte), categorie MISSING_PATH_OR_EXECUTABLE
ed OCI_RUNTIME_FAILURE. Journal: 12 APPLIED + ingestion.start CLAIMED,
hash 4781c2c59cdd1075a4c1d5510a5fc91251a7350281a432d9a59dc59cdee7ecf1.
Worker CANCELLED: 10 grant cumulativi (9+1), admission BLOCKED; il prossimo
nuovo tentativo sarebbe l'undicesimo. Nessun budget azzerato.
Gateway 74 route conforme, 28 effetti conservati; backup COMPLETE, MCP
migrazioni COMPLETE/audit CLEAN; UDP e Onboarding stessa generazione.
Fase 6/8 sospesa, fasi 1–5 complete, CSV 0/6. Il programma non ha avviato Java.
L'eventuale conflitto PATH/JAVA_HOME con i default immagine è un'ipotesi:
prossima diagnosi legge soltanto confronto comando/ambiente e classificazione
più precisa dell'errore. Nessun nuovo start o modifica alla configurazione.

### Ultima esecuzione VPS: start Ingestion ambiguo

Runtime f6078a5ac07853b4abc13d310882f5a30086baba: preflight passato,
review 62c8837120f9079cbf2dd026105ccce7befbbbfbbd09b1c67fc813e6a468f91e
approvata; autorità b6335ae592c469d253a345c29352a6fe2180e1297a29146b98bf1048016b4fe4.
APISIX adottato senza replay, nuovo worker finito installato, Gateway verificato
senza scritture. Arresto COHORT_START_REQUIRES_RECONCILIATION nel POST Docker
start Ingestion: la risposta non era 204, il corpo non è conservato.
Lo stato fisico del container dopo la richiesta non è ancora provato.
Fase 6/8 sospesa, fasi 1–5 conservate, CSV 0/6. Il predecessore conserva nove
grant; il conteggio del nuovo worker deve essere letto e non va presunto pari a dieci.
Prossimo passo: diagnosi GET-only fissata all'ultima review/autorità/generazione,
lettura claim start e State.Error classificato senza testo, verifica delle route.
Nessun nuovo start, create, dump, restore, grant o replay autorizzato dalla diagnosi.

### Arresto del launcher di fase 6 nel preflight

Il tentativo con runtime a2132d7ee330f9f0ce7d4fc9316dd880acad4f3f si è fermato
in gateway_recovery.retained_bindings con AttributeError prima di nuova autorità
runtime: il nome locale prior (conteggio grant) nascondeva il modulo
migration_recovery usato per archive_bytes. Nessuna nuova approvazione richiesta,
nessun avanzamento target; restano nove grant conservati. La qualifica precedente
non copriva il percorso completo: l'enrichment simulava retained_bindings.
Correzione runtime f6078a5ac07853b4abc13d310882f5a30086baba: prior_count separato
dal modulo; nuova regressione attraversa il validatore e il lettore reale di tutti
quattro i file, rifiuta ogni archivio alterato e il conteggio errato. Nessuna
modifica a confini di autorità, pin, policy, retry, piani o identità target.
Il nuovo launcher è scripts/launch-chatbot-ingestion-archive-binding-fix-20261016.sh.
CI mirata 38879641570 PASS (21 test di storico/ripresa e due nativi), backup
38879641568 PASS; locale 14 test di consegna PASS. Suite generale aggiuntiva
38879641541 ancora in corso al rilascio; nessun avanzamento target derivato dai test.

La cronologia seguente resta come evidenza degli arresti precedenti.

### Cronologia precedente


**Ultimo output VPS: fase 5 superata nel flusso; sostituzione Ingestion/MCP
raggiunta (fase 6 almeno, fase esatta 6/7 da journal); CSV 0/6.**
Sorgente `e2252339dcc127e9237b8120727bf27439f506f0`, review
`50b5e2348c950ab9832cf890c7d0129f6ba92c8b05eb5d853fcd94ad1574b8cb`,
authority `50ce40e69082a813ba92b7dd9defacc1e6ccb904a3be8ef20226f80fca468893`.
Contesto `chatbot-file-cohort-signed-9e843050f99e2da257ec6c33221ae0c963f78412c7d31c119af97ae81dfa442f`.
Otto passi APISIX adottati senza replay; nuovo worker finito avviato; il codice
ha completato gateway.apply/verify prima di await_container nella coppia
Ingestion/MCP. Arresto: `COHORT_REPLACEMENT_PROCESS_CONFIG_DRIFT` nel confronto
Config effettiva/richiesta. Non assumere che sia Env o Labels prima di leggere
la differenza. Nessun rilancio del delivery consumato. Fasi 1–4 conservate;
la mappa Gateway completa e il journal devono essere riletti per conferma
persistente. Il totale grant corrente va riletto dal worker, non fissato a otto.
Diagnosi in sola lettura: `scripts/read-chatbot-postgateway-container-20261016.py`,
GET Docker/route, zero chiamate DB/IAM/MCP/grant, zero nuovi dump o scritture.
La sezione seguente conserva la cronologia dei tentativi precedenti.

### Cronologia precedente


Ultimo tentativo VPS: sorgente `495d46f6ff7320c6d6248438895a52c8dc4c0818`,
bloccato nel preflight con `PREGRANT_APISIX_GENERATION_DRIFT`, prima di login IAM,
revisione o emissione di nuova authority runtime. Il controllo originale pretendeva
ancora viva la generazione APISIX già sostituita: errore della ripresa, senza
nuovo avanzamento target. La correzione verifica la catena del predecessore
conservato e fermo verso il successore approvato e stabile; nessun replay.
Otto grant conservati; 28 modifiche Gateway residue, fasi 1–4 complete, CSV 0/6.

**Fase tecnica 5/8 sospesa; dimostrazione funzionale 0/6.**

Storico del primo arresto Gateway: l'esecuzione della prosecuzione `70af66b26d9a8dfdd7151c55f44eb5795fcc84a8` è arrivata a `PUBLISHING_REVIEWED_GATEWAY_ROUTES`, poi si è fermata con `GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY`. L'ordine del codice impone prima `migrate_mcp()` (con revoca verificata), quindi sostituzione/readiness e `verify_module()` di UDP e Onboarding. Le fasi 2–4 sono quindi superate nel flusso. La lettura VPS successiva conferma la fase 2 COMPLETE/CLEAN e la generazione UDP; la diagnosi completa successiva conferma entrambe le generazioni e le storie schema UDP/Onboarding. Non scambiare il successo del flusso precedente per disponibilità permanente dopo la cancellazione del worker.

**La fase 1 non è stata ripetuta:** vengono copiati/verificati i quattro archivi già COMPLETE, senza nuovi dump. I messaggi generici del launcher (`REGISTRY_REPLACEMENT_AND_VERIFICATION`, preparazione completa) descrivono passaggi comuni: in questa prosecuzione i dieci effetti Registry restano conservati e non vengono rieseguiti. Le autenticazioni/revisioni rinnovano la sola sessione finita, non la fase backup.

Il Gateway ha un claim di scrittura e una mappa riletta non uguale alla mappa attesa. L'ACK della PUT non è conservato dal codice corrente: dai soli log non si può distinguere mancata applicazione, normalizzazione lato APISIX o altra differenza. **Non ripetere quel delivery o quella PUT: usare solo la prosecuzione governata corrente, dopo la riconciliazione.** Diagnosi già eseguita: [diagnosi GET/SELECT di fase 5](../releases/CHATBOT_GATEWAY_PHASE5_READBACK_20261016.md), vincolata al contesto, con differenze strutturali redatte e verifica delle fasi già superate. Il primo reader, pur avendo superato CI `38841644559`, si è fermato sul VPS per una collisione del campo riservato `readOnly` prima di leggere Gateway. Il test del flusso aveva una fixture SQL incompleta: la correzione mantiene il guard e annida i risultati SQL sotto `facts`. Nuovo sorgente `26defb34e5573f535f03be869050fe3811725fd5`, CI `38842513682`: 12 test passati senza skip, inclusi PostgreSQL e namespace reali; il nuovo test riproduce il difetto sulla vecchia riga. Diagnosi VPS corretta completata: due GET stabili, nove effetti applicati, decima route assente e mappa esattamente precedente al claim.

| # | Fase tecnica | Stato |
|---|---|---|
| 1 | Riconciliare il backup interrotto e completare i backup dei quattro database | COMPLETATA: quattro archivi COMPLETE, hash e journal verificati sul VPS; nessun nuovo dump nella ripresa |
| 2 | Applicare le migrazioni MCP e verificare la revoca dei privilegi temporanei | COMPLETATA e confermata sul VPS: 12 migrazioni attese, COMPLETE/CLEAN, privilegi temporanei revocati |
| 3 | Sostituire UDP e verificarne schema e avvio | COMPLETATA; rilettura VPS conferma generazione running/restart 0 e 35 migrazioni attese |
| 4 | Sostituire Onboarding e verificarne schema e avvio | COMPLETATA; rilettura VPS conferma generazione running/restart 0 e 34 migrazioni attese |
| 5 | Pubblicare e verificare le route Gateway | **Completa: 28/28 nuove modifiche, mappa finale stabile di 74 route** |
| 6 | Sostituire Ingestion e verificarne schema e avvio | **Sospesa: create CLAIMED, container mai avviato; soli default Env immagine** |
| 7 | Sostituire MCP e verificarne schema e avvio | Da eseguire: vecchio container fermo |
| 8 | Verificare l'insieme e riabilitare i produttori | Da eseguire |

| # | Dimostrazione funzionale | Stato |
|---|---|---|
| 1 | Approvare la configurazione semantica del CSV Teatri | Da dimostrare |
| 2 | Completare l'onboarding con approvazione umana | Da dimostrare |
| 3 | Ottenere il commit effettivo in UDP delle 13 righe, con provenienza verificata | COMPLETATA:13/13 commit,13 oggetti distinti, zero quarantene; log target18 ottobre2026 |
| 4 | Ritrovare i dati con una nuova ricerca dal chatbot | Da dimostrare |
| 5 | Importare nuovamente lo stesso CSV e dimostrare il riuso degli oggetti senza duplicazioni | Da dimostrare |
| 6 | Verificare entrambe le acquisizioni e la conservazione degli otto oggetti Cinema esistenti | Da dimostrare |

## Correzione Gateway qualificata in CI, 16 ottobre 2026

La lettura schema VPS completa lega immagine e schema alla riproduzione: fase 5/8,
nove modifiche applicate, decima assente, otto grant cumulativi, CSV 0/6.
Fasi 1–4 conservate: nessun nuovo dump, restore, migrazione o sostituzione UDP/Onboarding.

Candidato Gateway `d20de6b886bc910cf408685a27eb78c76a910151`; CI nativa deploy
`38851740138` (job `116814239144`, sorgente `99dfe5e3d8dd9c4517c8c7910ccfc461475ffdd2`)
PASS: 37 route accettate/rilette esattamente prima e dopo riavvio, 24 vettori sulle
tre route interessate e 8 vettori generali JSON/numerici. Schema canonico invariato;
proiezione del solo `$id` qualificato, precisione cjson a 16 cifre e costanti range
del compilatore jsonschema a 17 cifre. Il massimo contrattuale resta 9007199254740991.

Il compilatore della prosecuzione conserva nove effetti APPLIED e il claim
storico irrisolto, calcola 28 modifiche residue e una diversa intenzione per la route
corretta. La successiva integrazione eseguibile richiede il nuovo profilo firmato,
la revisione HUMAN completa e i controlli concreti del runtime; il piano da solo
non conferisce autorità.
La pubblicazione futura conserva stato HTTP/hash/lunghezza ACK senza corpo privato;
GET esatta resta obbligatoria e nessun esito ambiguo autorizza replay.

**Gate ancora aperto:** integrare e qualificare insieme runtime APISIX, adozione dei
checkpoint delle fasi 1–4, fencing e nuova sessione finita con storia degli otto grant.
Non usare i launcher precedenti: nessun nuovo comando VPS di ripresa è rilasciato
con questa qualificazione. La fase 5 target NON è completata. [Prove e limiti](../evidence/chatbot-gateway-numeric-qualification-20261016.json).

## Collegamento schema/immagine target confermato, 06:26 Europe/Rome

La lettura mirata è completa: image ID corrispondente al manifest APISIX della riproduzione; schema canonico e proiezione metadata coincidono, URN annidato presente e zero riferimenti. Tutti e tre i massimi corrispondono al contratto safe integer. Due GET stabili: nove effetti applicati, decima route assente, journal immutato. Otto grant conservati, zero chiamate DB/letture backup/mutazioni. [Evidenza](../evidence/chatbot-gateway-schema-target-20261016.json). Non serve ripetere questa diagnosi per ricercare la stessa causa: prossimo lavoro è correzione della serializzazione, prova nativa dei limiti e prosecuzione governata. L'ACK storico resta non disponibile.

## Analisi storica precedente alla correzione numerica

La riproduzione isolata con Admin API APISIX reale restituisce HTTP 400 sulla stessa decima route per un `$id` URN annidato non supportato. La proiezione candidata elimina solo il metadato senza riferimenti, lasciando intatto il contratto canonico. La prova su tutte le 37 route ha inoltre rilevato tre massimi numerici alterati da 9007199254740991 a 9007199254741000.0: **il candidato non è ancora applicabile**, nessuna tolleranza nel confronto né indebolimento dei limiti. Controllo target successivamente completato: [schema e immagine, solo GET senza DB o archivi](../releases/CHATBOT_GATEWAY_SCHEMA_DIAGNOSIS_20261016.md). CI reader 16 test senza skip; riproduzione candidata 37 accettate, 34 GET esatte, 3 differenze aperte a quel checkpoint, poi risolte in CI come riportato sopra. Fase 5/8, CSV 0/6.

## Diagnosi completa VPS, 16 ottobre 2026 05:04 Europe/Rome

Log `/home/oufadmin/ouf-gateway-state.QOMMaUj8/read.log`, sorgente reader `26defb34e5573f535f03be869050fe3811725fd5`: END complete, archivi/journal immutati, zero dump/mutazioni/grant/IAM. Fasi 1–4 confermate nei checkpoint e nelle letture native/schema; la readiness corrente non è stata riprovata e non costituisce accettazione permanente.

Gateway: **9 modifiche APPLIED su 37**, claim alla posizione 10 (`nextStep=9`), due inventari identici alla mappa prima del claim. La route rivendicata è assente; nessuna differenza estranea. L'hash ID corrisponde nel sorgente pubblico a `mcp-managed-file-review-prepare`. L'ACK non è conservato: assenza osservata non dimostra causa, assenza storica di effetti o autorizzazione a ripetere PUT. Il claim resta consumato. Prossimo lavoro: riproduzione isolata del pacchetto originale con Admin API APISIX reale; poi diagnosi/correzione e riconciliazione governata. Otto grant conservati; fasi 6–8 e CSV 0/6 invariati. [Evidenza completa](../evidence/chatbot-gateway-target-readback-20261016.json).

## Ultima diagnosi VPS: parziale, fermata su RESERVED_OUTPUT_FIELD

Log `/home/oufadmin/ouf-gateway-state.FU6f1wTi/read.log`, reader sorgente `ebdcf153c450ea5ab55c1783d281f1b963c5c29c`. Quattro archivi COMPLETE invariati; checkpoint MCP COMPLETE/CLEAN, container migrazione exited 0 e 12 migrazioni attese presenti. Membership/CREATE/TRIGGER temporanei assenti, proprietà/OID/ACL preesistenti preservati. Registry conserva dieci effetti APPLIED. Worker CANCELLED: **8 grant cumulativi**, 2 nella sessione, nessun reset.

UDP running, generazione attesa e cinque effetti completati, restart 0. Il reader si arresta mentre emette lo schema UDP: `module_schema_read` restituisce `readOnly`, campo riservato nell'involucro. Nessuna lettura Gateway né verifica Onboarding raggiunta; controlli finali di stabilità non eseguiti. Zero mutazioni/dump/grant della diagnosi; non dichiararla completa. La correzione della sola emissione e del test non modifica criteri runtime, autorità o normalizzazione Gateway. [Evidenza parziale](../evidence/chatbot-gateway-target-partial-readback-20261016.json).

## Ultimo arresto VPS (16 ottobre 2026, output ricevuto alle 04:30 Europe/Rome)

Revisione `bd2cbc1e969bf3eb4c5b1b54240cf1d67d3283685bc1ca563f893d17e3430144`, autorità `0e3a1a76b5528704c3295eff50c92b269a4f69c7d5eeff3304b193e991b54cb8`.
Contesto `/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-35d5c6c756feb9c4811ac6d24610698a10c82d22b831d2cc85cd5c22c94d40d5`.
Unità `ouf-file-cohort-35d5c6c756feb9c4811ac6d24610698a.service`, PID iniziale 3622829, piano `b7bd0f0906ab9741b06e91040bd3f402c933b79fbed606cdde003e67d4afd538`, scadenza 1792121285, restart=no.
Log `/home/oufadmin/ouf-mcp-phase2-continuation-launch.AINt2Om8/run.log`.
La rilettura successiva conferma otto grant cumulativi: sei precedenti e due nella sessione, due pubblicazioni; worker CANCELLED e admission BLOCKED. Nessun reset, restore, nuovo primo grant o accettazione permanente. Fasi 6–8 non raggiunte; CSV 0/6.

## Qualificazione storica della prosecuzione di fase 2

Runtime `70af66b26d9a8dfdd7151c55f44eb5795fcc84a8`: CI completa `38838880289` superata, 435 test/58 suite, zero errori o skip. CI backup `38838880431`: 79 test/7 suite, parzialmente sovrapposti alla completa. CI nativa `38839051380`: binario MCP originale su Docker 29.8.1/PostgreSQL 17, da 9 a 12 migrazioni e revoca verificata dei privilegi temporanei; nessun accesso al VPS. Un ulteriore test locale del percorso produzione conferma completamento/pulizia e riconciliazione senza secondo start (13 test locali della nuova suite).

**Passo storico, ora consumato: nuova revisione completa sul VPS** con `scripts/launch-chatbot-mcp-phase2-continuation-20261016.sh`. La nuova sessione conserva sei grant cumulativi; il prossimo è il settimo. L'esecuzione successiva ha superato le fasi 2–4 nel flusso ed è sospesa in fase 5. Il launcher consumato non va ripetuto.

## Precedente conferma VPS (16 ottobre 2026, 03:56 Europe/Rome)

Diagnosi `ouf.chatbot-mcp-migration-readback.v1` conclusa con `complete=true`, zero mutazioni/dump/grant. Fase 1 definitivamente confermata per questo checkpoint: UDP 247357 byte, Onboarding 325831, Ingestion 94318, MCP 250874, tutti COMPLETE e immutati. Il nuovo MCP ha SHA256 `b050f7706b650199a09115e24828858de509179f26896c92072cab6ae9946dc4`.

Fase 2: container `e502ee4e5ebd13ca6cbc8857756d895668a06bd9ca4a44a0b27ed1b0232a12c6`, stato created, mai avviato, PID 0, restart 0. Soli confronti falliti: Env e Labels; entrambi coincidono con immagine più richiesta. Nove migrazioni, identiche alla baseline pre-migrazione; risultato atteso non ancora raggiunto. Ruolo audit BOOTSTRAPPED/NOLOGIN, membership SET=1, CREATE schema=true, TRIGGER temporaneo=1; proprietario/OID/ACL preesistenti preservati. Revoca ancora da eseguire e verificare.

Worker CANCELLED con 1 nuovo tentativo e 1 pubblicazione; **6 grant cumulativi**, predecessori 5. Admission BLOCKED. Registry READY v30 con dieci effetti APPLIED; zero effetti nei journal containers/authorization/gateway. Archivi e journal immutati durante la lettura. I controlli di integrità restano obbligatori: non equivalgono a ripetere la fase 1. La nuova prosecuzione deve usare tutti e quattro gli archivi e il container già creato, senza dump/create ripetuti; conserva i sei tentativi.

## Evidenza storica della sospensione al 16 ottobre 2026

Ultimo sorgente runtime: `b93e3570bd3e43b6c8e99d2237743bb819e43304`; release `cc8921b87a55d17f2a548f6be59eb592b9bd7581`. Il preflight del Registry già in esecuzione e del filesystem è passato sul VPS. Le dieci fasi Registry precedenti restano conservate.

Revisione approvata dall'utente: `225d317b485939ebf2a5b2582d0f5168a5ff6fe19be17e0e68109c9003dade1c`.
Autorità della nuova sessione: `ce4fcdc3b0af1aaee503582f00af4beed06786641d15afe4a55efa0cd29584d7`.
Contesto: `/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-f9616bc49b224fa219e6ea4b8c9ff5425f9728fda0bc2175d6d877ebb5189a9a`.
Unità: `ouf-file-cohort-f9616bc49b224fa219e6ea4b8c9ff542.service`.
Piano: `6714bf5f617fb53535d5cb3ee6ebf74abe4af841f83b42346a1c7b9d00ddb1e6`.
Scadenza dichiarata: `1792118031`; finestra massima 3600 secondi, nessun rinnovo automatico.

Il traceback raggiunge `databases.migrate_mcp`, riga 668, nella verifica native dopo create e prima di start. Il flusso ha già completato `backup_quiesced()` e verificato nuovamente l'archivio MCP prima del punto fallito: questo sostiene il superamento della fase 1. Questa era l'incertezza iniziale, risolta dalla lettura VPS riportata sopra. Non dichiarare già applicate le migrazioni o revocati i privilegi: la preparazione del ruolo audit precede il create e può avere lasciato privilegi temporanei.

Cinque grant erano consumati prima della nuova sessione; la successiva lettura ha confermato sei grant cumulativi. Il messaggio finale è `FINITE_DELIVERY_PROCESS_STOPPED_INSPECT_RETAINED_STATUS`, con autorità emessa. Nessuna prova end-to-end e nessuna accettazione permanente.

## Regole di prosecuzione

- Prima riconciliare con letture bounded, redatte e vincolate al contesto esatto; conservare claim, archivi, journal, conteggi e storia.
- Non ripetere il launcher già consumato, create/start ambigui o le dieci fasi Registry; non sostituire i backup né ripristinare il DB precedente.
- Non azzerare budget o estendere l'autorità. Una diversa ripresa richiede revisione governata concreta; delega allo sviluppo non equivale ad autorità runtime HUMAN.
- Correggere il contratto di identità solo sulla base dell'immagine e della richiesta verificate, mai consentendo genericamente differenze o variabili aggiuntive.
- Qualificare il comportamento Docker reale rilevante oltre ai test con engine simulato. Documentare separatamente prova CI, prova VPS e parti ancora non verificate.
- Proseguire autonomamente su codice/analisi/CI; fermarsi quando occorre l'intervento dell'utente sul VPS. Tenere l'utente aggiornato durante il lavoro.

Riferimenti: `AGENTS.md`, `docs/OUF_RESILIENCE_POLICY.md`, `releases/CHATBOT_RUNNING_ROOTFS_RECOVERY_20261016.md`.

### Historical phase-5 candidate checkpoint (qualification subsequently completed)

The previous full cohort CI run38852300756 completed successfully on549f9e66.
The new candidate integrates retained phases1–4, numeric compatibility mounts,
remaining28 Gateway writes and an eight-grant predecessor worker. Its new native
and signed integration gates are pending. No new target action or launcher is
accepted; target phase5 and functional0/6 remain unchanged. See
[continuation design and gates](../releases/CHATBOT_GATEWAY_PHASE5_CONTINUATION_DESIGN_20261016.md).


## Prosecuzione fase 5 qualificata, pronta per la revisione sul VPS

Sorgente `aeeb625ddacc5837e4520788d73a6598aaa5734f`. CI `38857329614` PASS:
APISIX reale sostituito con asset in sola lettura, nove effetti conservati e 28
scritture residue, mappa finale di 37 route esatta; revisione completa, storia di
otto grant e nono grant reale TLS. La correzione del confronto mount ordina solo
i record completi per destinazione univoca, senza scartare campi o alterare i pin
storici. La policy corrente si applica all'esecuzione nuova, preservando la
ricostruzione degli scope storici. Il guard Registry include esplicitamente il
profilo di fase 5 e conserva verifiche correnti di readiness e token montato.

Backup regression `38857329638` PASS. Suite completa `38857329616` PASS:
473 test in 63 suite, zero errori o skip. Il launcher sorgente/hash-pinned è
rilasciato: [procedura di fase 5](../releases/CHATBOT_GATEWAY_PHASE5_CONTINUATION_20261016.md).
Nessuna modifica target da queste prove; fasi 1–4 conservate, fase 5/8 sospesa,
CSV 0/6. Prossimo passo: nuova revisione privata completa sul VPS e decisione
HUMAN esatta, poi esecuzione e lettura dell’esito.

## Readback del 16 ottobre, 08:18 CEST: preparazione fase 5 bloccata

Il launcher `add1a8a53216ce35f1f8ece08b110417f5f8ec66` ha superato lo
storico conservato (otto grant, dieci effetti Registry) e la sessione IAM, ma
si è fermato prima della revisione HUMAN con `AttributeError` in
`gateway_runtime.compile_runtime` riga 81. `runtimeAuthorityIssued=false`.
Le fasi 1–4 restano acquisite, fase 5 non completata, CSV 0/6.

Il test locale riproduce lo stesso errore: `HostConfig.Binds=null` con
montaggi già espressi in `HostConfig.Mounts` causava `.append()` su `None`.
La correzione crea la lista solo nella nuova richiesta di creazione; conserva
identità e configurazione storiche e tutti i montaggi strutturati. Il test
nativo usa ora `--mount` e richiede esplicitamente `Binds=null` prima della
sostituzione. Il vecchio test Docker usava `-v` e non copriva questa variante.
Il launcher precedente è superato; attendere il nuovo pin qualificato.

La correzione `5d9c9b6b944e71b25cd006994c511397295b4f4f` supera la CI nativa
38860719163 con `Binds=null`, 9 effetti conservati, 28 scritture e 37 route;
regressione backup 38860719021 PASS. Il nuovo launcher e le evidenze sono nella
[procedura corretta](../releases/CHATBOT_GATEWAY_PHASE5_NULL_BINDS_20261016.md).
La regressione generale 38860719114 è ancora in corso alla pubblicazione.
Nessuna nuova esecuzione target: fase 5, CSV 0/6.

## Tentativo approvato del 16 ottobre, 08:27 CEST: verifica autorizzazioni

La revisione `57e0e293fef4abbaac5e45d214f30b3a1e312780f441c04c7f8c008c9fcf3209`
è stata approvata. Authority `08417d9c20401f26e5ea1223f753b016e1f35047e83d06e7aa8469af9432c852`,
contesto `chatbot-file-cohort-signed-594c62d1be7fc0274bcd90097e014736dc4aac636ab34bd7f8be1920fc875081`,
sorgente `5d9c9b6b944e71b25cd006994c511397295b4f4f`.

Il difetto Binds null è superato. L'esecuzione si ferma in `delivery.run` riga
413, `auth_owner.verify()`, con `AuthorizationPaused` durante la lettura MCP
`authorization.permissions.read` dei ruoli. Il flusso raggiunge questa riga
soltanto dopo `GatewayRuntime.apply()` e prima di `owner.install()`; indica
avanzamento della sostituzione APISIX, da confermare tramite journal e stato
nativo. Non dimostra pubblicazione delle 28 route, nuovo grant o fase 5 completa.
Fasi 1–4 acquisite, fase 5 sospesa, CSV 0/6. Non ripetere il launcher consumato.

La verifica finale legge il trasporto direttamente: non ha un budget durevole
per le osservazioni transitorie; `AuthorizationPaused` perde inoltre il codice
HTTP nell'output sicuro corrente. Prima di ammettere retry occorre distinguere
transitorio da rifiuto permanente e riconciliare i nuovi effetti APISIX.
Il reader `scripts/read-chatbot-gateway-authorization-20261016.py` è vincolato a
questa esatta review/authority/unità e legge journal, due mappe Gateway e al
massimo 200 righe di log del nuovo container. Pubblica solo conteggi di codici
HTTP; nessuna nuova chiamata MCP, refresh, IAM, grant, SQL, dump o scrittura
Gateway. L'assenza di access log riconoscibili è dichiarata senza inventare la
causa. Non costituisce ripresa né nuova autorità.

La diagnosi `1b098a98f46aaa0717000e322d971622b4540e53` supera i quattro test
mirati locali e la CI reader 38861702379 (job 116845217363, PASS). Il nuovo
launcher di sola lettura è `scripts/launch-chatbot-gateway-authorization-20261016.sh`.
Attendere il suo readback prima di predisporre una prosecuzione: la nuova
configurazione APISIX è un effetto già consumato da riconciliare, non da ripetere.

## Readback del 16 ottobre, 08:33 CEST: APISIX completato, autorizzazione MCP 503

Il reader conferma otto passi APISIX APPLIED, journal
`1505050a950b8a9d9565eff9fb95301d5193baa55ad8fc76dbb3acac3f362b18`,
container `733c5bdeca250fba778d431e121120e6653296d84c747552d8f95290ad01e8d9`,
runtime `456f99eb1c0d071d188194ba30c0cb1e73b9665e6a89ac03b21c9e2e3451e354`,
running, restartCount 0, due asset numerici RO. Le due letture delle 64 route
esistenti hanno hash `2df6795143d7f8c81aa8f692688a8ba40f1026de1053650dd61fbfe5736e35d8`:
corrispondono al prefisso conservato, non al piano finale. Restano 28 modifiche
delle 37 del piano; 64 è l'inventario totale, incluse route estranee preservate.

Autorizzazioni: zero effetti nuovi, journal
`690865a6eddb01ddca3edf90c7e3502e14d7c74af1b2b214987deddc9c65ea36`;
nuovo worker non installato. Gli otto grant precedenti restano acquisiti.
Nei log della nuova generazione compare una chiamata MCP 503 e un GET
amministrativo 200; il reader non conserva il corpo né dimostra la causa
interna di quel 503. Non sono stati effettuati nuovi MCP probe, grant o mutazioni.
Fase 5 ancora sospesa, fasi 1–4 completate, CSV 0/6.

La prosecuzione in preparazione adotta il journal APISIX in un nuovo journal
firmato e conserva il vecchio claim consumato. Nessun nuovo stop/create/start,
nessuna ristadiazione di configurazione o asset. La chain resta lo stesso profilo
Gateway e lo stesso incidente con una ricevuta tipizzata di adozione completata.
Una prenotazione nuova e distinta richiede un nuovo HUMAN review; non ripete
nessun effetto precedente. Le letture di autorizzazione dopo APISIX e prima del rilascio
coorte hanno un profilo firmato `ouf.authorization-finite-observation.v1`,
128 tentativi e 3600 secondi entro la scadenza HUMAN, backoff 5/15/60/300/900,
jitter massimo 20%, Retry-After, contatori persistenti, nessun rinnovo automatico.
Crash in ATTEMPTING, drift, revoca, rifiuti permanenti e budget esaurito bloccano.
Gli esiti ambigui di scrittura restano fuori da questi retry di sola lettura.
La nuova versione deve superare la qualifica Docker prima del launcher operativo.

### Dipendenza circolare della verifica ruoli, corretta prima del rilascio

Il planner `file_only_preparation.phase_intents` include tutte le vecchie
generazioni sostituite nei produttori quiescenti. MCP viene sostituito soltanto
dopo le route, nella fase 7; quindi una nuova lettura MCP dei ruoli prima di
installarlo può restare 503. Nel processo iniziale `OwnerTransport.roles` conserva
la cache ottenuta prima della quiescenza; un processo di ripresa la perde.
Il solo retry non elimina tale dipendenza. Non è una prova del corpo interno
dell'errore storico, ma è un vincolo dimostrabile del flusso corrente.

La ripresa ricostruisce quella cache dalla ricevuta owner immutabile
`before/QUIESCE_PRODUCERS.ownerEvidence`, dopo averne verificato l'hash con il
nuovo scope firmato. Il catalogo pianificato deve avere esattamente il medesimo
roleCatalogueHash. Prima e durante l'osservazione preliminare, policyRef e
contentHash vengono riletti dall'owner HTTPS e devono restare identici alla
ricevuta. L'owner pubblica ruoli e policy nella stessa transazione bloccata
(OufRoleCatalogueStore.stage / PermissionProposalService.decide); questo è lo
stesso contratto già usato dalla cache in-process, non un nuovo endpoint o un
accesso diretto al DB. Policy diversa o gara di pubblicazione blocca senza
interrogare MCP fermo. Gli altri controlli di policy, descriptor e OAuth sono
comunque riletti. Dopo l'avvio del nuovo MCP la cache viene svuotata e la lettura
MCP reale è obbligatoria prima di rilasciare i produttori. Test specifici provano
assenza di chiamate MCP durante la quiescenza, gara/drift e refresh finale con
503, attesa e recupero. Nessun permesso o ruolo applicativo viene modificato.

## Prosecuzione qualificata: APISIX già completato, ruoli e budget riconciliati

Sorgente `495d46f6ff7320c6d6248438895a52c8dc4c0818`, capsula di 129 membri
`ae6cb82723a0273e64a198354eb5ed2d826b8a80f8a3db201a2a8d6deb73db8d`.
CI nativa 38865027512 PASS (job 116855740434: adozione degli otto passi APISIX con
zero nuove operazioni, nove modifiche conservate e 28 residue; job 116855740112:
revisione completa, otto grant TLS conservati e nono effettivo, sei test budget/ruoli,
tre custodia/adozione e due orchestration). Regressione generale 38865027539 PASS:
484 test in 65 suite, zero errori o skip. Regressione backup 38865028729 PASS.

Launcher operativo `scripts/launch-chatbot-gateway-retained-20261016.sh`, SHA256
`d3f2f1b24a14475fc02a5074d53dd9483480e0860b7c9d519d55823ef470db13`.
[Procedura completa](../releases/CHATBOT_GATEWAY_RETAINED_AUTHORIZATION_20261016.md),
[evidenza](../evidence/chatbot-gateway-retained-authorization-20261016.json).
Il comando prepara una nuova revisione completa prima di APPROVO; adotta APISIX
con controllo delle generazioni e non ripete stop/create/start. I ruoli prima
della quiescenza sono accettati solo con identico policyRef/contentHash owner
appena riletti; lettura MCP nuova obbligatoria prima del rilascio produttori.
Fasi 1–4, quattro backup, migrazioni CLEAN, UDP/Onboarding e Registry sono conservati.
Otto grant storici restano conteggiati; una nuova finestra HUMAN finita, nessun
primo grant o budget storico ripetuto. URL e legami di rete restano quelli
approvati; adattatore Docker/netns specifico, non qualifica multi-host generale.

Nessuna nuova esecuzione target durante questa qualifica: **fase 5 ancora sospesa,
fasi 6–8 da completare, CSV 0/6**. Solo il prossimo output VPS può avanzare la roadmap.


## Correzione del preflight verso APISIX già sostituito

Il launcher precedente, sorgente `495d46f6ff7320c6d6248438895a52c8dc4c0818`,
si è fermato prima della revisione con `PREGRANT_APISIX_GENERATION_DRIFT`.
`current_baseline` invocava il lettore pregrant originale senza indicargli la
sostituzione APISIX già completata. Il lettore richiedeva ancora viva la vecchia
generazione: errore nel percorso di ripresa, non prova di nuovo drift operativo.
Il tentativo non ha emesso authority runtime; nessun nuovo grant o avanzamento.

La sorgente `e2252339dcc127e9237b8120727bf27439f506f0` passa esplicitamente
il predecessore riconciliato al lettore. Restano obbligatorie le prove delle
cinque immagini e del più vecchio container ritirato. Solo con la ricevuta esatta
si segue il collegamento oldRuntimeBinding del piano approvato: identico pin
dell'effetto originale, identica HostConfig originaria, predecessore conservato
fermo senza nuovo avvio/restart, otto effetti APPLIED e successore attuale stabile
verificato due volte. Non si accetta un container arbitrario né si elimina un
controllo di identità. Percorsi senza questa ricevuta mantengono il predicato
precedente e respingono generazioni cambiate.

CI Gateway `38871464959` PASS: job `116876301244` prova il nuovo controllo
pregrant con Docker reale prima dell'adozione, zero operazioni di ciclo di vita
aggiuntive e 28 scritture residue; job `116876301590` prova la storia finita e
cinque test di custodia/lineage, compresi drift e instabilità respinti.
La qualifica CI non avanza il target: fasi 1–4 complete, fase 5 sospesa, CSV 0/6.


Qualifica completa della correzione pregrant: CI `38871464818`, job
`116876298761`, PASS: 487 test in 65 suite, nessun fallimento o skip.
Regressione backup `38871464977`, job `116876299223`, PASS.
Launcher corrente `scripts/launch-chatbot-gateway-retained-20261016.sh`,
SHA256 `5fb2c9f42e28b18f4e16705642587322f227d889b27f4a375d78e338e7183ed2`;
sorgente runtime `e2252339dcc127e9237b8120727bf27439f506f0`, capsula di 129
membri `9ca1c537e02de4fb2fa988edd244a46613fa115332d9a16de32db4fd0bd49991`.
Il precedente launcher vincolato a 495d46 è superato: usare questo rilascio.
Nessuna nuova esecuzione VPS durante la qualifica: fase 5 ancora sospesa,
fasi 1–4 conservate, otto grant storici, 28 modifiche residue, CSV 0/6.


## Diagnosi del nuovo arresto dopo Gateway

Reader `scripts/read-chatbot-postgateway-container-20261016.py`, sorgente
`c48305c1f960cb7642589a5b973ac0520193b200`, SHA256
`3c057b348857d99784af932f11cb86d458bd7c225aef70f180845ced68219405`.
CI `38874295581`, job `116885500996`, PASS: 26 test, comprese le prove reali
namespace GET e SELECT PostgreSQL dei lettori di regressione. Il nuovo lettore
non chiama PostgreSQL: verifica file privati, GET Docker e due GET Gateway.
Il flusso completo è provato con file privati reali e osservazioni native
simulate; i helper di trasporto/custodia sono identici al lettore già qualificato.
Non dichiara esecuzione o riconciliazione sul VPS prima dell'output operatore.
Legge modulo/passo CLAIMED, configurazione richiesta/immagine/effettiva senza
valori, worker con contatori reali, journal 28/28 Gateway e mappa finale stabile.
Zero nuovi dump, backup letti, DB/IAM/MCP/grant o scritture di servizio/Gateway.
Launcher `scripts/launch-chatbot-postgateway-container-20261016.sh`, SHA256
`ad9ac7854ca025f0b097a6164d22e3fe3539951f2af7b6001a438d39c4326b24`.
Il vecchio delivery non va rilanciato: contiene effetti ormai consumati.

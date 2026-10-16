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

# Handoff aggiornato — tappa funzionale1/6 sospesa sul403

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


Procedura: releases/CHATBOT_SEMANTIC_DENIAL_READBACK_20261016.md.
Richiedere l'output del launcher pinned; non è ancora disponibile la lettura VPS.

---

## Snapshot storico precedente (13:02 Europe/Rome)

# Handoff — Gateway repaired; functional CSV stage1/6

Last verified operator result2026-10-16 13:02 Europe/Rome. Work in Italian.
Follow AGENTS.md and docs/CHATBOT_CSV_ROADMAP.md; progress updates every~60seconds.
No direct VPS/SSH transport is available: publish exact pinned/hashed commands;
operator executes. GitHub read/write GioNob authorized. Never push this dirty
checkout wholesale: explicit paths/tree/CAS only; private fixtures must not leak.
Do not spawn agents unless explicitly requested. Continue until external input
is necessary. Chat disconnections are recurrent; make state/progress visible.

## Current outcome

Eight technical phases completed and retained. CSV functional0/6. Gateway
Registry upstream correction COMPLETE, not application/E2E acceptance.
Source continuatione13825d65481a151665497ae90101f4db27f7276;
releasec5f80dbaaa8e10322ef939f9ba5125e5266b061f.
CI38890710003/job116939252099:91tests PASS, zero skipped; includes actual
Ed25519 and disposable namespace HTTP PUT, not target APISIX conformance itself.
Operator review8d9ed8ebebf1937a091d45905a49019eb8c738f341a2522c290bd128a452cff3;
repair authority830b072a37ef4d7689225acd39fd1ca4776f48e9a640f1405bb140ff8082d4da.
ENDcomplete:14PUT applied,1previous PUT adopted without repetition,
15cumulative attempts, zeroDB/grants/lifecycle, predecessor journals unchanged.
Final74-route mapd4452956e84f19df0bc13b31b379985460a5fc60c9287d616757665229fc8e1b;
15Registry bindings corrected,59unrelated routes preserved.
Every PUT returned200; immediate reply normalization was not equal to the exact
requested route. Exact full-map GET after each mutation proved all effects.
Do not rerun any repair applicator: journals/issuance claims are consumed.

## Root cause and retained history

Gateway plan originally selected a pre-cutover Registry DNS name, then compared
target against that same stale plan. Old name did not match current aliases;
DNS SERVFAIL, no address, while independently bound Registry TCP reachable.
The replacement container has one85-character name label, invalid as DNS.
The correction uses explicit versioned profile
ouf.reviewed-retained-static-registry-address.v1: address derived from signed
creationRequest NetworkingConfig/IPAM and required equal current NetworkID/IP,
reachable from APISIX. No embedded replacement IP/domain/default fallback.
A future reusable installer must preserve logical identity across replacement
and qualify post-cutover DNS/reachability. This scoped fix is not that general
implementation or independent multi-host/network qualification.

Prepared private review71e8c444f6164cd077e25c13429f218c27bf909131b4031529c836e28687ccfa
at /etc/ouf/deploy-snapshots/semantic-upstream-review-71e8c444f6164cd077e25c13429f218c27bf909131b4031529c836e28687ccfa/review.json.
First authoritye1b672b93ba670849690860c99426683eee06fb88ff6c111f6428fde4ab0f496
stopped on REPAIR_WRITE_ACK_UNPROVEN_NO_REPLAY. Readback proved exact map after
claim0, a58eb2bc7dc2c226eddd17e6b2b649129437e379ecd761326cda5a6a0b762ea0,
with two stable GETs and one PUT200. Old repair-journal.json stays CLAIMED/next0.
The completed continuation preserves it and creates execution-continuation-v2/
first-write-reconciliation.json plus repair-continuation-v2.json. Never reset it.

## Original application window expired

Runtime sourced7bbb768970aad1a001ca4d085bcc87c58a29cec;
review07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc;
authoritya604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca;
context /etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b;
unitouf-file-cohort-16e5f80e40d09772048f1575850b643a.service, originalPID3733354.
Expiry1792148226 =2026-10-16 12:57:06 Europe/Rome.
Operator supplied complete first-terminal output: all8technical phases reached
COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE, cohort hash
724b79922d99e1582f294ba9447011d713686fda7eaefa80575560b481b015aa,
then ownerNOT_PROVEN zero sources/ACK/commits and finally
FINITE_DELIVERY_PROCESS_STOPPED_INSPECT_RETAINED_STATUS. That wrapper does not
prove the child's precise terminal reason. Inspect retained state before any
new governed application session. Route repair did not renew that window,
create a worker/grant or accept perpetual runtime. Do not reinstall phases1–8.
Predecessor10controlled grants proven before the last application worker;
its actual cumulative total needs current readback, never guess/reset it.

## Direct chatbot checks after repair

Use ouf-admin connection (last link_idlink_6aafef96b4148191b767e9af7b756a07;
principalb93d8cf6-cd14-4ee6-91d7-84cd76c4f500). Re-establish current connection
identity after refresh if link IDs change; do not silently switch to giovanni.
semantic.search Teatri→[] success; teatro→[] success;
Cinema→oneACTIVEONTOLOGY artifact5ae731cc-e4c5-43a3-aa5e-a7576adbd3a1,
revision51706bed-81e4-4306-aca1-70119821727d,
publicationSetf92a2e17-30c9-456f-bb12-63afa84f41e6.
This proves semantic consultation works now, not all8UDP Cinema objects or CSV.
A fourth query in the same minute, PerformingArtsTheater, returned
orchestration budget exhausted/retryablefalse. No retry/reset/limit increase.
Pinned MCPf249b3dcc58c2a96742092d90fa09fd90b705bd0 budget code uses persisted
principal/tenant/service/manifest windows; kernel window1minute, threshold3,
default1call maximum per invocation yields window3calls, with byte/object limits.
This is separate from installer/lease worker budgets. Pace fresh legitimate
operations and do not retry the failed query or bypass admission.

## Immediate blocker: client tool catalogue

Current pinned candidate manifest declares semantic.propose,
semantic.review.prepare, semantic.approval.request and semantic.proposal.read
ACTIVE/toolEligible; kernel registers active eligible tools. These four are NOT
available in this chat's OUF tool catalogue, while search/get/file/onboarding are.
Actual fresh remote tools/list has not been independently fetched here: do not
assert the exact cache/permission cause. Refresh the existing OUF connection's
metadata in ChatGPT and verify the four proposal tools become callable. Official
OpenAI guidance for direct custom MCP: open connection at ChatGPT Plugins,
Refresh, check changed metadata, start a new conversation and retest:
https://developers.openai.com/plugins/deploy/connect-chatgpt#refresh-metadata
Do not delete/recreate credentials, expand IAM grants or call owner APIs directly
merely to bypass the missing chatbot catalogue. No fresh proposal/source exists.

## Functional input ready for governed review

Existing Teatri asset6609b245-86ed-4315-8ce0-73f2a8555bf3;
profile7984c39c-7396-4248-ab0a-f2efc390b49c version1.
Actual MCP preview confirms13rows/20columns/UTF8/semicolon. No new upload/profile.
Identity native-key(nome_teatro) is only PENDING_HUMAN_REVIEW. Never autoapprove.
Prepared unregistered proposal releases/teatri-reuse-semantic-proposal-20261014.json,
hashbe74308e098aa3a65396f3df739dd8f2837e9f8e27b6e49deb0e49d04506cb1a,
reuses schema.org/PerformingArtsTheater/name/additionalType, qualified source
properties for other fields; it is NOT an active semantic revision/publication.
Historical semantic namespace reflects this installation; new operational
endpoints/names/placement always derive validated installation/bootstrap config.
Preserve approved contract paths/semantic identities; never invent active refs.
Use all20fields with lexical IDENTITY only as a proposal: profiler LONG/DECIMAL/
DATE is metadata, not implemented conversion. CAP must preserve original lexical
zeros, coordinates need CRS/precision/provenance, capacity qualified by notes.
RESTRICTED labels, identity and inclusion require HUMAN review, not this chat.
All semantic refs must resolve exact containing approved revision/publication.

## Stable six functional milestones

1. Approve Teatri semantic configuration through governed owner/HUMAN THS.
2. Complete onboarding with HUMAN approval.
3. Prove actual13-row UDP commit and provenance.
4. New actual chatbot search finds committed data.
5. Second CSV import reuses objects without duplicates.
6. Verify both acquisitions and all8existing Cinema objects.

No functional milestone is proven. Preserve releases/chatbot-existing-cinema-baseline-20261014.json.
Read PET baseline releases/PET_ROADMAP_RECONCILIATION_20261010.md
(Matrix1.7/Blueprint0.3), AGENTS.md and resiliencev3. HUMAN decisions stay THS;
MCP proposes, Gateway mediates, Authorization evaluates and owner enforces.
Use durable cumulative budgets/backoff/jitter/Retry-After for explicitly
retryable reads; unknown/ambiguous mutation/configuration drift blocks replay.
No restore/reset/budget reset/new first grant/automatic session renewal.

New target evidence: evidence/chatbot-semantic-upstream-complete-target-20261016.json
and evidence/chatbot-post-upstream-semantic-reads-20261016.json. They contain safe
metadata, not raw CSV/keys/tokens. Do not publish private target review values.

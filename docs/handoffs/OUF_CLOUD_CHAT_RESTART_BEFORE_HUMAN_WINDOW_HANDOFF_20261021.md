# OUF CLOUD — ripartenza in nuova chat prima della finestra HUMAN

**Stato di trasferimento: richiesta esplicita dell’owner,21 ottobre2026. Nessun nuovo STOP runtime.** L’owner ha dichiarato: «il tuo comando NON lo ho eseguito». Si riferisce al comando `open-window` riportato sotto. La finestra successiva **non è stata aperta**, nessun nuovo login HUMAN è iniziato e il budget resta **284/288, quattro richieste residue**. Non trasformare questa dichiarazione in una nuova osservazione remota o in autorità runtime. Questa sessione si conclude con sola documentazione, nessuna ulteriore operazione VPS.

L’owner allegherà personalmente nella nuova chat gli originali PET/baseline. Non sono stati pubblicati archivi PET o estrazioni integrali nel repository durante questo trasferimento. I riferimenti e gli hash sotto identificano gli allegati da consultare; il registro di integrità non sostituisce la lettura delle sezioni pertinenti.

## 1. Prima azione della nuova chat

Leggere questo handoff, gli AGENTS e i documenti obbligatori del§2. Verificare il catalogo strumenti disponibile per l’account ouf-admin senza usare un tool protetto come prova implicita di autenticazione. Poi **chiedere all’owner di eseguire esattamente il comando del§3**, già qualificato e non eseguito. Non ricominciare diagnosi, installazione, policy IAM, preflight, login o apertura di finestre alternative. Non aprire la console Keycloak. Non eseguire automaticamente il comando.

Autonomia autorizzata per sviluppo/diagnosi/repository, in sequenza e senza subagenti/automazioni operative; proseguire finché non serve davvero un intervento HUMAN. Ogni richiesta del terminale deve essere spiegata: comando, password corretta, frase esatta, output atteso, azione successiva. L’owner è su cellulare; non deve dedurre da solo cosa fare. Aggiornamenti frequenti, con tecniche8/8,funzionali4/6,gate corrente e cronologia reale vs baseline.

## 2. Letture obbligatorie e autorità

Usare il commit che contiene questo handoff e i riferimenti pinned; main da solo NON contiene necessariamente gli ultimi draft. La branch documentale corrente è `feat/csv-e2e-owner-composition-20261020`(PR43). Per gli originali PET leggere gli allegati dell’owner, rispettando le supersessioni.

| Documento | Riferimento | Uso |
|---|---|---|
| Istruzioni progetto | [AGENTS](../../AGENTS.md),poi AGENTS del modulo prima di modificarlo | Ownership,parametri Ente,resilienza,IAM,canale VPS |
| Stato corrente unico CSV | [CHATBOT_CSV_ROADMAP](../CHATBOT_CSV_ROADMAP.md) | Leggere i prefissi CURRENT; i blocchi inferiori sono storico |
| Mini-PET esecutivo | [v1.1](../OUF_CSV_E2E_COMPLETION_MINIPET_v1_1_20261020.md),baseline d190193773116c9a59403aa42ccc9f89423eb959 | Seguire WP0–WP7,gate,criteri M1/M2 e§§15.1–15.7; non riscrivere la baseline |
| Registro del piano | [csv-e2e-completion-plan](../../releases/csv-e2e-completion-plan-20261020.json) | Requisiti,30attività,dipendenze,criteri CSV-AT-* |
| Cronologia reale | [timeline-current](../../evidence/csv-e2e-execution-timeline-current.json) | Intervalli attivi/attese/non segmentati,eventi target,gate; non azzerare o duplicare |
| Resilienza vigente | [policy v3](https://github.com/GioNob/ouf-deploy/blob/5d114e3973667dd26dde407a70d6718263ad1840/docs/OUF_RESILIENCE_POLICY.md),rileggere anche la versione vigente se modificata | Retry finiti,ambiguità,quarantena,budget nuovi espliciti,OA,fencing |
| Baseline PET | [indice riconciliazione](../../releases/PET_ROADMAP_RECONCILIATION_20261010.md),[integrità allegato](../../evidence/pet-baseline-cloud-integrity-20261018.json) | Indice normativo e precedenze; stati del10ottobre sono storici,non nuove prove target |
| Ultimo dossier operativo | [supplementary HUMAN](OUF_CLOUD_SUPPLEMENTARY_HUMAN_READY_HANDOFF_20261021.md) | Catena completa IAM,profili,limiti,prove,comandi successivi |
| Origine miniprogetto | [handoff Mini-PET](OUF_CLOUD_CSV_E2E_MINIPET_HANDOFF_20261020.md) e [riesamina repository](../CSV_REPOSITORY_REAUDIT_AND_EFFORT_20261020.md) | Motivazione del riuso,effort e perimetro |

Baseline originale: OUF_Reality_Baseline_Package_v1_7.zip SHA256 **e63df67e8817eec38a9d4b3eb736b020f693b932f3360dc02f4555330f2201ce**,323checksum verificati storicamente; non ripetere audit/installazioni già conclusi. Matrix1.7 e supersessioni governano la coerenza; Blueprint0.3 e Notice1.1 per parti applicabili; PET Authorization1.5,Onboarding/THS1.6,Ingestion1.3,UDP/Lake1.3,Semantic1.3,Gateway1.5,MCP1.4. Contratti1.0.0-rc3-coherence. Consultare gli originali pertinenti a ogni decisione, registrando versione/sezioni realmente lette. Per questa chiusura sono stati riletti policy v3 e indice di riconciliazione; per il delta precedente Matrix1.7§1,Blueprint0.3§§9–10,Authorization1.5§2.1/12.1 e Mini-PET1.1. Nessuna dichiarazione di conformità completa deriva da questi controlli.

Resilienza: default5/15/60/300/900s,jitter20%,128tentativi/24h si applicano dove il profilo governato li consente. **Non applicarli come polling/login/replay in questo percorso manuale**, che ha profili finiti più restrittivi. Mutazione ambigua,integrità/generazione/identità non provata,revoca o errore ignoto: conserva e riconcilia. Nessun reset,rollback automatico,nuovo contesto a contatore zero o riuso di claim. Un nuovo budget richiede decisione HUMAN separata e conserva il cumulativo; qui NON ne è stato concesso uno nuovo oltre288.

## 3. Esatto prossimo comando NON eseguito

Il launcher corrente è già presente sulla VPS. Non riscaricare/installare nulla e non usare vecchi launcher HUMAN. La verifica hash precede l’esecuzione.

```bash
printf '%s  %s\n' \
  702e2c42ea94eecdf53a38d85ed42e7fea47341a8bb518db955cd7e55a667026 \
  /home/oufadmin/ouf-human-supplementary-launcher.1gLteQgM \
  | sha256sum -c - &&
bash /home/oufadmin/ouf-human-supplementary-launcher.1gLteQgM open-window
```

Può chiedere **password sudo di oufadmin**, non password IAM. Quando il terminale chiede “Scrivi esattamente”, l’owner deve incollare **nel terminale**:

```text
APRO FINESTRA HUMAN 981d810332ad855e7b9305d15fc4bbb10796bc50d556241060d7044c43d715dc
```

Questo approva una sola finestra di7200secondi. **Zero richieste OAuth**, nessun login avviato, nessuna autorità runtime/THS. Esito atteso: schema`ouf.human-supplementary-ledger-result.v1`,state`NEW`,attempts284,remainingAttempts4,newHumanWindowOpened true. Chiedere JSON pubblico finale e nuovo percorso `operator.log`. Se compare STOP o drift, conservare contesti/claim e diagnosticare in quel contesto; **non rilanciare open-window**,non rifare prepare e non inventare un altro hash per aggirare il blocco.

Il controllo stesso ricontrolla catena,custodia,boot/clock,consensi e preparazione trattenuta prima degli effetti. L’hash è quello verificato sulla VPS, non una credenziale. La nuova chat non deve fingere di avere già aperto la finestra o ottenuto un token.

## 4. Ultima prova target e cronologia certa

Preflight nativo qualificato eseguito una sola volta, [ricevuta](../../evidence/human-supplementary-preflight-target-20261021.json):

- **21ottobre08:11:16.774650→08:11:16.797031Europe/Rome**,elapsed0.022378984s; timestamp inizio/fine realmente restituiti.
- `SUPPLEMENTARY_HUMAN_REVIEW_READY_NO_AUTHORITY`,complete true,readOnly true.
- HUMANstorico282,ledger amministrativi283/284,attempts284/max288,remaining4.
- runtimePreparationRetained true,zeroOAuth,newHumanWindowOpened false,runtimeAuthorityIssued false.
- reviewHash`981d810332ad855e7b9305d15fc4bbb10796bc50d556241060d7044c43d715dc`.
- Launcher `/home/oufadmin/ouf-human-supplementary-launcher.1gLteQgM`; log `/home/oufadmin/ouf-human-supplementary.KJqJCAKS/operator.log`.

Prima di questo trasferimento: checkpoint cronologico08:13:02.227Europe/Rome,effort tecnico misurato8.020976h(8h01). La timeline registra anche l’effort documentale del trasferimento; gli intervalli non segmentati e l’effort umano ignoto restano separati. Non convertire l’attesa notturna in giornate di lavoro e non dividere di nuovo la stima per10/20: la baseline era già assistita da agent.

Baseline centrale immutata: G0H+0.5,G1H+3,G2H+14,G3H+19,F5H+22,G4/F6/M1H+24,G5H+35,G6H+46,G7/M2H+55. Range M1 18–30h;M2complessivo40–70h,HUMAN3–6h separati. G0–G2PASS;G3–G7,F5/F6,M1/M2aperti. G2superato a3.160557h misurate,con WP5 intercalato; nessuna allocazione WP2pura o previsione residua per sottrazione.

## 5. Catena IAM e azioni concluse: nessun replay

| Passo | Risultato ed evidenza | Stato |
|---|---|---|
| Vecchio HUMAN278/288 | Finestra scaduta20ottobre00:57:44italiane; selezione/custodia riconciliate | Storico,non autorità |
| Nuovo HUMAN282/288 | Device flow verificato; token effettivo300s,poi scaduto; finestra scaduta20ottobre22:40:41italiane | READYstorico,immutabile; no bearer/refresh reuse |
| Timing | 300s incompatibili con margine produzione930s | Lettura conclusa,non ripetere |
| IAM read originale | STOP`EXACT_RECORDED_ADMIN_SESSION_CONTEXT_REQUIRED`;Engine7/7 | Non riaprire |
| Riconciliazione IAM | Usernameclaim mancante,expiry interi,token admin60s scaduto; metadata riconciliati senza login | Conclusa,non ripetere |
| AdminAPI283 | Identità admin verificata via API,timeout/flow correnti letti;realm300,device abilitato,grant password/standard/service disabilitati sul client HUMAN | [ricevuta](../../evidence/iam-explicit-api-target-20261021.json),conclusa |
| PolicyAPI284 | Un solo override`access.token.lifespan=1200` sul client`ouf-human-admin`,UUID`d51384e5-bedd-4fac-96e9-4ad13dd0b7c9`,realm`ouf`;readback completo invariato altrove | [ricevuta](../../evidence/iam-client-lifetime-target-20261021.json),conclusa |
| Preflight successore284 | Catena e preparazione trattenuta corrispondono;zeroOAuth | Concluso,non ripetere |
| Nuova finestra | Ultimo comando proposto NON eseguito,per dichiarazione esplicita owner | **Da chiedere nella nuova chat** |

Override1200persistente: nessuna scadenza/rollback automatico. L’owner ha approvato limite normale di freshness autorizzazioni1200s; revoca urgente/propagazione non misurate. Realm,flussi,ruoli e campi estranei invariati. Nuovo token HUMAN effettivo1200s NON ancora provato. Account masteradmin non sostituisce il principal HUMAN OUF né le decisioni THS. Non abilitare password grant sul client HUMAN,non impersonare l’utente. L’owner ha chiarito che l’ostacolo è navigare la **console amministrativa** da cellulare; non esclude autenticazione nel browser fidato. Console non serve,amministrazione via API.

Contesto amministrativo originale `/etc/ouf/deploy-snapshots/iam-policy-read-7120rnka`;successore283 `/explicit-admin-api-successor`;successore284 `/explicit-admin-api-successor/lifetime-policy-successor`. Le due scritture di claim supplementari fanno fencing sui vecchi opener. I nuovi controlli leggono questa catena senza riscrivere lo storico282.

## 6. Codice,CI e consegna già qualificati

Repository `GioNob/ouf-deploy`,PR45draft,branch`feat/explicit-human-successor-20261020`,HEAD **5bb47f6654a71dffa2c98c6d105d9c830d542205**,base PR42/e56f335f07a20f5574b1f31989f52735cab0acbc. Non merged/non release.

[Case](../../releases/human-supplementary-case-20261021.json),[pins](../../evidence/human-supplementary-delivery-pins-20261021.json); codice nuovo in `tools/governed_human_successor/supplementary.py`,`supplementary_delivery.py`,`auth_delivery.py` sul commit PR45. Script `scripts/human-supplementary-20261021.py`:blob`dc6f9e6e61479e4a73abe40d4c2b1fdafe6409b7`,SHA256`c7de71e40cc15c3c15393a097379d8fda2106107bdf865b878466a57af79a275`. Launcherblob`ea5f64485f18a977372eaa072a46cf554ba13552`,SHA256del§3. Case/source closure sono pinned;non ricompilarli dopo preflight per “ripartire da zero”.

CI [39553046609](https://github.com/GioNob/ouf-deploy/actions/runs/39553046609): Python3.12job119066351853 e3.13.5job119066352132,PASS **57test ciascuno,zero skip**(13supplementary+32successor+12operator). Comprende catena reale di journal/custodia root di fixture,crash/fencing/no-replay,consensi negati,scadenze,quattro richieste sintetiche284→288,reader privato e sealed loader55moduli effettivamente isolato. Nove altre workflow sullo stesso commit PASS:39553046512,39553046519,39553046525,39553046528,39553046536,39553046556,39553046572,39553046589 e39553046600.115blob frozen(native114+loader) conservati rispetto24c2d9b8c7b3f4f8a4a61125b86877ffbd635dba;guard930s immutato. CI non equivale aVPS;preflightVPS non equivale a login/rollout/E2E.

La policy lifetime era qualificata separatamente al commit1852942f47af54ec015764841ebbcddb09ab3e05,run39545126657,12test perPythonzero skip,Keycloak26.2.5reale usa-e-getta e token fixture1200s. Durante quella qualifica è stato corretto l’effetto collaterale reale`frontchannelLogout` della PUT parziale: ora conserva il Boolean osservato e confronta ogni campo,normalizzando soltanto ordine di insiemi documentati. Non indebolire il readback. Le precedenti CI fallite e la correzione dell’albero Git incompleto sono documentate nel dossier e nei pins,non sono state eseguite sulla VPS.

## 7. Passi dopo la finestra,senza sprecare il nuovo token

Solo dopo ricevuta di apertura valida: il controllo derivato espone percorso esatto;ogni `step` è un comando manuale distinto con consenso tty,al massimo una richiesta provider. Sequenza nominale:DISCOVERY285,DEVICE_START286,completamento browser da cellulare e UNA token poll287,USERINFO288. Nessun polling/refresh automatico. Rispetta l’intervallo provider: un comando prematuro restituisce WAIT senza richiesta. Un pending/fallimento consuma la prenotazione; non esiste riserva per un quinto tentativo. Dopo esito ambiguo fermarsi e riconciliare,non ripetere l’autenticazione. Nessun nuovo budget concesso qui.

Al READY il profilo HUMAN privato viene scritto nel nuovo control,non pubblicato come client profile. Reader nativo compatibile anche a288;restano vietati refresh/scritture dal reader. Richiedere token effettivo con **oltre930s residui** prima di review/approve produzione. Preparare tutti i comandi/stadi prima di richiedere il token: non sviluppare un nuovo applicatore mentre il token fresco scade.

Controllo produzione già sulla VPS:launcher `/home/oufadmin/ouf-rollout-bootstrap-launcher.84fOiF2L`;contesto `/etc/ouf/deploy-snapshots/ingestion-rollout-native-7fs9r6md`. **Non eseguire prepare di nuovo.** La modalità`review CONTEXT HUMAN_READ_PROFILE` compila la proposta;`approve CONTEXT` richiede consenso infrastrutturale corrente;`initialize CONTEXT`,`step CONTEXT` e`reconcile CONTEXT` sono invocazioni separate. Consultare `tools/ingestion_rollout_preparation/production_control.py` e launcher pinned sul commit PR45 prima di consegnarle. Runtime900s,margine930s invariati;review/approval non sono decisioni semantiche/attivazione fonte.

Il rollout proposto richiede due sostituzioni(Ingestion/Gateway),una chiave dedicata nuova,sola immagine già qualificata,massimo2PUTGateway,80altre route conservate,VALIDATE_ONLY/zero migrazioni. I gate HUMAN/Owner/DB/Gateway,generazioni e ruoli firmati restano obbligatori prima degli effetti. Nessuno di questi effetti è stato eseguito. DopoSTOP conservare contesto/claim:riconciliare senza replay,nessuna firma/rinnovo per aggirare scadenza.

## 8. Stato CSV,WP e residui reali

M1:casoTeatri conservato,profilo nativo pubblicato,F5/F6,seconda acquisizione deliberata dello stessoCSV,identità/proprietà/ACK/provenienza di entrambe,8Cinema preservati. M2:M1+CSVnuovo,tipi/vocabolari/relazioni dove richiesti,matchesistenti/nuovi/ambigui,fault/ripresa,due client reali. Chat prepara e accompagna;decisioni HUMAN inTHS;Onboarding mapping/bundle,Semantic semantica,Ingestion esecuzione pinned,UDP identità/materializzazione,Gateway media,MCP tool/recupero. ACK trasporto non prova commit canonicoUDP. Seconda acquisizione identica non deve creare revisione canonica gratuita. Ricerca prossimità/affinità,altri formati,verticaliAPI,streamingGIS e installer universale multi-host sono successivi/fuori da questo mini-perimetro.

| WP/gate | Stato e prossima prova |
|---|---|
| WP0–WP2/G0–G2 | PASS nel perimetro registrato;executor nativo qualificato;non reinstallare per “ricominciare” |
| WP3/G3 | In corso;HUMAN corrente manca;ammissioneDB effettiva,policy startup,rollout Ingestion/Gateway e profilo governato non provati |
| WP4/F5–F6/G4/M1 | Aperti:percorso caso conservato e seconda acquisizione/readbackUDP |
| WP5/G5 | Delta tipi già implementati/qualificati,prova compostaJVM/PG2acquisizioni→1oggetto/1revisione/2osservazioni;vocabolari/relazioni ancora aperti;non confondere con deployVPS |
| WP6/G6 | Composizione owner reali e due client ancora aperta |
| WP7/G7/M2 | Acceptance completa,failures/riprese/prove PET rappresentative ancora aperte |

Candidati nominati nei registri(non sono automaticamente installati né HEAD correnti da assumere):

| Repository | PR/commit | Scope |
|---|---|---|
| ouf-ingestion-runtime | PR45,bcc13544afdea6f5d331292f93eef86726587e2b | TipiCSV generali |
| ouf-source-onboarding | PR48,17a68aea8dccb603405ec4761cb9f52666692a32 | TipiCSV generali |
| ouf-udp-object-resolution | PR47,df1f4c38d31da8a8ac63d5a5cb2532f633778979 | Tipi/riconciliazione |
| ouf-source-onboarding | PR49,7b04d36fd8462616514cca956fd973c9bd01c1e7 | Recovery owner/schema tipizzato |
| ouf-mcp-server | PR77,0a76376a7c6a0f07597c1c3aaf447b29deed597f | RecoverySDK/proposta tipizzata |
| ouf-api-gateway | PR82,c22fbf7f5593f612aba7e318797c9459d0b871a7 | Dispatch recovery/schema |

Le sourceHeads selezionate per la coorte trattenuta restano nella timeline;il candidatoIngestion operativo fissato è0fe0de60c6d980fe97610acf195d4bfd46d3777f,imageIDsha256:5dfdf2239fa9eb3ae2ff8510521322cf91718bc787eee179db8e65c515a30e8b. Non sostituirlo con un candidatoWP5senza nuova proposta governata.

## 9. Contesti e binding da conservare

- Owner7completo: `/etc/ouf/deploy-snapshots/ingestion-owner-recovery-execution-d6o9cpwd/execution-plan.json`,hash`e5f69f89aa40b8c9b963134d38a6aecaf864499346f9e366539c1eb1aefa0938`;result`update-result.json`,hash`7d3902327a9b3641129f4416b66324c4cf727d0e54708216f9df098388a15618`. Nessun replay.
- Projection7attiva: `/opt/ouf/installation/active-projection.json`,SHA256`dd31d2b7de5ae66582275e5ac841584ff784065aa6e362ed0279d45fb6cdbc66`,mai ripubblicata da questi controlli.
- Packetoriginale`ingestion-rollout-packet-kkj_njiz`,staged`ingestion-rollout-packet-reconcile-0wd4wyuf`,riconciliato`ingestion-frame-mac-reconcile-qfcpqd9f`,tutti sotto`/etc/ouf/deploy-snapshots`,root0700. Packet-planhash`ad1bdb240483f85785b989f28cd895a72394ea964baabd85ad3062b10180fe5c`,verifiedInputs`c556d7ea44bc7f7e1f337358e166e2cde11c90e6459a76cc703c178218bd9907`.
- DBreadpreflightconcluso:Postgres17UTF8,18migrazioni/33tabelle,privilegi richiesti presenti,nessun lavoro pendente nello snapshot,headroom61;**non**ammissione corrente né startup effettivo. Non ripetere la lettura conclusa.
- Capture`ingestion-native-inputs-qs8zybi4`,profiles`ingestion-native-profiles-5xl2drfi`,productionbootstrap`ingestion-rollout-native-7fs9r6md`,conclusi. Productionoperator-controlPRIVATE_READY;recoveryruntime assente all’ultimo preflight. No serviceReachabilityproven,chiave dedicata ancora da creare,clientprofile non pubblicato.
- Vecchio controlHUMAN `/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem/human-successor-control-ba456a2fd7a540473de5fdb084d0195ac857997b1aa5ab7d4571f07a9bcadd07`;profilo/journal282immutabili. Non usare vecchiohumanoperator per un’altra finestra.

Ogni valore specifico di Ente deve essere input parametrico,validato/versionato:domini/endpoint/issuer/trust,route,placement/reti/interfacce,MAC/IP,filesystem/secretreferences. MACDockerendpoint non è MACfisicohost. I binding storici qui sono esclusivamente diagnostici dell’installazione corrente,non default portabili. Nessuna costante di questo handoff autorizza a installare altrove senza profilo.

## 10. Limiti e comportamento della nuova sessione

Ultimo catalogo ouf-admin:26definizioni tool,nessun executorroot/IAM/VPS qualificato;metadata disponibili non provano autenticazione. Canale target attuale:comando manuale esatto dell’owner nel terminale VPS con sudo. Niente tentativiSSH,sessioni browser/login automatici o credenziali inchat/argv/env/log. `gh`VPS non inPATH:eseguibile noto`$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh`,poieventualecommand-v;fallire prima di sudo se manca,senza loginGitHub/tokenstampati.

Nuova chat:non dipendere dal filesystem di questa sessione o dalla memoria di altri thread. Leggere GitHub+allegati,riconciliare i riferimenti documentali senza replaytarget,tenere cronologiaappend-only. Non fare benchmark generici prima di chiedere il comando già pronto. Nessun altro passo operativo finché l’owner non ha eseguito quello del§3 e restituito il risultato. Dopo di esso proseguire la traccia Mini-PET e fermarsi solo per il prossimo intervento HUMAN realmente necessario.

Checkpoint finale documentale: 2026-10-21T06:23:42.108Z UTC; effort tecnico/documentale misurato cumulativo 8.130166h(circa488minuti),baseline invariata;G3aperto. Nessun nuovo secondo di runtime target aggiunto. [Checkpoint strutturato](../../evidence/csv-e2e-chat-restart-checkpoint-20261021.json).

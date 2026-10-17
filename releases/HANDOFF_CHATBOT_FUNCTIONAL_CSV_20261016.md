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

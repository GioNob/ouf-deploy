# CSV/chatbot — handoff corrente, 15 ottobre 2026

## Readback completo: primo grant provato, Registry CREATED, cinque servizi fermi

Ricevuto allegato8:103 record, END complete=true/unavailableChecks vuoto,24 GET, zero mutazioni. Allegato SHA256 f4e71357305f6827eac16a931b1ea23dbc85e3a5f135af4fc0b42cf09eed600b. Evidenza integrale in `evidence/chatbot-registry-creation-readback-20261015.json`. Non chiedere di ripetere il reader.

RegistryTransition bfabae1561e4f906f23afe0c2e71d8f240774a38b9ac8b08c9ed43e4b5e1ecfb/v9/IN_FLIGHT/nextPhase4 CREATE_REPLACEMENT. STOP_REVOKE_OLD_LEASE, QUIESCE_PRODUCERS, FENCED_BACKUP, RELEASE_OLD_ENDPOINT APPLIED e tutti i4payload hash verificati. DB/applicationMayHaveChanged=false. Nuovo Registry **790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d**, created/PID0/nonrunning/unpaused/stabile. Nome/immagine/config corrispondono; solo HostConfig.Mounts differisce: expected list, actual NoneType. Il preparatore sourcebc2 imposta SEMPRE Mounts=[] e trasferisce i quattro mount effettivi in Binds. Moby HostConfig.Mounts è omitempty. Questo è un errore del comparatore: [] vs campo omesso/null. Non accettare mount nonvuoti mancanti o cambiamenti dei Binds/readonly. I mount reali/OCI restano controllati nelle fasi successive.

Primo grant4bb904ea93df0766647641fd397cac7d8504f1ca81252ce597d1db363a86105a TOKEN_PUBLISHED_NOT_RUNTIME_ACCEPTED, copia worker identica. Continuazione completed855fa3ba86b742351da2ab14ba0c1c8958cb96005aad02257bf0aceb44a4b395 OWNER_READY_FOR_FINITE_WORKER_NOT_APPLICATION_ACCEPTED. Nuova sessione392c28e56c80869b67b1333c384a952726c60f6d734089cd587230dcb50fddcc/v1/slot1, created1792064164/expires1792064464. Credenziale riusata receipt319e06f17e99c3d8ba180b2792ca94e16dc70001770409395fea9df33c48f66d. Worker af84e55b73651d742b652df71893e2db83d2f55e68fbc8bdca25f0383421069b CANCELLED, attempts0/cumulative1; admission c1b47e5a2db2652fddfd8b905c5e80abf1b0327a01c0c6748833fd4bf0d52107 BLOCKED/v2. Sessione worker6f27f3d34eefa3c4b10685d705b5edf97c2164d4ce994b63b8bbc853645717d1 conservata. Processo b051... spento/not-found/PID0. Non riusare ACTIVE né slot iniziale.

OldRegistry7ae83... e UDP6552..., Onboarding9a72..., Ingestion1fa5..., MCPddbfc... tutti exited/PID0. Scostamenti da pin pre-stop su host/network/pid riflettono fasi quiescenza; non chiamarli drift non autorizzato senza confrontare evidence APPLIED. Postgres50b36d... attivo/PID10948/generazione esatta. Journal containers v2/next0/effects0; DBv1; Gatewayv1/next0/effects0. Stage corrente manifest90444cb2256ba789ed2ab33e063652966f3fd4de58ad74fa1bf95dc49817de0f/intent71dc87128d802d6b075d2921ec53aa0177a599f33033d17e303c0198df0e1544,10file esatti. Nessuna migrazione successiva raggiunta; backup Registry già eseguito, nessun rollback.

## Richiesta attiva: verificare TUTTE le fasi Docker residue prima di nuovo tentativo

L'owner ha chiesto esplicitamente anche l'audit delle chiamate Docker successive e la predisposizione adeguata. In corso audit di create/start/pause/unpause/SIGUSR1, OCI/runc, bind/readonly, reti/IP/MAC/alias, update restart policy, rename, API exec PostgreSQL/backup/migrazioni, readiness e release. Non consegnare un altro wrapper dopo la sola correzione Mounts.

Sorgente candidata in sviluppo **61fe3cabb1f3eead65ed8f06a03b1b66fe6ed0bd**, PR31 draft/unmerged; nessuna nuova esecuzione target. Engine.requested_host_config_matches accetta SOLO requested Mounts=[] vs omesso/null, conserva Binds e nonempty esatti; helper condiviso con cohort/Gateway e fase started. Diagnostica CreationDenied con codici fissi e frame interni. Capsula0800225b1c7ed310bea2bc241844bcd6bdd09deb7c59ef8c46366a8d254390c6/112file, launcher62799b6826e10d000ae0e33853d9ccaf44717c37dea91a7d9087bc1327c96445. Non è un pacchetto di recovery qualificato.

Nuovo job installa Docker ufficiale29.8.1 in data root isolato, containerd-snapshotter overlayfs e cgroup systemd (verificati su primo job), CLI29 e test del gate con immagine fixture/static ELF,4bind, network, health, update/stop/rename, quindi native PostgreSQL/MCP via exec/dump. Cinque test puri e3closure locali PASS. Primo job9e0e9 fallito solo nella compilazione del fixture C con Werror; corretto qui e compilazione locale PASS nel seguito61fe3. Il test usa una JVM simulata per contratti Docker, non prova il vero servizio, IAM o OCI completo.

Audit ha trovato un ulteriore problema da risolvere: i vecchi test nativi di release usano un loop esterno e.reconcile quando exec cambia argv; l'aggregate chiama executor una sola volta. GatedRelease può rispondere UNKNOWN immediatamente dopo SIGUSR1, e ApplicationVerification può rispondere UNKNOWN mentre Spring avvia HTTP. Evitare un altro arresto per transitorio noto con riconciliazione READ-ONLY e budget persistente/versionato; mai ritrasmettere start/signal. Integrità, revoca, generazione diversa e unknown restano deny. Leggere `tests/test_gated_release_adapter.py`, `tests/native_gated_release_executor.py`, `application_verification_adapter.py` e policy v3. Nuovo recupero post-grant/quiescenza NON ancora implementato: non riusare il contratto pregrant o un mandato scaduto, non ricreare container790c né ripetere i4effetti APPLIED.

## Binding/storia precedenti (superseduti per la prossima azione)

## Difetto IAM confermato dal confronto pubblico sul VPS

L'operatore ha fornito l'output completo del reader ecd9849a4fd89657c267d2e1b0af7406c37fe19e84a385ad52bb63cb41f2c148:6record. Vecchio adapter: HTTP200/HTTP1.1/Connection:close, socket chiuso prima del body, OSError errno9 EBADF. Adapter con file nativo: identica classe di risposta, bodyReadPass/discoveryIdentityPass=true, socket valido fino alla chiusura del body e rilasciato dopo cleanup. Esattamente2 GET pubbliche, zero grant/admin/credenziali lette/scritture, record conservati. Evidenza `evidence/chatbot-iam-http-close-target-confirmed-20261015.json`.

Il difetto del client è quindi riprodotto sul target nella stessa fase; il vecchio journal del processo conserva solo OSError, non un traceback retroattivo. Non attribuirlo a disco/RAM. Il fix conserva il riferimento SSLSocket.makefile fino a chiusura della risposta e chiude anche le risposte rifiutate; restano deadline, limiti body, CA/hostname/IP e divieto redirect. Diagnostica nuova: solo fase consentita, errno e posizioni di sorgente verificato; nessun messaggio, argomento o valore privato.

## Contratto della continuazione post-credenziale

Solo la storia fissa4a65b9/authority2c351... osservata è ammessa. Conserva intent, vecchi receipt, contatori, sessione scaduta0 e i due stage95749/4a65; verifica tutte le loro hash. Riuso della credenziale completata: metadati/inode fissi, poi confronto dei byte col newSecretHash solo sotto autorità runtime corrente. Zero nuova rotazione IAM. Cinque immagini e generazione APISIX riusate con verifica nativa; nessun load/mask-stop/mkdir già consumato viene ripetuto.

Nuova decisione HUMAN esplicita per una sessione distinta <=300s: actor issuer/tenant/subject uguale alla selezione corrente, motivo del difetto, decisionRef e predecessore persistiti. Stessa logical operation, vecchia sessione mai riscritta, massimo cumulativo1 primo grant. Record e lock della prima claim rimangono quelli originali. Budget worker distinto <=128/3600s. Nessun rinnovo automatico, reset, replay di effetti ambigui o storia legacy ricostruita.

Qualificati in CI: successo fino al worker ACTIVE con TLS Connection:close, zero admin/mask-stop aggiuntivi, bytes/record precedenti intatti, revoca prima degli effetti e dopo il nuovo receipt, drift credenziale/counter, concorrenza, actor mancante/cambiato, grant fallito senza replay, storia vecchia e nuova, immagini/APISIX modificati. Il primo candidato aveva un embedded component vecchio e un test col boot storico simulato; corretti qui prima della consegna. Nessuna guardia produzione indebolita per passare i test. I test locali che richiedevano gid10001 erano saltati per capacità del sandbox; tutti gli8 ora sono eseguiti e PASS nel runner root.

## Stato VPS osservato da preservare

Readback OSError:54record, END complete=true/unavailableChecks vuoto, in `evidence/chatbot-pregrant-oserror-readback-20261015.json`; allegato SHA25668ae2671e29b07ae1e2f3e56836e86f63e8bc0f6f88ccfe4297c747392c15557. Processo4a65b9 spento/not-found/PID0; PAUSED_REQUIRES_RECONCILIATION/OSError. Credenziale completata/version1, hash a9fa6304781bff2c9a795d16520881401a49124db869de87338f8978251436ae, root:root0400/device65028/inode4161549/86byte/nlink1. Vecchia sessione0/version0 hash2879325cd95434413f29dc4058d945e16d0bbc71eaf29d44176c705b5ca6ce0c, created1792058313/expires1792058613. Nessun primo grant/worker, output vuoto.

Continuazione intent6bdf577601a0b4275b52c2758e7bb5493024682cdea12f1f46a62e8ee75d6dc7, completed assente. Output receiptc5d6d3bc78d65c18127058b8e236246f5cfde87d93ddc5aac5d7f8f6471880a7; retirement3b054f15c49ff43e9de9a6fb5aa642dad8ad23757130af2a9cdd236cb83538d5 QUIESCENCE_OBSERVED. Stage intenta654074cc01bf4c702041591907614e1ca22a6ee34ff37b6b0e4abadf084dc53 e manifest0ff3cf4f630709a74c089b4aa75359aa27d62176a9c0975d8f9db90a831b99bf:10file verificati/zero parziali. Authorization journal80db4295967f18a733adff0c3b5273d1af9af0789bcddbe7b76ac4849907b465/version1. Containers/databases/gateway/gatewayRuntime non iniziati nel context4a; APISIX già completato nel95749.

Filesystem corrente:352277303296byte e32668398inode disponibili, mount scrivibile; /tmp8369836032byte. Footprint capsule108397015040byte/20intake+4signed. Nessuna pulizia effettuata o autorizzata. Applicazioni e ZIP congelati; nessuna nuova mutazione target eseguita dall'agent.

## Limite e obiettivo ancora aperto

**CSV/chatbot end-to-end non dimostrato.** Dopo COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE continuare immediatamente via MCP nella stessa finestra; l'installazione non è l'accettazione. Servono semantica pubblicata con HUMAN, onboarding approvato, COMMIT ingestion distinto dall'ACK, lineage UDP e nuova ricerca chatbot; seconda sorgente stesso contenuto con riuso/NOOP provato. Dettagli/pin in fondo. Non promettere una distanza o un numero di blocchi residui senza prove.

## Binding e storia conservati

Il reader è fissato a:
- source **4a65b9326c15d9758ecba1793965617a2a92e43e**;
- context `/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-eff1b6915816bcfc409b16e1d24b9eb342b1c38e3d6ae80e362ac893c5480d0b`;
- unit `ouf-file-cohort-eff1b6915816bcfc409b16e1d24b9eb3.service`;
- authority **2c35198422227b7db0894ca37ee4d70947ae56fcce813f8d0d1ab9a81c9b5733**;
- plan **0a74c41f04068e11e6fefbb24430fa14a7fcdeaa0c087c76795039141fc6f5df**;
- scadenza1792061873.

Rilegge review/authority/bundle esatti, unità, ricevute originarie e della continuazione, staging corrente ed eventuale parziale, transazione credenziale/sessione/primo grant/worker, metadati delle directory e journal delle fasi successive. Legge il journal di systemd ma stampa solo eventuali errno e posizioni del traceback appartenenti ai sorgenti verificati; non stampa messaggi, codice o argomenti. Rileva spazio/inode/mount e footprint aggregato delle capsule; queste letture correnti non sono da sole prova della causa storica. Non legge file client-secret/token, non esegue sorgenti conservati, non crea lock/journal, non interroga IAM né rinnova autorità. Conserva errori di singoli controlli e prosegue.

Evidenza dell'output operatore: `evidence/chatbot-pregrant-continuation-oserror-20261015.json`. Il readback completo e il confronto pubblico sono stati ricevuti e archiviati; vedere le evidenze correnti. **CSV/chatbot end-to-end resta non dimostrato.** Sorgenti applicativi e pacchetto restano congelati; nessuna modifica target è stata eseguita dall'agent in questa diagnosi.

## Qualificazione e storia precedenti

La revisione4a65b9 aveva superato tutti i9 workflow: consegna262 test/34 suite/zero skip, online IAM234 test/31 suite/zero skip, installazione completa, retirement e HUMAN. Il wrapper resta evidenza della consegna, non un comando da rilanciare dopo il nuovo arresto. PR31 draft/unmerged, source branch `codex/retained-inspection-channel-20261015`, base PR29 `codex/chatbot-mcp-migration-role-20261014` a fdc990136592f0353c2824f4de632a052910a2a0.

## Stato precedente95749 verificato prima della continuazione

- Tutte e cinque le immagini hanno journal VERIFIED e prove native di identità, configurazione e RootFS corrispondenti. Semantic è stato riutilizzato senza load (0 nuovi tentativi); UDP/onboarding/ingestion/MCP hanno ciascuno 1 load consumato.
- APISIX ha tutti gli otto passaggi APPLIED e versione journal19. La generazione attuale è running, non paused e coincide esattamente con il binding finale del journal. Il container precedente è conservato.
- Dieci file del token owner sono stati predisposti: manifest e hash dei file corrispondono alla revisione. La directory token-output esiste, è vuota, root:10001/0750; il root delle credenziali è vuoto, root:root/0700. Il root recovery contiene il solo token-output.
- Prenotazione installazione presente; completamento assente. Prenotazione comando ritiro presente/version0/consumata; nessun replay autorizzato.
- Transazione credenziale, first-gap-session, first-grant e quattro record del worker assenti. Journal applicativi containers/databases/gateway assenti. Nessuna migrazione o sostituzione dei cinque container applicativi è stata raggiunta da questa esecuzione.

Il timer `ouf-policy-token@semantic.timer` è LoadState=masked, UnitFileState=masked, ActiveState=failed, SubState=failed, Result=resources, Job vuoto. Il servizio `ouf-policy-token@semantic.service` è masked/inactive/dead/MainPID0/Job vuoto. Il predicato precedente pretendeva inactive anche per il timer e ha respinto questa condizione terminale. Result=resources **non dimostra** esaurimento RAM/disco; la causa storica specifica del timer resta ignota.

## Binding dell'ultima esecuzione

- Context: `/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-3f1e74ca1de7962018be8e1d6dd023f685ea208a70aa5e2e2078f92961d7fd4c`.
- Unit: `ouf-file-cohort-3f1e74ca1de7962018be8e1d6dd023f6.service`.
- Review: **6ff5430760e93ab51a26313a18198f094ded12760954fb8a4fcf53db5b3274a0**.
- Authority: **83d70a33518b7bf7c1ca2904d715623294bb8132d5db1373381ab7ea001f2072**.
- Plan: **c2fad152330f9bfa82615fc910e1a213770736e9d4d0408ed0dfdf61dd8242e8**.
- Scadenza finestra: 1792056838, 2026-10-15T09:33:58Z /11:33:58 CEST. Il controllo predecessori richiede scadenza naturale e processo fermo; non rinnova né revoca automaticamente la vecchia autorità.
- Unit osservata not-found/inactive/dead/MainPID0: transient unit raccolta. Result=success non significa riuscita della consegna.

Hash dei record immutabili:
installation ff7de4da5b1503e109891b7f00aaf2a7df2709e2aac89e0e6e61a8c4e442fca2;
retirement 38c670782408fd6843350f549eaeffe1b59adae7b923b907d4ccdad373424b7c;
output 0d176ef0fa749df76cbd636a944e1b420b33201b65741c652c9ad5c376fa01ce;
source intent 47f8ecd2d5cd70564cd9062fe093634f93083691e79a94abcb6697659a4428d7;
source intake e6f5140a6c63048b8ccd5f6c5d0b758ced5da9ef6d7c05f16180bf8f309cea94;
gateway runtime d9a7427d73867801fda31acbba4b1df3d7dafd4e99d35cd1cdbb2b5d7816448a.

## Correzione candidata e verifiche

Candidato4a65b9: stesso contratto di quiescenza nei due percorsi (retirement e worker standalone): entrambi permanentemente masked, nessun Job, servizio inactive/dead/PID0; al timer è consentito inactive/dead oppure failed/failed. Nessun reset-failed. Il worker resta indipendente dai moduli installer.

Il recupero è integrato nel modulo legacy già presente nei runtime chiusi. Richiede esattamente il predecessore95749a8, review/authority e record sopra, custodia/inode, dieci file precedenti intatti, assenza di rotazione/grant/worker/applicazioni e prova nativa di immagini/APISIX. La nuova revisione include tutto il proof nella scope owner corrente. Output e ritiro vengono osservati con nuove ricevute separate (massimo0 mkdir/mask/stop), conservando contatori/timestamp originali. Una sola prenotazione di continuazione stabile, autorità HUMAN e firme correnti; nessun riuso della start claim. Il nuovo codice owner viene predisposto come generazione distinta, conservando la precedente.

Le verifiche precedenti nel candidato71264d8 hanno passato i13 nuovi casi, inclusi sei con custodia root:10001, vere firme Ed25519 e TLS/grant/pubblicazione, oltre alla regressione owner. Hanno però individuato un'importazione incompatibile nel worker standalone e un errore nella fixture systemd: rifiutare inizialmente un timer con target già masked non produce lo stato failed. Il candidato22e856 ha riorganizzato il recupero senza ampliare i runtime e corretto la fixture del timer; conservava però l'ulteriore import incompatibile individuato e corretto in4a65b9. Questi risultati restano storici: la qualificazione corrente4a65b9 è documentata sotto.

Il candidato22e856 è stato fermato dalla CI: quattro workflow hanno fallito allo stesso import di producer dal modulo legacy, prima dei test di recupero. Nessuna esecuzione VPS. Il candidato4a65b9 elimina questa dipendenza dalla componente standalone, mantiene la lettura privata con FD/ancestry/no-follow e aggiunge una regressione che vieta il package worker durante l'import isolato.

Verifiche locali4a65b9: retirement9PASS, import runtime completo3PASS, recupero7PASS e6 skip per group10001 non disponibile nel sandbox. Le tre closure migration/installer/worker standalone compilano con32/39/24 moduli, senza ampliare allowlist o set dei moduli. I sei casi nativi restano obbligatori in CI. CI hosted4a65b9 completata: tutti i9 workflow push/PR PASS. PR consegna38715383127:262 test/34 suite/zero skip, incl13 casi recupero e timer systemd reale. PR online IAM38715383165:234 test/31 suite/zero skip, incluso Keycloak reale disposable. Installazione completa38715383033, retirement38715383112 e HUMAN verifier38715383372 PASS. Push corrispondenti38715377019/38715377065/38715377030/38715377158 PASS. Vedi evidence/chatbot-pregrant-recovery-qualification-20261015.json.

Capsula qualificata: **f9715d9728e78554305df567415bd949f8c3a89d00010204f6c549a1932a3728**,112 file.
Launcher qualificato: **4b6f30144055af38978f04d6eef16ddab134a890b0dcee460261ec28de5ca3dd**.
Wrapper qualificato e pubblicato: releases/chatbot-file-cohort-pregrant-recovery-execute-vps-20261015.sh, SHA2564e85a8e48f134a8c6d53ecaafd8b25942ff8cad9a38731a4dcd52be12caf6bf9. Verifica sintassi Bash PASS. Il wrapper è stato consegnato ed eseguito al commit4a65b9326c15d9758ecba1793965617a2a92e43e; dopo l'arresto OSError non va rilanciato. Il programma mostrerà una NUOVA review: approvare soltanto l'hash corrente, mai6ff o altri precedenti. Include gli effetti applicativi ancora da eseguire: cinque container, backup/migrazioni e primo grant/worker finito. APISIX e immagini completati vengono verificati e riutilizzati. Non rilanciare automaticamente dopo un nuovo PAUSED/BLOCKED: leggere stato e record prima di qualsiasi ulteriore azione. Dopo COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE proseguire subito con la prova MCP nella stessa finestra.

## Pacchetto applicativo congelato

Producer8bff54a52a0ce15daccaf2aee932004f106dd178; run38584614991 attempt2; artifact11907557440.
ZIP SHA256 **144699ab7756c8312d49783967cfbb64acc02a617015ad89f5adf51e25a10300**.
Esiste già in `$HOME/ouf-chatbot-file-delivery-126e49f3830667934bf8f8d7/cohort/cohort.zip`: riutilizzarlo verificandolo, nessun rebuild delle applicazioni.
Client gh: `$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh`, fallback command -v gh; preservare auth e non stampare token.

Pin moduli: semantic eccef11a97367f20e278db40b9ed6f45dd980c37; UDP b49c0d6f50c574c11684361ce4e8040e9cbddee2; onboarding **GioNob/ouf-source-onboarding** 84828f74ac586bae09a78f0fb197b75b1a3d98d1; ingestion c48ee4b1873a474e81c6e1be70d393854021e2c1; MCP f249b3dcc58c2a96742092d90fa09fd90b705bd0; Gateway bf179e96200deb84942ad32507edef52a4284cd0.
MCP conserva migrazioni1–9 e aggiunge10–12. Non merge globale del target overlay.

Il difetto precedente immagini era config digest vs native manifest digest in Docker/containerd. Corretto e provato nel VPS: semantic configuration29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489, nativeb61bc39c1593c28404a8258962008c024d13689d7e9b132e6a85619580003ca3. Manifest/config/layer/RootFS e campi di esecuzione rimangono stretti; nessuna adozione sulla sola label. Payload applicativi invariati; nuovo envelope derivato conserva provenance e non pretende una nuova firma publisher. `image_import.validate_record` è la stessa validazione owner estratta per readback puro senza lock/scritture.

Precedente qualifica95749a8: run38704843732 e38704849033 (234 test/30 suite/zero skip), matrix38704843739 con tutte le5 immagini originali su classic/containerd, frame completo e owner firmato. CI Docker28.0.4; VPS29.8.1: non dichiarare equivalenza di versione. Referenze complete nella versione storica di questo documento al commit077c12021546c2c9d5b62b283d46ce3d6c3ec075.

## Storia e regole di recupero

Primo contesto auth-only b96d2afabbd3275beadb0bbb525608278d5f098af1e14de1f5e4333bff9b488d, source6959b1dbaeb30ca3a838c7d6243a55e9cfc5118a, finestra scaduta e processo fermo. I ruoli sono stati poi confermati: rileggere stato attuale senza ricreare una proposta invariata. Il vecchio link adf95413-92b0-460b-a112-2fd80bd208ac è scaduto e non va riaperto.

Secondo contesto dd03d434361deb62e1caeaf7958a71c39c095f065e776312779d59dd6a7f4a77, sourceb64645982655f58a2907bf1425dd86fd6ab0ed9f, authority48c75739575b7d618484ed78184834d2d1961da97fa2870d80d14ce26fe978f4. Semantic caricato, vecchio check config-ID fallito; gli altri4 mai tentati. Record IN_FLIGHT1 conservato e riconciliato tramite native manifest nel terzo tentativo.

Tutti e quattro i contesti vanno mantenuti. Nuova authority finita non azzera incidenti o tentativi, non riavvia claim, non estende TTL zero, non equivale ad accettazione. Nessun rollback DB automatico. Una sola invocazione systemd finita (Restart=no, massimo1h), primo grant<=300s e worker distinto<=128 tentativi/3600s. La storia legacy resta UNKNOWN. Seguire AGENTS.md e docs/OUF_RESILIENCE_POLICY.md v3.

## Accettazione finale ancora da dimostrare via MCP

Dopo `COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE` mantenere viva la stessa invocazione e continuare qui via MCP. L'MCP governa il CSV, non Docker/systemd/DB admin.
Account corretto **ouf-admin**, link_id **link_6aafef96b4148191b767e9af7b756a07**, owner profile b93d8cf6-cd14-4ee6-91d7-84cd76c4f500. Non usare giovanni-chatgpt/link6aaff0a687... . Nuovi tool potrebbero richiedere refresh del catalogo dopo l'upgrade: i ruoli pubblicati da soli non provano che il client li esponga.

Teatri: asset6609b245-86ed-4315-8ce0-73f2a8555bf3, profile7984c39c-7396-4248-ab0a-f2efc390b49c v1, 13 righe/20 colonne, UTF8/semicolon/header1, storico content SHA08b20658b2b4eadf34d25cd93eead2945096b353ae33b797cf3c41df5319c9e9.
Proposta pronta in releases/TEATRI_SEMANTIC_REUSE_REVIEW_20261014.md, teatri-reuse-semantic-proposal-20261014.json e teatri-reuse-20261014.ttl. ProposalHashbe74308e098aa3a65396f3df739dd8f2837e9f8e27b6e49deb0e49d04506cb1a; RDFSHA6e4668ea42cf1c75b822e17a8ca9cb71fb2c4d8f500eed628282fa6039a6dbaa.
Classe https://schema.org/PerformingArtsTheater, ontology https://api.ouf-lab.it/semantic/teatri#TeatriOntology. Nessuna proposta/DRAFT attualmente registrata o pubblicata è provata.

Sequenza: rilettura asset/profile/identity attuali → proposta semantica e vera approvazione HUMAN/pubblicazione → riferimenti owner realmente risolti → DRAFT onboarding e approvazione HUMAN → ACK ingestion distinto da COMMIT provato → lineage UDP e ricerca chatbot fresca → seconda sorgente governata, stesso contenuto, MATCH/NOOP e riuso. Preservare8 Cinema ACTIVE revision1 e loro IRI. 13 Teatri/21 totali soltanto se commit/unicità provati. Classificazione RESTRICTED e NATIVE_KEY nome_teatro normalization://managed-file/native-key-v1 richiedono decisioni reali. Nessun CSV sintetico o riferimento pubblicato inventato.

`ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED` non basta: leggere ownerAcceptance.phase. Richiesti **TWO_SOURCE_COMMIT_AND_REUSE_PROVEN** e ricerca chatbot fresca. L'installazione non dimostra l'end-to-end.

## Modalità di collaborazione

Utente soprattutto da smartphone, molto provato dal numero di accessi/approvazioni. Aggiornamenti chiari almeno ogni60s; nessuna promessa di arrivo imminente o conteggio ostacoli non supportato. Procedere autonomamente fino a intervento necessario. Già autorizzati analisi, test, branch/PR draft ed evidence GitHub; niente merge/force o messaggi a terzi. Nessun SSH attivo: non inventarlo né chiedere chiavi/password in chat. Le password restano nei prompt locali. Prima delle nuove richieste di login completare tutti i preflight e le qualifiche possibili.

Consenso di sviluppo in chat distinto dall'esatta approvazione runtime nel terminale: mai auto-pipe APPROVO, riusare hash vecchi o usare un vecchio mandato per codice nuovo. Se il terminale mobile sparisce, fare readback prima di decidere. Non chiedere di rilanciare come diagnosi automatica.

Questa branch evidence non è una source applicativa/deployment qualificata: eseguire solo wrapper che pinna source e hash verificati. Il VPS è un test project, ma questa circostanza non autorizza a perdere dati o storia. Inventario completo originale resta sul VPS /home/oufadmin/ouf-vps-inventory-v2.sRYFvsMe/inventory-full.json; sono archiviati soltanto i report selezionati, non dichiarare un inventario integrale salvato.

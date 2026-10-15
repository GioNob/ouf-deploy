# CSV/chatbot — handoff corrente, 15 ottobre 2026

## Stato operativo e prossima azione

L'ultima esecuzione VPS (source **95749a8ef316856e16c44c1d7aa3b6791b408993**) è **ferma prima del primo grant**: `PAUSED_REQUIRES_RECONCILIATION / RETIREMENT_QUIESCENCE_UNPROVEN`. Il reader successivo è terminato con END, senza mutazioni. L'output allegato completo è archiviato in `evidence/chatbot-pregrant-native-readback-20261015.json`.

**Nessun nuovo comando di esecuzione è ancora qualificato. Non rilanciare i wrapper precedenti, non riavviare unità finite consumate, non cancellare prenotazioni e non eseguire reset-failed.** L'agent sta qualificando la correzione candidata **22e856fe359048a6b24523d8c8ec03dc931bc286** (draft PR31, branch `codex/retained-inspection-channel-20261015`). Non è stata eseguita sul VPS. PR31 resta non merged e ha come base il branch PR29 `codex/chatbot-mcp-migration-role-20261014` a fdc990136592f0353c2824f4de632a052910a2a0.

Il passo successivo dell'agent è verificare tutti i workflow del candidato, risolvere eventuali errori CI, aggiornare questa pagina e pubblicare soltanto allora un wrapper con commit/hash esatti. L'utente non deve intervenire durante queste verifiche.

## Progresso VPS verificato

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

Candidato22e856: stesso contratto di quiescenza nei due percorsi (retirement e worker standalone): entrambi permanentemente masked, nessun Job, servizio inactive/dead/PID0; al timer è consentito inactive/dead oppure failed/failed. Nessun reset-failed. Il worker resta indipendente dai moduli installer.

Il recupero è integrato nel modulo legacy già presente nei runtime chiusi. Richiede esattamente il predecessore95749a8, review/authority e record sopra, custodia/inode, dieci file precedenti intatti, assenza di rotazione/grant/worker/applicazioni e prova nativa di immagini/APISIX. La nuova revisione include tutto il proof nella scope owner corrente. Output e ritiro vengono osservati con nuove ricevute separate (massimo0 mkdir/mask/stop), conservando contatori/timestamp originali. Una sola prenotazione di continuazione stabile, autorità HUMAN e firme correnti; nessun riuso della start claim. Il nuovo codice owner viene predisposto come generazione distinta, conservando la precedente.

Le verifiche precedenti nel candidato71264d8 hanno passato i13 nuovi casi, inclusi sei con custodia root:10001, vere firme Ed25519 e TLS/grant/pubblicazione, oltre alla regressione owner. Hanno però individuato un'importazione incompatibile nel worker standalone e un errore nella fixture systemd: rifiutare inizialmente un timer con target già masked non produce lo stato failed. Il candidato22e856 corregge la dipendenza senza ampliare i runtime e fa fallire il timer alla scadenza dopo aver mascherato il target. **La nuova revisione deve ripassare la CI; i risultati vecchi non qualificano il candidato.**

Verifiche locali del codice22e856: 7 casi metadata/immagini/APISIX, legacy8, import runtime completo3, terminale7 e launcher14 passati; i sei casi con group10001 non sono eseguibili nel sandbox locale e restano obbligatori in CI. Le tre closure migration/installer/worker standalone compilano con i32/39/24 moduli previsti, senza nuova dipendenza o allowlist stdlib.

Capsula candidata: **7c3c31c874bb2db6edc81726b89c584f53007826c8a9af08cd98c169892cd555**, 112 file.
Launcher candidato: **250bedbed6521e96c78db90cb70ffcd436a70948c33c8cfb25ac417e4999ccbe**.
Non offrire ancora un comando VPS su questa base.

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

I tre contesti vanno mantenuti. Nuova authority finita non azzera incidenti o tentativi, non riavvia claim, non estende TTL zero, non equivale ad accettazione. Nessun rollback DB automatico. Una sola invocazione systemd finita (Restart=no, massimo1h), primo grant<=300s e worker distinto<=128 tentativi/3600s. La storia legacy resta UNKNOWN. Seguire AGENTS.md e docs/OUF_RESILIENCE_POLICY.md v3.

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

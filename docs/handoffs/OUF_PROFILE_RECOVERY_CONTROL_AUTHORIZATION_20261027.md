# Farmacie — riuso Teatri e correzione persistente del contesto HUMAN

27 ottobre 2026. Predecessore: [V36 installata](OUF_CHAT_RESUME_V36_INSTALLED_FARMACIE_RECOVERY_20261027.md). [Checkpoint verificabile](../../evidence/profile-recovery-control-authorization-20261027.json).

La pagina recovery è raggiungibile ma l'utente continua a vedere il diniego dopo il login e la riapertura dell'URL esatto. La radice api.ouf-lab.it/404 non è una prova utile del job. L'assistente non accede più alla THS: login e decisioni esclusivamente dell'utente, link esatto fornito quando occorre.

## Diagnosi acquisita

Verificato il collegamento corrente ouf-admin e riletta la sua proposta protetta b045ada2...: PUBLISHED/policy56. Il codice owner status impone stesso soggetto e tenant del proponente; questo controllo non verifica l'identità del browser dell'utente. Riletti134grant del soggetto su tre pagine50/50/34, tuttepolicy56/hashc52e856c.... Preview e profiling hanno grant strutturali che richiedono label/dettaglio, mentre i grant generici sono scaduti. Nessun grant nominale del soggetto per ouf.onboarding.quarantine.release nella proiezione letta. ROLES e CAPABILITIES hanno restituito INVALID_ARGUMENT/400: non inventare descriptor o un catalogo completo corrente per sostituirlo.

Una nuova sola lettura MCP dello stesso asset/job è stata negata, retryable=false: nessuno stato applicativo nuovo o byte CSV acquisiti. La policy e il codice riproducono l'incompatibilità con il precedente contesto capability senza attributi; il preciso hop/status del diniego nativo non è ancora osservato. Non attribuire a questa prova una verifica end-to-end della sessione del browser.

## Recupero del lavoro Teatri

[Permesso esatto dell'ultimo job](../../tools/csv_last_row_recovery/permissions.py), [protocollo retry idempotente](../../tools/csv_materialization_recovery/retry.py). Quei controlli vincolavano job/versione/baseline/tenant/soggetto, label già provata, review fresca e comando stabile. I grant finiti di quel caso e le authority/launcher consumate non vengono riusati. Separatamente, [Teatri readiness403](../../evidence/chatbot-teatri-readiness-service-route-diagnosis-20261017.json) aveva richiesto di correggere il client SERVICE che attraversava una route HUMAN: [codice qualificato](../../evidence/ingestion-readiness-correction-ci-20261017.json). Non è automaticamente la stessa causa del nuovo diniego HUMAN.

La recovery persistente non è tutta scomparsa: V35 readiness e ManagedProfileJobs V36 già installato conservano sessioni, contatori, snapshot, fencing e separazione budget/resume. Mancava la composizione del perimetro autorizzativo di controllo.

## Correzione nei candidati di produzione

- Onboarding PR53:9890b31868641e5be43c949a56f4ef69dd23bdfd. Risorsa managed-profile-job risolta dopo prova HUMAN/ownership tenant e stessa coppia asset/job; nessuna label CSV inventata. Contesto di dettaglio operativo TENANT_OPERATIONAL. La lettura MCP verifica anche ownership durevole prima della serializzazione.
- MCP PR80:d2454f3cb8cd410d284b9dc78349a170187aea1c. Il solo source.file.preview con asset/job esatti usa lo stesso contesto; ASSETS e contenuto dei profili mantengono il contesto precedente. Policy, scope, DENY e owner restano obbligatori.
- Profilo ruolo confezionato senza assignment/soggetto/validità: nessuna autorizzazione automatica. Applicabile solo al contesto managed-profile-job, non ai vecchi endpoint generici di quarantena o ai dati CSV. Un amministratore deve scegliere esplicitamente assegnazione/validità nella governance esistente, dopo aver letto il catalogo corrente e verificato descriptor/scopes/route. Non concedere grant larghi o temporanei per tentativi.
- Test con evaluator e compiler reali, API reali, PostgreSQL, SDK/trasporto e browser; conservati tentativi5, stessa operazione, pending idempotente e decisioni separate.

Primo candidato Onboarding da9faef8... PASS337test/0failure/error/skip e immagine build/scan/boot nel run40559914524/job122385845477; log diretto letto. Coppia finale qualificata: Onboarding9890... run40560505484/job122387932522 PASS338test/0failure/error/skip (17budgetPG/4policy/3API/1ownership), build/scan/nonrootbootPASS. Browser40560505488/job122387932567 e diagnostica40560505683/job122387933312 PASS; log diretti letti. MCPd245... run40560685583/job122388544115 PASS suite/kernel/race/pairwise/build/staticcheck/govulncheck (nessuna vulnerabilità), log diretto letto. Artifact immagine Onboarding12761085834/ZIPdigest704bf886..., MCP12761775539/ZIPdigestdbc4c918... conservati; archivi non ancora scaricati indipendentemente, nativeimageID e nuova review target non provati. Primo MCPb935... fermato solo da gofmt del test; corretto ind245.... Nessun risultato candidato target implicito.

## Stato target e seguito

V36 source6ea5242f.../nativeimagee4690481... rimane installata secondo la ricevuta acquisita. Il job Farmacie677480c8.../asset9c502da5... resta FAILED5 nell'ultima prova acquisita, non riletto con successo. Nessun budget/resume, grant/policywrite, nuovo job/upload/acquisizione, Engine/SQL, Registry restart/reinstall o accettazione eseguiti in questa ripresa.

Completare la qualifica, registrare i log e fissare la coorte/immagini del delta necessario; preparare una nuova ammissione minima e una review concreta, non rieseguire il vecchio APPLY/cattura/publisher. Poi verificare accesso HUMAN reale e due decisioni distinte sullo stesso job:3tentativi/900s e resume, cumulativi6–8. Se esito ambiguo, stesso comando/sessione. Dopo profilo: originale/hash/parser/preview e Farmacie61righe→UDP; D5/D6/D7 e due client restano aperti.

M1/G4 acquisiti; M2/G5/G6/G7 aperti. Nessun reset/replay/merge/release acceptance/subagenti/automazioni. Supervisor dopo E2E completo.

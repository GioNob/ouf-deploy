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

# CSV — tappa funzionale 3: rendiconto delle13righe
17 ottobre2026 · tecniche8/8, funzionali2/6

La tappa3 storica richiede13commit effettivi UDP con provenienza. La scelta dell'utente di mantenere un caso in quarantena resta conservata: un rendiconto12commit+1eccezione può essere completo, ma non modifica silenziosamente quel criterio.

## Riscontro corrente dalla chat

source.onboarding.read, account ouf-admin, conferma fonte teatri-csv-6609b245 e versione9860853e-e8f3-4b93-b9d2-03521a039962 ACTIVE, configurazione e pubblicazione immutate. urban.object.search per il tipo canonico pubblicato restituisce12ID distinti ACTIVE, revisione1, pagina completa. Ritrovato anche l'oggetto originario d6051381-934b-4a11-8e71-e1d89cee4e49.

La ricerca espone properties vuoto per ogni oggetto e nessuna provenienza. Questo non prova assenza dei dati: la proiezione è autorizzata per proprietà e la causa concreta dell'omissione non è ancora provata. Neppure il conteggio12 dimostra da solo l'appartenenza di ogni oggetto alla fonte Teatri. ingestion.status rifiuta la lettura, non ripetuta; permissions.read non supera lo schema del connettore e non legge grant. [Evidenza minimizzata](../evidence/csv-functional-stage3-chat-readback-20261017.json).

## Lettura puntuale riusata

Si estende scripts/read-teatri-post-resolution-materialization-20261017.py, preservando il controllo della ricevuta delle11decisioni. Il trasporto e i controlli di custodia/generazione provengono dal lettore post-rollout già qualificato: contesto linked-property-execution-cjecd1en, journal55, UDP35 e helper root esatto.

La diagnosi è specifica dell'installazione e della fixture; nessuna regola di prodotto specifica per Teatri. Due transazioni READ ONLY con rollback e timeout, nessuna lettura di token o valori di proprietà:
- Ingestion: run conservata, handoff, ACK e legame al lineage;
- UDP: tutte13le righe visibili nel tenant, job, source binding, revisione/osservazione verificata, numero di contributi e issue aperte;
- confronto degli ID handoff fra i due registri, senza interpretare il campo envelope ingestion_run_id come un UUID di run;
- rendiconto completo, commit13/13, eccezione e11decisioni sono condizioni distinte.

Le righe sono identificate dall'handoff durevole: l'ordine tecnico dell'elenco non è presentato come numero di riga CSV. Nessuna riacquisizione, decisione o ripresa job. La sola quarantena aperta non viene attribuita a una nuova decisione HUMAN.

## Esecuzione e prove

Il workflow csv-functional-stage3-read.yml esegue prima le prove su PostgreSQL17 e i controesempi. Solo dopo usa il runner VPS già esistente e un tentativo di sudo non interattivo, con hash dei byte verificato prima dell'esecuzione root. Non cambia permessi, non apre login e non cerca trasporti alternativi se l'accesso è negato.

Risultati aggiornati nella sezione seguente; i test non sostituiscono il readback del VPS. Il contatore funzionale resta2/6 finché il criterio storico non è soddisfatto o rivisto esplicitamente.

## Qualifica conclusa e limite di trasporto accertato

[CI39072444327](https://github.com/GioNob/ouf-deploy/actions/runs/39072444327), job117512659326: **9test PASS,0skip**. Il test PostgreSQL17 esegue entrambe le query e verifica anche ACK assente, lineage mancante, revisione mancante, job duplicato, isolamento tenant e omissione dei valori. Il launcher supera il controllo sintattico. La prima fixture è stata corretta aggiungendo il campo source_id della contribution; nessuna modifica di semantica del reader per superare il test.

Il tentativo sul runner in [CI39072364964](https://github.com/GioNob/ouf-deploy/actions/runs/39072364964), job117512471194, termina con **sudo: a password is required**. Il lettore root non viene eseguito:0sessioni SQL e0mutazioni target. Questo è un limite accertato del trasporto non interattivo, non una richiesta di ulteriore consenso utente. Nessun tentativo automatico successivo: il job target è disabilitato dopo il rifiuto.

La consegna è un solo launcher da eseguire come oufadmin nella sessione VPS già usata. Riusa il client GitHub portabile e l'autenticazione già presenti, scarica i byte prima di sudo e verifica SHA256 sia nel download sia nel processo privilegiato. Non richiede OAuth o un worker temporaneo. Non stampa né richiede token.

| Artefatto | Commit immutabile | SHA256 |
| --- | --- | --- |
| Lettore | 19f7da2cee7d4367181feb8b7fbb95eafa600306 | a026c82c257e1929677976484760ba669eb94c64fb8f7e84075cdbd3ecac7730 |
| Launcher | ca119dc9292cbf2e127da9e96d5245d1c44fccaa | 777c102bb313a984f85b04ff9c169d0dbe5852240dac5484f3ffeff7d53e83ee |

[Evidenza di qualifica e blocco di trasporto](../evidence/csv-functional-stage3-reader-qualified-20261017.json). Dopo l'esecuzione servono i record ACQUISITION_DATABASE e END: solo quelli possono completare il rendiconto corrente delle13righe. complete=true significa lettura terminata; readbackProven, expectedCurrentDispositionProven e allThirteenMaterializedProven hanno significati distinti. Il contatore resta2/6; nessuna ridefinizione tacita della tappa3.

## Readback VPS ricevuto: rendiconto e provenienza verificati

L'operatore ha eseguito il launcher qualificato e fornito i record BEGIN, ROLLOUT_READBACK, ACQUISITION_DATABASE(Ingestion/UDP) ed END. Il risultato supera il limite di trasporto del runner per questa lettura: non occorre ripeterla. [Evidenza target normalizzata](../evidence/csv-functional-stage3-target-readback-20261017.json).

| Controllo | Risultato |
| --- | --- |
| Generazioni applicative e contesto rollout | Coerenti, journal55; UDP35 checksum -376865285 |
| Run Ingestion conservata | Una run SUCCEEDED,13tentativi,0fallimenti |
| Handoff e lineage | 13ACKED,13ricevute,13lineage verificati; gli stessi13handoff presenti in UDP |
| Materializzazione | 12job SUCCEEDED,12binding/oggetti distinti,12osservazioni con revisione verificata |
| Proprietà persistite | 20contributi per ogni oggetto materializzato;240totali derivati dal rendiconto |
| Decisioni CREATE_NEW | 11decisioni consumate,11oggetti distinti con revisione e contributi verificati |
| Oggetto precedente alle11decisioni | d6051381-934b-4a11-8e71-e1d89cee4e49 conservato |
| Quarantena | Un handoff DURABLE, job QUARANTINED, una issue OPEN, nessun binding/contributo; escluso dal pacchetto confermato |
| Confronto con ricerca MCP | Gli ID dei12oggetti coincidono esattamente con quelli della ricerca precedente |
| Schedule | DISABLED, triggerOnce=true, pubblicazione1 già consumata,0failure e activationBlocked=false |
| Esito del lettore | complete=true,readbackProven=true,allRowsAccounted=true,upstreamHandoffsAndLineageMatch=true |
| Effetti | 0mutazioni,0retry job,0pubblicazioni,0grant,0OAuth |

La schedule disabilitata è coerente con il consumo della pubblicazione MANAGED corrente; non è un hold preventivo già qualificato per una nuova pubblicazione.

### Rendiconto per handoff

Questo elenco segue l'ordine degli ID tecnici, non l'ordine delle righe del CSV. I lineage completi sono conservati nell'evidenza JSON. Nessun valore di proprietà è pubblicato qui.

| Handoff | Oggetto UDP | Esito | Contributi |
| --- | --- | --- | --- |
| 0aab7d69-624e-4d76-853c-ce3fbc778255 | 63d4fde8-044f-4f36-9db0-86debe078973 | SUCCEEDED | 20 |
| 0aff252f-f9a6-46eb-9149-d64219030cc9 | d6051381-934b-4a11-8e71-e1d89cee4e49 | SUCCEEDED | 20 |
| 387f2a31-444c-4f80-b724-026cdeb7a296 | 2606bba6-2799-4275-833e-00cf10f7e03b | SUCCEEDED | 20 |
| 54ca77cc-165e-4b17-9e63-412f57ad0b34 | f4f18054-8b90-48be-b355-c8358a2d019d | SUCCEEDED | 20 |
| 62ddbb50-a5e1-4720-a628-5a9d55d56ce3 | 3db3a213-05f2-4817-a643-475cf7b3868b | SUCCEEDED | 20 |
| 77327abb-c7ec-4427-9b50-aa70515c4b42 | 76d5d321-6585-4c8a-92a0-588bf691a0cd | SUCCEEDED | 20 |
| 7e1c39ab-6733-4a4b-9229-9869158ab9e4 | ec6897bf-74e2-4534-94e0-3fff1204c250 | SUCCEEDED | 20 |
| 9fde61f1-8d3c-4de7-b3fe-b534b32e45e3 | — | QUARANTINED | 0 |
| a82a4173-132d-4baa-a538-3705c8db535a | 43d6d5c7-1b01-4fbb-9ec0-a7575399981a | SUCCEEDED | 20 |
| b09a9644-0ee6-4218-be30-3e4949b9aa38 | c2f83340-bf65-44f1-803b-347ae1246e5d | SUCCEEDED | 20 |
| b3176149-cddb-4e44-a594-fdf99c89bda2 | fe0f7632-96bb-4fc7-8641-5dca487f1c75 | SUCCEEDED | 20 |
| e9709c11-b8e4-46ee-b09f-ab42667299e5 | 535ea2cc-163a-49f0-94f0-1797dc31e521 | SUCCEEDED | 20 |
| ea3f1144-e1db-47c5-965b-157232168062 | 96aa4cb9-c51c-4316-8c9e-472c11c8e302 | SUCCEEDED | 20 |

L'eccezione è l'handoff9fde61f1-8d3c-4de7-b3fe-b534b32e45e3, lineage419ec184-7116-4ce8-b57c-6106938c65fb. Il codice del job è UDP_RESOLUTION_REVIEW_REQUIRED; la issue resta UNRESOLVED_IDENTITY/OPEN. La volontà di lasciarla in quarantena proviene dalla conversazione, non da una nuova decisione HUMAN creata dal lettore.

### Significato dell'avanzamento

**Verifica della tappa3 conclusa per l'esito scelto:12commit+1eccezione, tutte13le righe rendicontate e tracciate.** Il criterio storico13commit rimane aperto: allThirteenMaterializedProven=false,historicalCriterionChanged=false. Contatore formale ancora funzionali2/6, con tappa3 documentata come “rendiconto verificato con eccezione conservata”. Non richiedere un altro import o una decisione sulla quarantena per ripetere questa prova.

L'attivazione del profilo proprietà rimane un gate distinto: profileActivationProven=false e nessuna pubblicazione è stata eseguita. Il readback dimostra contributi persistiti; non risolve da solo la ricerca che restituisce properties vuoto. Il prossimo controllo funzionale è la tappa4: completare il riscontro dal chatbot sui dati autorizzati, riusando i12ID già ottenuti e questa provenienza.

## Verifica successiva alla nuova decisione HUMAN

L'utente riferisce di aver trattato il caso rimasto in quarantena. La THS /trusted-human/resolution/ consultata nel browser mostra “Non ci sono casi incerti aperti per questo tenant”. Una nuova ricerca MCP restituisce ancora i12ID precedenti, revisione1 e properties vuoto. Questo non distingue un collegamento a un oggetto esistente da un commit in attesa o un'altra azione: la chiusura della review da sola non incrementa il contatore.

Il lettore v3 conserva i controlli precedenti e aggiunge l'azione HUMAN più recente e il safe_failure_code per handoff. Il criterio è13righe committate, non13oggetti distinti: un APPROVE può riusare un oggetto. Il risultato readbackProven descrive il rendiconto; functionalStage3Proven richiede tutti13i commit più provenienza,11decisioni precedenti e oggetto originario. Solo allora END può riportare funzionali3/6.

Qualifica su PostgreSQL dei controesempi “review chiusa, job ancora in quarantena” e “13commit verso12oggetti”. Nessun nuovo tentativo sudo sul runner, già accertato non disponibile. Occorre il riscontro finale del lettore nella sessione VPS per verificare il commit dell'ultimo handoff9fde61f1-8d3c-4de7-b3fe-b534b32e45e3.

Qualifica v3 [39073074291](https://github.com/GioNob/ouf-deploy/actions/runs/39073074291), job117514536828:12test PASS,0skip. Lettore SHA256ff9f1f593e8c831e2192bc8483431de2b226f7408da28744ad7f5b9490fdcc6e, commitdb274e626e22fe3cf8148af3cf759bed2316e019; launcher SHA25689fdeeed327774e8f743aeb68426ce361e6ae55a19a55ec42e37debe11bc5771. Entrambe le query sono provate su PostgreSQL17, inclusi collegamento a oggetto esistente e review chiusa prima del commit. [Evidenza di qualifica v3](../evidence/csv-functional-stage3-final-reader-qualified-20261017.json). Il nuovo readback target resta da ricevere.

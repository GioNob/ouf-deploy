# Oggetti fino a 1024 colonne — modifica e prove

Decisione di Giovanni, 7 novembre 2026: portare a **1024** il limite, adeguando i passaggi correlati e il budget di lavoro. Caso concreto: una pratica dello Sportello Unico dell'Edilizia può contenere 300–400 dati. La pratica resta **un unico oggetto logico**; pagine di schema e letture progressive sono dettagli di elaborazione.

Stato: primo incremento di codice qualificato, su cinque PR draft. CI dei cinque moduli riuscita; dettagli e commit esatti nell'evidenza collegata. Il primo incremento del 7 novembre non ha distribuito servizi o modificato dati sul VPS. Aggiornamento dell'8 novembre: Gateway applicato e MCP PR83 installato con migrazione 14/readiness 204; Onboarding 1024 e Ingestion 1024 sono successivamente installati e pronti; resta UDP 1024. [Stato corrente](STATE.md). Nessun nuovo caricamento o acquisizione applicativa. Aggiornamento successivo: [MCP PR83](https://github.com/GioNob/ouf-mcp-server/pull/83) aggiunge piano dinamico, esecuzione e progressi persistenti e compone la discovery. [Stato corrente e limiti](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md). Il pacchetto MCP PR83 è installato, gli strumenti nuovi restano INACTIVE; la sola finestra fissa a 60/minuto non è la soluzione.

## Catena modificata

| Modulo | Modifica | Proposta |
| --- | --- | --- |
| Onboarding | 1024 colonne CSV/XLSX; statistiche CSV senza conservare tutte le righe; rifiuto dei valori oltre l'header; pagine immutabili COLUMNS; bozza, preparazione e copertura d'identità fino a 1024 proprietà | [PR55](https://github.com/GioNob/ouf-source-onboarding/pull/55) |
| MCP | Schemi create/review a 1024; COLUMNS autorizzato; limiti trasporto e timeout coerenti; capacità separata per le pagine di schema | [PR82](https://github.com/GioNob/ouf-mcp-server/pull/82) |
| Gateway | Schemi a 1024, body letti anche dal file temporaneo nginx senza cambiare i byte firmati, envelope e timeout allineati, ingresso MCP più capiente | [PR86](https://github.com/GioNob/ouf-api-gateway/pull/86), basata sul candidato PR84 |
| Ingestion | CSV validato interamente prima di restituire il cursore, poi letto una riga per volta; identità e checkpoint conservati; niente scarto silenzioso di valori extra | [PR48](https://github.com/GioNob/ouf-ingestion-runtime/pull/48) |
| UDP | Copertura di tutte le proprietà nel contratto d'identità fino a 1024 segnali; regole di riconciliazione, tenant e riferimenti immutati | [PR49](https://github.com/GioNob/ouf-udp-object-resolution/pull/49) |

Il controllo d'identità preesistente richiede un segnale per ogni proprietà mappata; sia Onboarding sia UDP ne consentivano solo 32. È stato aumentato il limite, non rimossa la copertura obbligatoria. Le regole sufficienti possono continuare a usare un sottoinsieme dei segnali. I 32 riferimenti a ontologie e le altre quote indipendenti dal numero di colonne non diventano automaticamente 1024.

## Limiti correlati

| Dimensione | Candidato | Motivo e limite della prova |
| --- | --- | --- |
| Colonne del profilo e campi della bozza | 1024; 1025 rifiutate | Include casi 300/400 e conserva il campo finale |
| Nome della colonna | 256 caratteri Java | Allineamento con il limite già presente nel contratto di mappatura |
| Pagina COLUMNS | 1–128 colonne; massimo 8 pagine per 1024 | asset, profile, versione e hash dello schema; senza campioni o riferimenti storage |
| Risposta preview MCP | 1 MiB | Allinea il manifest al limite già effettivo; per schemi grandi usare COLUMNS |
| Argomenti MCP create/review | 2 MiB | Limite totale indipendente dalla cardinalità; 1024 non significa stringhe illimitate |
| Envelope Gateway/owner create | 3 MiB | Spazio per identità e ricevuta oltre agli argomenti |
| Envelope Gateway review-prepare | 3 MiB | Include proprietà e segnali d'identità; altri comandi restano limitati |
| Ingresso MCP JSON-RPC | 4 MiB | Allineato tra gateway e server; le altre singole tool mantengono i loro contratti |
| Attesa create/preview | 10 secondi | In MCP e upstream Gateway; preparazione review già a 10 secondi |
| Scrittura risposta HTTP MCP | 15 secondi | Margine rispetto al comando da 10 secondi; ingresso Gateway esplicito a 30 secondi |
| Pagine di schema per minuto | 24, quota separata | Sufficiente per le 8 pagine, con consumo persistito; retry equivalenti invariati |
| File, righe e campioni profiler | 10 MiB, 10.000 righe, 5 campioni | Restano limiti indipendenti. I casi di prova massimi rientrano nei 10 MiB |
| Job di profilazione | Deadline esistente 900 secondi, lease esistente fino a 120 secondi | Non aumentate senza evidenza: le prove CPU CSV sono nell'ordine dei secondi, non dei minuti. Tempi VPS/S3 non misurati qui |

Il limite di payload rimane reale: configurazioni con 1024 nomi, URI e annotazioni molto lunghi possono superarlo. Il numero di colonne da solo non descrive i byte necessari. Non fingere accettazione universale di ogni combinazione dei massimi delle stringhe. Le pagine evitano di imporre una risposta monolitica all'analista, senza spezzare la pratica.

## Risultati misurati

Prove sintetiche native Java 21, heap **384 MiB**, non misure sul VPS:

| Prova | Esito |
| --- | --- |
| Prima implementazione CSV che conservava la tabella, 1024 × 10.000 celle vuote | OutOfMemoryError: difetto riprodotto, non mascherato aumentando l'heap |
| CSV progressivo, 1024 × 10.000 righe vuote, 10.250.154 byte | PASS, circa 0,7 secondi |
| CSV, 1024 × 2000 valori distinti per colonna, 9.113.514 byte | PASS, circa 1,64 secondi; conteggi e chiavi esatti |
| Ingestion CSV, 1024 × 10.000 righe vuote, validazione e lettura completa | PASS, circa 2,35 secondi; nessuna tabella completa trattenuta |
| Onboarding PostgreSQL: profilo, 8 pagine, una bozza idempotente da 1024 proprietà | PASS |
| Preparazione esecuzione, proprietà e segnali 300/400/1024 | PASS; 1025 rifiutate |
| UDP: decoder e motore d'identità, un oggetto con 300/400/1024 proprietà | PASS; evidenze complete, 1025 rifiutate |
| SDK MCP ufficiale → autorizzazione → trasporto TLS Gateway fixture, 1024 campi | PASS; 1025 non inoltrate |
| APISIX reale, 1024 campi e firma dei byte integrali | PASS, incluse richieste maggiori del normale buffer nginx |
| APISIX reale, ingresso MCP oltre il vecchio MiB | PASS sul fixture di trasporto; non è una prova completa dell'applicazione |

Questi tempi qualificano casi precisi. Non sono SLA o stime della ricerca semantica: ricerche di vocabolari, ambiguità e servizi remoti hanno costi differenti.

La CI Onboarding sul primo candidato corretto ha eseguito **383 test senza errori**, poi è stata fermata dalla scansione immagine: APT e libapt-pkg7.0 affetti da CVE-2026-109518. Il rapporto identifica 3.2.0 e la correzione 3.2.1ubuntu0.1. Il Dockerfile candidato fissa il digest della base osservata e applica l'aggiornamento APT con Acquire::Retries=0 durante l'installazione, come indicato da [Ubuntu USN-8996-1](https://ubuntu.com/security/notices/USN-8996-1). Non è stata introdotta un'esenzione dello scanner. La nuova immagine supera scanner e avvio con staging abilitato. Dettagli nell'[evidenza](../evidence/wide-object-1024-20261107.json).

## Rischi residui e gestione

| Rischio | Gestione attuata / ancora necessaria |
| --- | --- |
| Esaurimento memoria proporzionale alle celle | CSV profiler e Ingestion non trattengono più tutta la tabella; prova limite a 384 MiB. Il profiler conserva conteggi distinti esatti, quindi il consumo dipende anche dalla cardinalità. XLSX non ha questa qualifica di memoria |
| Perdita di campi a valle | Array, proprietà e segnali allineati; verificato l'ultimo campo e il rifiuto della 1025ª colonna. E2E reale ancora necessario |
| 413/timeout dopo un upload riuscito | Contratti e materializzatori allineati; test APISIX. Gateway aggiornato e verificato successivamente; supporto funzionale completo1024 ancora da provare |
| Analisi semantica fermata dalla quota | Piano/progresso persistente PR83 implementato e installato; strumenti INACTIVE e prova live ancora aperta |
| Lavoro perso o ripetuto dopo interruzione | Checkpoint CSV e idempotenza della bozza verificati. Avanzamento semantico persistente implementato in PR83; prova live ancora aperta |
| Costo UDP con molte proprietà e candidati | Decoder e decisione deterministica qualificati; cardinalità dei candidati resta limitata. Carico concorrente e normale scrittura lake non qualificati qui |
| Dati SUE potenzialmente personali | Nessuna estensione automatica della scelta OPEN di Teatri ai dati edilizi; access label resta decisione specifica per proprietà |
| Rollout con stato del container diverso | Nessun rollout in questo incremento. Conservare la lezione MacAddress e leggere il profilo del lifecycle applicabile; niente hash riscritti o ignore globale |

## Sequenza di completamento

1. **Supporto di forma e trasporto:** chiudere la CI dei cinque candidati ed eventuali incompatibilità residue. Stato ed esiti esatti nel JSON collegato. Non dichiarare installazione dal merge o dalla build.
2. **Budget dinamico, candidato PR83:** il coordinatore implementa il collegamento necessario per associare l'analisi a tenant/soggetto/asset/profilo/versione/hash verificati dal proprietario; dimensionare il lavoro dal profilo e dalle attività effettive, distinguendo ricerche nuove, letture riusabili e retry. Conservare consumo e progresso per colonna. La stessa analisi ripresa non riceve una quota nuova. [Implementazione e qualifica](OUF_SEMANTIC_ANALYSIS_BUDGET_20261107.md).
3. **Ripresa attraverso più finestre:** esporre stato, lavoro residuo e attesa; la saturazione temporale non chiude l'analisi. Testare 20/50/100/200/300/400/1024 colonne, riavvio e completamento/irrisolti espliciti. Non inventare coefficienti come se fossero misurati.
4. **Composizione e prova funzionale:** distribuire un insieme coerente conservando SeaweedFS e gli ID correnti; provare il percorso Teatri conservato fino alla normale scrittura lake UDP, quindi ripeterlo. Usare un fixture distinto per il caso SUE ampio; non ricaricare il file reale per dimostrare i test di codice.

Il lavoro è diviso in incrementi verificabili perché il limite di schema e il coordinamento durevole dell'analisi sono modifiche diverse. Questo documento chiude il rischio di dimenticare i passaggi a valle, **non dimostra il funzionamento dell'analisi dinamica né chiude F2–F6**. L'installazione successiva del pacchetto MCP PR83 è documentata dalla [ricevuta dell'8 novembre](../evidence/mcp-analysis-ready-operator-20261108.json).

## Aggiornamento distribuzione — 9 novembre 2026

UDP preflight target acquisito: V36 e binding SeaweedFS coerenti,34 handoff/34 job conclusi e110 oggetti VERIFIED. Archivio c0cf1702 scaricato e verificato; installer qualificato in CI42568440028 su classic/containerd, due profili legacy,59 tabelle sintetiche invariate e TLS JVM. [Comando e limiti](OUF_UDP_WIDE_UPGRADE_20261108.md). Ricevuta UDP_WIDE_1024_READY ancora attesa; nessuna prova funzionale1024 o E2E aggiunta. Gli altri quattro componenti aggiornati restano pronti, strumenti discovery ancora da attivare.

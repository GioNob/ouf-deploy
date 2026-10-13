# Lacuna di accounting — proposta di contratto owner

La lettura sul VPS del13ottobre,16:54 Europe/Rome, è riuscita: audit attualmente disabilitato, GET concluso con exit0, nessun campione richiesto, conteggio storico non noto. I tipi di evento configurati non abilitano la registrazione quando eventsEnabled=false. Questo non dimostra che l'audit sia sempre stato spento o che non esistano vecchi eventi: non sono stati interrogati. Anche eventuali vecchi eventi richiederebbero una prova indipendente di completezza per essere accounting storico accettato. [Ricevuta conservata](../evidence/policy-token-owner-accounting-audit-disabled-target-20261013.json).

La modifica IAM precedente resta completata: un solo POST riconciliato e due firme. Non ripeterla. Le osservazioni della lacuna non creano budget, non emettono token e non risolvono lo storico.

## Decisione concreta richiesta

Si propone un nuovo contratto esplicito di migrazione dell'owner, non una certificazione retrospettiva. Il contratto conserverebbe lo storico legacy come UNKNOWN, con totale cumulativo null e lacuna OPEN. Tutte le ricevute, i contatori noti e i claim consumati restano conservati; nessuno storico mancante viene scritto come zero. Il ledger di una futura sessione avrebbe i propri contatori prospettici, distinti dai totali legacy indeterminati e collegati allo stesso scope logico/lineage.

La prima sessione proposta è volutamente limitata a UNA richiesta di grant e successiva introspezione entro300secondi, per qualificare il nuovo owner. Non è rinnovo periodico illimitato, non attiva servizi, non produce una nuova sessione automaticamente e non autorizza semantic publication/ingestion. Ogni grant consuma il limite prima della chiamata; timeout/crash/esito ambiguo richiedono riconciliazione e impediscono un secondo invio, anche con altro processo o job. Dopo il tentativo il nuovo lavoro resta fermo; un'ulteriore sessione richiederebbe una decisione governata distinta, preservando storia e cumulativi noti/indeterminati.

**L'approvazione richiesta ora riguarda solo questo contratto da implementare e qualificare. Non concede il budget e non autorizza una richiesta reale.** Prima di qualsiasi esecuzione servirà il pacchetto completo concretamente verificabile, una nuova approvazione HUMAN vincolata ai suoi byte e le firme del proprietario esistente. Custodia/ripristino della credenziale, quiescenza del writer legacy, TLS/issuer/client/scope/generazione e persistenza/fencing devono essere dimostrati nel cutover approvato; la decisione sul contratto non sostituisce quei gate. Il vecchio worker non può essere avviato usando questa proposta. R12 non è ripristinato né rigiocato.

## Perché serve una decisione del proprietario

La [policy v3](../docs/OUF_RESILIENCE_POLICY.md),§14–16, consente nuovi budget finiti HUMAN con storico conservato, ma non cambia implicitamente i contratti di dominio e non risolve effetti incerti o grant/custodia mancanti. Il [contratto worker esistente](SEMANTIC_POLICY_TOKEN_FINITE_WORKER_20261012.md) dichiara: “Missing legacy history is not created at zero.” L'intake di installazione corrente richiede accounting storico riconciliato. Il nuovo ramo UNKNOWN non è già approvato né implementato da quei contratti: richiede una decisione esplicita owner, mantenendo il deny corrente fino alla successiva chiusura concreta. La delega di sviluppo autonomo non viene trattata come questa modifica del contratto o come autorizzazione runtime.

L'implementazione dovrà distinguere almeno: gap ancora OPEN; disposizione contrattuale approvata; sessione nuova autorizzata; permessi IAM; credenziale re-established; richiesta consumata; introspezione positiva; pubblicazione ammessa; runtime readiness. Nessuno dei primi tre certifica la completezza del passato. La validazione richiesta include due approvazioni concorrenti/stesso scope, worker vecchio/stale, clock e scadenza, crash prima/dopo effetti, revoca/custodia/configurazione, accounting indeterminato mai convertito a zero e nessun reset/replay intersessione.

## Artefatto esatto

[Proposta strutturata](policy-token-accounting-gap-contract-review-20261013.json), SHA256 `f1200b4de0b33899760b1db1406725b6b7d633451b037ec9dc638754ecbcaa17`. Stato PROPOSED_OWNER_CONTRACT_NOT_APPROVED. Decisione richiesta APPROVE_ACCOUNTING_GAP_MIGRATION_CONTRACT_DESIGN_ONLY. Nessuna authority/firma/grant/mutazione/servizio/budget emessa da questa pubblicazione. L'artefatto è una proposta di dominio, non codice installer qualificato o release acceptance.

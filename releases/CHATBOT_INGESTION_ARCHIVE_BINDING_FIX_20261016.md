# Fase 6: correzione del lettore degli archivi conservati

Il launcher precedente ha raggiunto il preflight del VPS e si è arrestato con
AttributeError, senza nuova autorità runtime, prima della revisione HUMAN.
La roadmap target resta fasi 1–5 complete, fase 6 sospesa, fase 7–8 pendenti,
CSV 0/6 e nove grant cumulativi conservati.

## Difetto e copertura mancante

In gateway_recovery.retained_bindings il conteggio locale prior nascondeva
l'import migration_recovery as prior. Dopo le verifiche di proof e file, il
codice invocava archive_bytes su un intero. Il fix cambia esclusivamente il
nome del conteggio in prior_count; la chiamata rimane al modulo originale.
I precedenti 494 test erano passati, ma l'enrichment simulava quel confine e
quindi non dimostrava il funzionamento del lettore completo in tale percorso.

La nuova regressione usa il validatore di produzione e il lettore di produzione
su quattro file privati di fixture, con dimensioni e SHA256 vincolati. Prova sia
otto sia nove grant, verifica l'immutabilità dei file, rifiuta il conteggio
errato e altera ciascun archivio a turno verificandone il rifiuto. Il formato
PGDMP sintetico di questa regressione non prova il ripristino: il parsing dei
dump PostgreSQL reali è coperto dalle qualifiche native precedenti.
La stessa regressione, caricando il corpo precedente della funzione, riproduce
esattamente int has no attribute archive_bytes; con il fix passa.

## Versioni e invarianti

Runtime: f6078a5ac07853b4abc13d310882f5a30086baba.
Capsula 130 membri, SHA256 890b78dc63521133a1535514e8aed82df7256328b9290c4562ffdc90a36ccb72.
Delivery SHA256 67dbee02177546b3d157fade03e5d815eabd5d9306819037266861e3605ae01b.
Launcher: scripts/launch-chatbot-ingestion-archive-binding-fix-20261016.sh.

Nessun cambiamento a proof, claim, pin, scope, piani, policy, trasporti o
confronto Env/identità già qualificati. Riutilizzo del container Ingestion
esistente e mai avviato, nessun nuovo rename/create, un solo start prenotato.
74 route e 28 effetti Gateway completati verificati senza nuove scritture;
APISIX conservato senza nuovo stop/create/start. Quattro backup riusati senza
nuovi dump/restore, migrazioni MCP COMPLETE/audit CLEAN e Registry senza replay.
Nuova revisione HUMAN esatta, massimo 128 tentativi/3600 secondi, prossimo grant
nuovo decimo cumulativo; niente reset o rinnovo automatico. Jitter, Retry-After,
revoca e scadenze persistenti restano invariati. Approvazioni applicative nei THS.
Configurazione e PET restano vincolanti; pin dell'incidente specifici di questa
installazione, nessuna nuova qualifica multi-host o end-to-end.

## Verifiche

Locale: sei test di ripresa Ingestion e 14 test di consegna PASS. Nuova regressione
rossa sul corpo precedente e verde sul fix, senza accesso al VPS.
Le qualifiche CI della correzione sono riportate nell'evidenza associata.

CI mirata 38879641570 PASS: job 116903005300, 21 test in sei suite;
job 116903005696, due test nativi reali Docker/APISIX. CI backup 38879641568,
job 116903004811 PASS. Sorgente fixture 1bc6fa728c9b5fdab7c9b030764a22ea3c538f3b;
GitHub compare prova che rispetto al runtime f6078a5ac07853b4abc13d310882f5a30086baba
cambia soltanto la directory temporanea del nuovo test, nessun membro runtime.
La prima esecuzione della nuova prova in CI usava /tmp: il rifiuto della
custodia degli antenati scrivibili era corretto. La fixture è stata spostata
sotto la radice protetta senza indebolire i controlli di produzione.

La suite generale aggiuntiva 38879641541 è ancora in corso al rilascio e non
è contata come superata. Le qualifiche mirate concluse coprono il cambiamento
locale del nome, il percorso reale dei quattro file, adozione, grant finiti e
consegna. La precedente suite generale (494 test) resta riferita alla sorgente
precedente a2132d7ee330f9f0ce7d4fc9316dd880acad4f3f, non a questa correzione.
La pubblicazione non avanza il VPS e non emette autorità runtime.

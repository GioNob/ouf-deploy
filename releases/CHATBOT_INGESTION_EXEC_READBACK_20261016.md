# Fase 6: confronto di processo e ambiente per lo start fallito

Il readback VPS conferma lo stesso container Ingestion in created/PID0,
neverStarted=true, ExitCode127, senza restart. L'eseguibile applicativo non è
partito; il journal conserva ingestion.start CLAIMED. L'errore Docker di 224
byte è classificato MISSING_PATH_OR_EXECUTABLE e OCI_RUNTIME_FAILURE, ma il
messaggio non è stato esposto. Queste categorie non identificano da sole la
causa esatta. La roadmap resta 1–5 completate, fase6 sospesa, CSV0/6.

Worker CANCELLED con dieci grant cumulativi, nove predecessori e un nuovo
tentativo, publicationCount1; admission BLOCKED. Tutti e quattro i backup
COMPLETE, migrazioni MCP COMPLETE/audit CLEAN. Gateway 28 effetti conservati,
74 route conformi al piano in due letture; UDP e Onboarding generazioni intatte.
Evidenza target completa redatta in chatbot-ingestion-start-target-readback-20261016.json.

Il nuovo lettore usa lo stesso contesto/review/autorità/CID già vincolati del
lettore start e non modifica il perimetro o i checkpoint. Aggiunge soltanto
metadata sul confronto Entrypoint/PATH/JAVA_HOME tra richiesta, immagine e
container. Rileva il messaggio standard executable file not found in $PATH
senza stamparlo. Non dichiara corretto il binario né legge il filesystem
privato o esegue processi nel container. Il confronto con JAVA_HOME dell'immagine
è un indicatore di configurazione, non una prova fisica del binario/loader.

Default di processo e ambiente derivano dai metadata dell'immagine esatta,
non da percorsi Java o domini codificati per un Ente. Nessun fallback automatico,
sovrascrittura di PATH o nuovo start. Il recupero con intento modificato richiede
nuova revisione concreta dopo aver dimostrato la causa; claim vecchio e CID
fallito devono rimanere conservati. Retry, revoca e budget non sono rinnovati
né modificati dal lettore. PET e policy resilience v3 restano vincolanti.

Fonte lettore 8403872c98a95111211880af07e30d02d8ca1513.
SHA256 lettore e870c34240bb69ed7e9d87cbffe48ca94ead769dc62ddacd33dc2193b470a635.
SHA256 launcher 719143c4b2ea14a083b16c009d711aa08690c289bb34ea26ebd5146710e334d8.

Nove test locali del lettore PASS, incluse tutte le otto prove di custodia,
identità, claim, redazione e deriva del lettore start e una regressione della
classificazione PATH/Java/default. Tutte le chiamate HTTP sono letteralmente
GET; helper di custodia/trasporto identici per AST al lettore nativo qualificato.

CI 38881156233, job 116907935162: PASS, 43 test senza skip incluse le letture native namespace/PostgreSQL ereditate. Nessun accesso al VPS o autorità runtime emessa dalla qualifica.

# Prosecuzione Gateway, fase tecnica 5/8

**Procedura corrente: [APISIX conservato e autorizzazioni riconciliate](CHATBOT_GATEWAY_RETAINED_AUTHORIZATION_20261016.md).**
I launcher di questa pagina restano storici e non vanno ripetuti.

**Launcher superato dopo il blocco di preparazione sul VPS.** Usare la
[correzione Binds null](CHATBOT_GATEWAY_PHASE5_NULL_BINDS_20261016.md).
Le evidenze sotto descrivono la precedente qualifica, che non copriva tale variante.

Sorgente qualificato: `aeeb625ddacc5837e4520788d73a6598aaa5734f`.
Stato target invariato: fasi 1–4 completate, fase 5 sospesa a nove modifiche su 37,
otto grant cumulativi; dimostrazione CSV 0/6.

## Cosa prepara il nuovo comando

Riutilizza il pacchetto originale, verifica i checkpoint e prepara una revisione
privata completa prima dell'approvazione HUMAN. La revisione include la
sostituzione APISIX con la stessa immagine e due asset Lua verificati, montati in
sola lettura; comporta una breve interruzione del Gateway durante la sostituzione.
Conserva le nove modifiche applicate e il claim storico ambiguo; prepara le 28
modifiche residue, con un nuovo intento per lo schema corretto. Ogni scrittura
richiede la rilettura esatta della mappa completa.

Quattro backup già COMPLETE vengono copiati e verificati: zero nuovi dump,
restore o reset DB. Migrazioni MCP COMPLETE e privilegi temporanei CLEAN restano
acquisiti. Nessun bootstrap audit, avvio migrazione, sostituzione UDP/Onboarding
o replay delle dieci fasi Registry. I gate correnti sono verificati nuovamente.

La nuova sessione conserva gli otto grant: il prossimo effettivo è il nono.
Massimo 128 tentativi e 3600 secondi entro la decisione HUMAN, senza rinnovo
automatico; esiti ambigui, drift o revoca bloccano. Poi il percorso comprende
Ingestion, MCP applicativo, verifica complessiva e rilascio produttori. Non
costituisce prova CSV end-to-end né accettazione runtime permanente.

## Configurazione e limiti

URL, domini, peer, credenziali e route vengono dal piano/configurazione già
approvati per questa installazione. Il nuovo adattatore conserva i byte della
configurazione esistente aggiungendo soltanto i due riferimenti Lua verificati;
configurazioni YAML ambigue o estensioni Lua già presenti bloccano la preparazione.
I contratti API/PET e i limiti numerici non cambiano.

Questa è una ripresa vincolata alla specifica installazione Docker/netns. Non è
una qualifica generale di trasporti tra host/reti diversi. I riferimenti host
del bootstrap e i pin di incidente non sono default per altri Enti.

## Verifiche

CI nativa `38857329614` PASS: sostituzione APISIX, 28 scritture residue, 37 route
esatte; revisione completa di fase 5, otto grant conservati e nono reale su TLS.
La regressione completa `38857329616` è PASS: 473 test in 63 suite, zero errori
o skip. Regressione backup `38857329638` PASS. Il launcher è rilasciato con
sorgente e hash vincolati; prepara la revisione completa prima della decisione HUMAN.

[Evidenza strutturata](../evidence/chatbot-gateway-phase5-continuation-qualification-20261016.json).

## Procedura operatore prevista

Il launcher `scripts/launch-chatbot-gateway-phase5-continuation-20261016.sh`
scarica il delivery dal commit indicato e ne verifica SHA256 prima di avviare
Python. Controlla prima il client GitHub portabile già presente e l'archivio
originale; se manca uno dei due si ferma prima di sudo. Non richiede nuovi token
GitHub né nuovi download del pacchetto applicativo.

La preparazione verifica lo storico e le generazioni correnti, poi richiede
la sessione amministrativa IAM e il login HUMAN quando necessario. Solo dopo
aver composto il documento privato completo presenta `APPROVO <hash>`.
L'approvazione si riferisce a quel documento e a quella finestra finita.
Un'eventuale sospensione conserva la diagnosi e richiede riconciliazione;
non ripetere il launcher già consumato.

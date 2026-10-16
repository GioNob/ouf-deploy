# Fase 5/8: riconciliazione in sola lettura della pubblicazione Gateway

## Avanzamento confermato dal flusso

L'utente ha eseguito la prosecuzione di fase 2, sorgente
`70af66b26d9a8dfdd7151c55f44eb5795fcc84a8`, revisione
`bd2cbc1e969bf3eb4c5b1b54240cf1d67d3283685bc1ca563f893d17e3430144`.
Il delivery è arrivato a `gateway.apply()` e si è fermato alla rilettura dopo
una PUT con `GATEWAY_WRITE_OUTCOME_UNPROVEN_NO_REPLAY`.

L'ordine di `delivery.run()` richiede prima il completamento di
`databases.migrate_mcp()` (inclusa revoca verificata), sostituzione/readiness UDP
più `databases.verify_module('udp')`, quindi gli stessi controlli di Onboarding.
Le fasi tecniche 2, 3 e 4 sono superate nel flusso. Il prossimo reader acquisisce
la conferma persistita e lo stato corrente. Fasi 6–8 non raggiunte, CSV 0/6.
La cancellazione del worker finito non costituisce accettazione permanente.

La fase 1 non viene rieseguita: la prosecuzione copia e verifica i quattro
archivi COMPLETE senza nuovi dump. I messaggi generici della preparazione e
`REGISTRY_REPLACEMENT_AND_VERIFICATION` descrivono il percorso condiviso;
nel ramo usato i dieci effetti Registry sono conservati, non ripetuti.
Le autenticazioni e la nuova revisione riguardano una nuova sessione finita.

## Limite diagnostico e divieto di replay

Il codice invia una sola PUT dopo il claim durabile. Scarta però status/body
dell'ACK e accetta l'effetto soltanto se una nuova GET dell'intera mappa coincide
con la mappa attesa. Il messaggio osservato prova quella mancata coincidenza,
non la causa: può essere mancata applicazione, normalizzazione APISIX o un'altra
differenza. Il log non consente di distinguere queste possibilità. Il reader
non può ricostruire un ACK non conservato. Non rilanciare il delivery, la PUT,
i container già sostituiti o le migrazioni completate.

## Reader esatto

Sorgente diagnostico: `ebdcf153c450ea5ab55c1783d281f1b963c5c29c`.
Script: `scripts/read-chatbot-gateway-state-20261016.py`.
SHA256: `fa88de46ffe5b772b155a71ba0945d068fa16570e8e5768ade496fef1dad20d1`.
Launcher: `scripts/launch-chatbot-gateway-state-20261016.sh`.
SHA256: `660c4a75612b483b727dd2f6dd5cc54532e902c0ca10b9ba9a9b729d43c1df67`.

Il reader è vincolato alla revisione sopra, all'autorità
`0e3a1a76b5528704c3295eff50c92b269a4f69c7d5eeff3304b193e991b54cb8`
e al contesto
`/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-35d5c6c756feb9c4811ac6d24610698a10c82d22b831d2cc85cd5c22c94d40d5`.
Richiede il processo delivery arrestato; controlla review/authority/bundle,
archivi e journal, poi li rilegge per rilevare variazioni concorrenti.

Controlla MCP COMPLETE/CLEAN, storia migrazioni corrente, membership e CREATE,
TRIGGER temporaneo e proprietà/ACL preservate. Legge i dieci effetti dei due
moduli UDP/Onboarding, le generazioni correnti e la storia Flyway di entrambi.
La readiness dei moduli è evidenza storica del journal; il reader non la
ripete né dichiara disponibilità applicativa permanente. Legge il nuovo totale
dei grant, che non viene supposto pari a sette.

Esegue esattamente due GET dell'inventario route tramite un figlio Python
isolato nel namespace APISIX selezionato. Metodo e endpoint sono letterali:
nessun metodo, path o body è fornibile dall'input. Configurazione, credenziale
amministrativa esistente, namespace e generazione hanno custody e binding
verificati prima/dopo le letture. La credenziale passa via stdin, mai argv/log.
Il reader non richiede una nuova sessione IAM o una nuova approvazione runtime.

Confronta ogni mappa con prima del claim, dopo il claim e piano finale. Stampa
conteggi, hash, tipi e percorsi strutturali selezionati; i nomi sconosciuti
sono redatti. Nessun contenuto route, nome route, URL, credenziale o valore
privato viene stampato. Sono visibili soltanto valori numerici limitati per
pochi campi strutturali (per esempio status/priority). Le differenze non sono
accettate o ignorate; nessuna normalizzazione runtime viene modificata.

Massimo 240 secondi totali, massimo due GET, timeout figlio 12s/parent 15s,
risposta massima 8 MiB, 256 route. SQL SELECT con transaction_read_only e
statement timeout 10s, lock timeout 3s, timeout remoto 15s. Zero dump, scritture
Gateway/DB, grant, IAM, start/stop, restore, riconciliazione dei journal o
emissione di autorità. Directory temporanee e log sono gli unici nuovi file.

## Qualificazione e prossimo passo

CI [38841644559](https://github.com/GioNob/ouf-deploy/actions/runs/38841644559),
job `116782864580`: **12 test passati, zero failure/error/skip** sul sorgente
esatto. Comprende namespace GET reale con credenziale sintetica, due letture,
rifiuto di inode/config cambiati e namespace del padre preservato; query
Flyway esatta su PostgreSQL 17 reale per UDP/Onboarding; fixture completa dei
record privati, redazione, differenze tipizzate, claim errato, mutazioni
concorrenti, confronto delle funzioni custody/parser con il sorgente runtime.
Il server HTTP della prova è una fixture, non APISIX: questa CI qualifica il
trasporto in sola lettura, non identifica la causa sul VPS né qualifica una
correzione runtime. Il reader non ha ancora letto il nuovo stato target.

Eseguire il nuovo launcher diagnostico e conservare/incollare l'output.
Il risultato determina se l'effetto è esatto, assente o differente e quali
verifiche/correzioni governate servono. La roadmap resta fase 5/8, CSV 0/6.

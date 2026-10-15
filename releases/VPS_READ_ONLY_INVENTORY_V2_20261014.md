# Raccolta VPS v2 — baseline del 14 ottobre 2026

Il prossimo comando autorizzato è una sola raccolta in lettura con confronto
stabile CLI/API. Non eseguire di nuovo la consegna del candidato: la causa del
precedente blocco deve essere verificata sul VPS prima del rollout.

## Sorgente e qualificazione

- Sorgente eseguibile: `8dd4c06b26c2c3a0e0545e8f733b8d58a20275de`.
- SHA256 del raccoglitore:
  `b0e9f78178452873be69b7e8870a185c6966ea1640231ffb7952ed102aaa4058`.
- [Qualificazione del commit](https://github.com/GioNob/ouf-deploy/actions/runs/38644073507),
  job116126488393: 32 test e una prova Docker/PostgreSQL reale, tutti PASS,
  nessun test saltato. Anche la qualificazione PR38644078961 è PASS.
- [Evidenza strutturata](../evidence/vps-inventory-v2-qualification-20261014.json).
- [Launcher esatto](vps-read-only-inventory-v2-20261014.sh): usa gh già autenticato,
  scarica il solo raccoglitore qualificato, verifica SHA256, invoca root Python
  isolato una volta, conserva il rapporto completo in una nuova directory privata
  e stampa la diagnosi selezionata. Il filtro di visualizzazione non modifica il
  rapporto completo conservato dal precedente `tee`.

Il test Unix reale gira obbligatoriamente in Actions. Nel sandbox locale il socket
è vietato e solo quel test è saltato; questa limitazione locale non è stata
trattata come qualificazione riuscita prima dell'esecuzione CI.

## Avanzamento dimostrato

La prova Docker reale usa Engine e CLI28.0.4, API massima1.48, oltre alla lettura
fissata1.44 del preparatore. Lo stesso container mantiene ID, immagine, PID e avvio;
entrambe le letture sono stabili. Il frame ottenuto dalla CLI coincide con la nuova
lettura CLI, ma differisce dalla lettura1.44 in `networkSettingsHash`. La differenza
strutturale osservata è `NetworkSettings.Networks.<rete>.Aliases`.

Quindi il meccanismo di falso cambiamento di generazione per differenza di canale
è riprodotto su Docker reale, non soltanto con dizionari sintetici. Non è ancora
la diagnosi del VPS29.8.1: la lettura del target deve mostrare i propri campi
diversi. Non dedurre che il solo campo Aliases spieghi tutte le differenze del
target, né che il percorso applicativo finale sia qualificato.

La prova PostgreSQL17 legge cinque storie, comprese quattro con il marker Flyway
SCHEMA quotato e la quinta con URL MCP `sslmode=disable`. Righe della fixture e
conteggio dei ruoli coincidono prima/dopo. Il test non modifica database del VPS.

## Cosa legge la v2

- Confronta il frame storico autenticato con CLI e API1.44, con due letture per
  canale; stampa binding, nomi/presenza/tipi dei campi diversi, mai i valori grezzi.
- Registra versioni Engine/API/CLI. Non normalizza oggetti, modifica hash storici
  o dichiara autorità runtime dal risultato del confronto.
- Inventaria fino a512 container con gruppi di16 letture; non fa una chiamata per
  ogni candidato storico. Le letture approfondite di immagini/configurazioni/DB
  restano limitate ai nove owner selezionati, incluso il control plane opzionale.
- Accetta soltanto il marker Flyway SCHEMA esatto per lo schema selezionato;
  metadati sconosciuti restano indisponibili con il nome del campo respinto.
- Distingue errori di host, porta e query del selettore DB; ammette parametri non
  identificativi limitati e continua a negare override di host/user/password/DB.
  Le query non usano il DSN per la connessione: SELECT tramite psql nel PostgreSQL
  già selezionato, transazione READ ONLY, timeout brevi e ROLLBACK.
- Distingue alcune classi di errore del GET IAM mediante pattern fissi, senza
  stampare stderr o credenziali; i casi sconosciuti restano tali. La classificazione
  non prova scope o grant effettivi. Non avvia login IAM; il GET può aggiornare una
  sessione amministrativa già esistente.
- Ripete configurazioni selezionate, Gateway, policy attiva, asset Teatri,
  runc e stabilità degli owner nel budget massimo240s/128 chiamate.

Il terminale mostra le cinque storie DB, il confronto completo CLI/API, conteggi
container, binding degli owner selezionati, ID delle route e tutte le aree
indisponibili. Il rapporto integrale conserva anche metadati degli altri container
OUF e hash/nomi plugin delle route. Non vengono stampati nomi di container estranei.

## Come leggere il risultato

`registryObservationChannels.historicalCliMatchAndPreparerApiMismatchObserved=true`
con `stableComparisonUsable=true` conferma sul target la contraddizione di canale;
le differenze strutturali indicano dove nasce. Se le letture sono instabili o
indisponibili, il risultato non viene promosso a confronto valido. Se entrambi
i canali differiscono dallo storico, conservare e analizzare la differenza reale;
non aggiornare lo storico automaticamente.

Rimane `completeEnvironmentInventory=false`: ledger corrente e accesso MCP da
questa conversazione non sono chiusi da questo script; altre letture possono
restare indisponibili. Zero operazioni di lifecycle, mutazioni DB/IAM/servizi,
approvazioni HUMAN, reset dei budget, import del pacchetto o riavvii. Sono attesi
soltanto file di audit/temporanei e processi brevi di lettura.

## Continuità e limiti

L'inventario dell'operatore e la sua valutazione restano immutati al commit
`a3a7c8bfab7711d05a0b668e362e093c559c771b`. La v2 non li sostituisce con dati
sintetici. I sei pin applicativi, archivio1.7GB, PR29, capsula e launcher di
consegna restano invariati. Nessuna esecuzione target è stata effettuata da
questa sessione e nessuna autorità di deploy deriva dalla pubblicazione.

B01 (preflight meno completo del gate finale) resta un difetto noto da correggere
e qualificare nel preparatore dopo la diagnosi; il codice del preparatore non è
modificato da questa tranche. B02 si chiude soltanto con confronto target valido
e causa verificata. B03/B04 richiedono ancora preparazione completa rappresentativa
e integrazione reale di migrazioni/IAM/Gateway/THS. B05/B06 restano primo CSV
Teatri con ACK/commit/lineage/ricerca e secondo-source reuse, preservando Cinema.

Il successivo agente deve leggere l'output v2 prima di produrre un altro comando
di consegna. Non chiedere di rieseguire il vecchio installatore per verificare
questa ipotesi, non rifare upload/profilazione dell'asset Teatri già osservato e
non cambiare microservizi senza un difetto dimostrato e prova di regressione.

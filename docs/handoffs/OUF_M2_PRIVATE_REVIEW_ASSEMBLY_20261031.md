# M2 — Preparazione privata dei quattro owner

31 ottobre 2026, Europe/Rome. Sorgente corrente `7fb1420e`, iniziale `31b344e0`,
PR54 draft/unmerged.
Quindici test locali PASS2.868s e quindici test CI PASS2.624s, senza skip;
log finale PR41177647675/job124468416188 letto.
La capsula CI è stata scaricata e confrontata byte per byte con la ricostruzione
locale. Questa qualifica aggiunge un frammento di preparazione: il parent completo
e l'installazione sul target restano da qualificare.

`private_review.py` riusa DiscoveryProfile, il compilatore frame e il baseline
Engine indipendente già fissato, il piano immagini e il compilatore MCP, più lo
scope del Gateway. Un solo input privato con hash canonico esplicito lega:

- immagini selezionate e hash della richiesta Registry;
- manifest della coorte condiviso e pacchetto MCP;
- workload discovery Registry/MCP;
- contenuto della chiave discovery Registry/Gateway;
- journal distinti, senza sovrapposizioni fra loro o con gli input privati.

Il contesto Registry è un template senza CID, rootfs o namespace presi da un
predecessore. La compilazione strutturale usa un CID sintetico e scarta la policy
risolta. Il risultato conserva template e launch indipendenti; l'owner esistente
dovrà materializzare e attestare il CID reale nella fase corretta. Non viene
inventata una policy nativa prima della creazione.

Il frammento ha uno schema distinto e viene rifiutato da `parent_authority.review_scope`.
Lo scope Gateway è un legame statico: file YAML, credenziali, archivi e generazioni
non sono ammessi come correnti dalla semplice compilazione. Il risultato mantiene
esplicitamente false le attestazioni di autenticità, review completa, ammissione,
integrazione executor, autorità e accettazione E2E.

La capsula incorpora 108 moduli applicativi fissati per hash e il baseline.
Richiede root e `-I -B -S`; gli unici modi sono preparazione e ispezione.
Input0600, output0700, ancestry protetta e apertura senza symlink. Il claim
esclusivo/fsync precede il payload privato; il receipt pubblico viene scritto
per ultimo. Un output parziale rimane parziale: né preparazione ripetuta né
ispezione lo completano. Il binding del compilatore fa parte dell'assembly;
un'altra versione non può adottarlo. Stdlib/interprete e publisher trust devono
ancora essere legati alla review d'installazione; la capsula non li autoapprova.

Solo hash e contatori escono sullo stdout. Chiavi, URL, identità, environment e
path rimangono nel file privato; errori CLI hanno un codice generico senza
eccezioni native. Il packager non emette firme. Il riferimento sorgente del build
CI è il merge commit della PR ed è dichiarato come provenance non autenticata.

Qualifica iniziale PR41175819455/job124463044243:15 test PASS2.117s/0skip,
artefatto13033046169 conservato come storico. Il wrapper corrente include
l'hash del loader nel binding, così anche un loader diverso con identica revisione
dichiarata e identico payload non può adottare l'assembly. Anche argomenti CLI
malformati producono solo il codice pubblico, senza eco su stdout/stderr.
Artefatto corrente13033249318; SHA256 capsula
`dcb00e22c1faf4365457a35d36eac4aed0e28825afcdde3b60d0ba74b332707a`,
1754221byte. Archivio e ricostruzione esatta locale verificati; la revisione
dichiarata corrisponde al merge commit osservato nel checkout CI.
[Registro completo](../../evidence/m2-private-review-assembly-20261031.json).

Il codice runtime precedente e i37pin del worker sono invariati. Il precedente
head9c48c104 ha29workflow verdi,457test/54suite di protocollo,251/33 IAM e505/69
coorte Chatbot, tutti senza skip nelle suite indicate. Le nuove regressioni
generali sono separate e non vengono dichiarate concluse prima dei loro report.

Proseguire con Registry child/HUMAN e componenti provider v2/gate/worker, poi
coorte corrente/TLS/IAM/DB/trust/fencing, pubblicazione governata e Farmacie→UDP
con61esiti. Boot/rotazione/due client e cause UNKNOWN/MCP/worker storiche aperti.
Teatri acquisita; stesso profilo Farmacie SUCCEEDED61righe/10colonne STRING/OPEN.
Nessun target apply, nuovo grant, reset, replay, merge o release acceptance.
Nessun comando operatore pronto per i vecchi scope consumati.


## Arresti della regressione corrente, conservati

Il nuovo codice aggiunge sei file: nessun owner/runtime/qualifier precedente è
modificato. La nuova preparazione supera la propria qualifica; la regressione
nativa generale31b344e0 non è verde. Run41175819397: finite124463043949 PASS;
sealed124463044077 nega la riconciliazione dopo scadenza del mandato v1 iniziale90s,
con worker ancora ACTIVE/RECOVERED,1attempt/1publication. Il limite è rispettato;
non è stato esteso né il processo riavviato per ritentare la prova.

Registry-worker124463044065 arriva a START dopo i tre sottostadi conclusi, ma il
read della pubblicazione restituisce CURRENT_OWNED_DISCOVERY_LEASE_PUBLICATION_REQUIRED.
L'osservazione resta UNKNOWN con startReplayAllowed=false; il worker finale è
ACTIVE/RENEWED,1attempt/3publications. Lo stato esatto del journal durante la
lettura non è nel diagnostico: un conflitto con il rinnovo è un'ipotesi coerente,
non una causa accertata. Nessun nuovo retry/read budget/avvio o rerun per cercare
un verde. Entrambi i log finali sono stati letti. Protocollo generale31b344e0
41175819349/job124463043993 PASS457test/54suite/0fail/0skip, log finale letto.
La successiva correzione controllata del read è registrata separatamente in
[evidenza](../../evidence/m2-publication-read-reconciliation-20261031.json).

## Riconciliazione del read, senza nuovo budget

La sola diagnosi1194b5d3 ha ripassato i tre modi nativi senza riprodurre il
fallimento; questo non ne ha accertato la causa. Tre regressioni controllate
mostrano però una lacuna precisa: uno snapshot valido `LEASE_UPDATING` non usava
il percorso di riconciliazione delle letture già esistente. La correzione27717b20
classifica solo `LEASE_UPDATING` con `leaseAuthorized=false` come lettura occupata,
dopo i controlli dell'owner, dell'inode e delle chiavi attese degli insiemi.
Conserva i tre tentativi e la singola scadenza originali, default15s e attese
0.02/0.04s. Non aggiunge tentativi operativi, DNS, scritture, firme o start.
Esaurimento resta UNKNOWN/READ_CONTENTION; revoca, BLOCKED e altre incoerenze
continuano a negare senza ripetizione. Ogni esito positivo conserva tutti i
controlli originari di membership, ownership, generazione, manager e contatori.

Il job nativo124465760019 ha osservato realmente:

| Punto della lettura | Stato osservato |
| --- | --- |
| Journal prima | LEASE_READY, leaseAuthorized=true |
| Insiemi | Tutte le chiavi attese, entrambe le famiglie positive |
| Journal dopo | LEASE_UPDATING, leaseAuthorized=false |

La stessa osservazione limitata si è riconciliata e la prova completa è passata,
senza secondo start. Tutti e tre i modi nativi41176743013 e IAM251/33/0skip
41176742864 passano, log finali letti. Sedici test locali start/read PASS6.367s.
Il protocollo esteso27717b20 PASS463test/54suite/0fail/0skip837.574s,
PR41176742954/job124465759690, log finale letto. Non viene dedotta
la chiusura degli UNKNOWN storici o del singolo31b344e0.

## Mappa dei sorgenti del packager

Il packager3ab5b6f5 verifica anche l'hash della mappa108moduli tramite una costante
indipendente, SHA42583665…. Una root alternativa con sorgente modificato e mappa
coerentemente aggiornata è negata prima del packaging. Il payload del compilatore
e la capsula qualificata13033046169 restano byte-identici. Quindici test locali
PASS2.626s e CI41177200572/job124467102837 PASS15/0skip2.119s, log letto.
Il successivo wrapper7fb1420e è qualificato separatamente sopra e sostituisce la
capsula iniziale; il payload applicativo108moduli rimane identico.

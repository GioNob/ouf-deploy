# CSV E2E — checkpoint di avanzamento verificato

Checkpoint: 20 ottobre 2026, 15:49:22 Europe/Rome (13:49:22 UTC).
Baseline Mini-PET v1.1 congelata: d190193773116c9a59403aa42ccc9f89423eb959.

## Stato rispetto alla baseline

| Voce | Effettivo verificato | Baseline centrale |
| --- | --- | --- |
| G2, decisione alle14:51:39 italiane | 3.16056 ore attive cumulative; intervallo conservativo3.16056–3.73082h | 14h cumulative |
| Lavoro attivo al checkpoint corrente | circa4.02h, comprendenti attività WP5/WP6 intercalate | Nessun confronto con un gate successivo ancora aperto |
| M1 / F5–F6 | aperto | 24h cumulative (18–30h) |
| M2 / CSV completo | aperto | 55h cumulative (40–70h) |

Le ore sono effort tecnico attivo, non tempo di calendario né ore umane imputate. Gli intervalli non verificabili sono esclusi e conservati nel registro; ultimo intervallo escluso13:25:20–13:28:36 UTC,196secondi. L'allocazione per singolo WP non è ricostruita artificialmente. Il vantaggio al G2 non è una previsione del residuo complessivo. La baseline era già corretta per l'uso di agenti: non applicare una seconda divisione10/20.

## Risultati disponibili

G0/G1/G2 PASS. G2 conserva la qualifica nativa sul source24c2d9b8c7b3f4f8a4a61125b86877ffbd635dba:162 test di componente,3 PostgreSQL,3 piattaforma con sequenza sigillata completa, oltre alle prove negative. Le autorità iniziali HUMAN/Owner nella fixture sono sintetiche; nessuna autorità target deriva dalla CI.

La prova composta CSV tipizzato è PASS sul deploy1d21d4f415481c069e586a4936bebc0ca6583938, run39428578919/job118647330860. Tre fasi JVM reali Onboarding/Ingestion/UDP e PostgreSQL dimostrano due acquisizioni deliberate, un oggetto canonico, una revisione, due osservazioni, decimale/data e RAW/lineage. Semantic e DataLake sono porte sintetiche; ACK/watermark, provider reale e autorizzazione end-to-end restano distinti.

Il nuovo cohort di recupero chat e proposta tipizzata ha tutte le CI verdi:

| Modulo | Commit | Evidenza |
| --- | --- | --- |
| Onboarding, PR49 | 7b04d36fd8462616514cca956fd973c9bd01c1e7 | CI39432864255 PASS;280 test dell'implementazione701ae74,0skip |
| MCP, PR77 | 0a76376a7c6a0f07597c1c3aaf447b29deed597f | CI completa39433193179 PASS; SDK/contratti39433193162 PASS; dispatch obbligatorio39433193465 PASS |
| Gateway, PR82 | c22fbf7f5593f612aba7e318797c9459d0b871a7 | CI39432768839 PASS; precedente recuperoe0eda7e:552 test,3skip |

ASSETS elenca solo file con prova durevole di Ente e utente, prima della paginazione, con limite1–50 e cursore UUID canonico. LATEST risolve la versione dal database owner e ricontrolla la policy corrente sulla versione scelta. Forme esatte precedenti preservate; riferimenti storici non dimostrati non ricevono ownership inferita. Non vengono creati challenge, approvazioni o attivazioni durante la lettura.

La proposta typed-csv:v2 permette esclusivamente XSD string/decimal/date, coerenti con il compiler owner già qualificato e le trasformazioni esplicite Ingestion. RAW rimane lessicale; nessuna coercizione o timezone implicita. Test SDK con due sessioni indipendenti hanno owner TLS sintetico; i test owner PostgreSQL sono separati. Non equivalgono alla prova composta con owner reale e due client rappresentativi richiesta per G6.

## Diagnosi conservate e risolte

- Due errori iniziali di formattazione Go: applicato l'output gofmt esatto della CI.
- Il nuovo test SDK ha dimostrato che format:uuid era solo annotazione: aggiunto pattern canonico esplicito, cursore malformato fermato prima del dispatch.
- Il controllo obbligatorio usava ancora un Gateway precedente, che rifiutava LATEST e datatype nuovi: aggiornato il pin alla versione esatta qualificata, conservando la verifica.
- La prima prova composta CSV falliva per il package Java della fixture: corretto il package senza ampliare la visibilità della produzione.

I risultati falliti restano nel registro. Nessun errore è stato risolto con reset, replay o disabilitazione dei gate.

## Gate aperti e percorso successivo

Tecniche8/8; funzionali4/6. G3–G7, F5/F6, M1/M2 restano aperti.

1. G3: ammissione DB, rollout Ingestion/Gateway e profilo nativo sul CLOUD, usando l'esecutore qualificato e autorità HUMAN/THS corrente.
2. F5/F6: prove funzionali sul runtime ammesso, distinguendo ricezione/ACK dal commit canonico UDP.
3. G5: mapping controllato codice→concetto e relazioni semplici, con autorità Registry sui concetti e Onboarding sui mapping sorgente. La proiezione propertyMappings già funziona; la sola conservazione di vocabularyMappings non prova la loro esecuzione. Non inventare IRI da label né risolvere contro ACTIVE mutabile durante un run.
4. G6: prova composta di ripresa con owner reale e due client, package di review, revoca/scadenza e idempotenza.
5. G7: delta finale, ripetizione controllata dello stesso CSV senza revisione canonica gratuita e accettazione rappresentativa.

## Vincoli CLOUD preservati

Nessuna operazione target è stata eseguita in questo tratto. Nessun login/refresh/reset/estensione finestra, SQL/lifecycle/Gateway target, replay Owner7/pubblicazione7/installazione/readback/preflight o consumo di claim.

Il pacchetto target ad1bdb240483f85785b989f28cd895a72394ea964baabd85ad3062b10180fe5c e i contesti kkj_njiz,0wd4wyuf,qfcpqd9f restano conservati. Il nuovo codice di sviluppo non modifica quel pacchetto e non viene assunto già installato. Eventuali nuove configurazioni richiedono un nuovo cambiamento governato e qualificato, non replay dello staging precedente.

HUMAN storico278/288,10residui, finestra scaduta20 ottobre00:57:44 italiane: nessuna autorità corrente. Gli strumenti OUF esposti sono ancora26; nessuna chiamata protetta o tentativo di autenticazione è stato eseguito. Non è disponibile a questo esecutore un canale qualificato verso il VPS come ouf-admin. Per il passaggio G3 serve l'intervento HUMAN/THS e la disponibilità di quel canale; lo storico e i budget consumati vanno mantenuti.

MAC degli endpoint, indirizzi, percorsi, UID, collocazione e altri dati specifici dell'Ente restano parametri espliciti e validati. Nessun valore osservato nell'installazione corrente diventa un default universale.

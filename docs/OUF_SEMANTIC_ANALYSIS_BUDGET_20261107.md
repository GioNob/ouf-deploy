# Budget dell'analisi semantica proporzionato al lavoro

Aggiornamento del 7 novembre 2026. Requisito: oggetti fino a 1024 colonne, compresi casi SUE da 300–400 campi. Candidato [MCP PR83](https://github.com/GioNob/ouf-mcp-server/pull/83), sorgente `907ace32100d44a0fcf1fcbda5d713ee7bd8fd94`. Il pacchetto è installato sul VPS con migrazione 14 verificata e readiness HTTP 204 ([ricevuta delle 20:26 CET dell'8 novembre](../evidence/mcp-analysis-ready-operator-20261108.json)); i nuovi strumenti restano INACTIVE e l'analisi funzionale resta da provare.

## Implementazione disponibile nel candidato

| Strumento | Comportamento |
| --- | --- |
| `source.analysis.plan` | Legge il profilo posseduto da Onboarding, conserva asset/profilo/versione/hash/conteggio autorevoli e aggiunge attività con revisione attesa. Le aggiunte successive riusano quel profilo immutabile. |
| `source.analysis.read` | Mostra consumi, attività e copertura delle colonne, con pagine da 128 attività e senza esporre i corpi delle risposte nella lista. |
| `source.analysis.step` | Esegue una sola attività tramite autorizzazione/ammissione/Gateway esistenti; conserva risposta e progresso. Un'attività riuscita viene riletta dopo nuova autorizzazione senza ripetere la chiamata. |

Attività ammesse: ricerca e lettura semantica, richiesta/stato/candidati della discovery. Argomenti controllati con gli schemi reali del manifest; nessun URL libero o SPARQL. La discovery rimane INACTIVE e viene rifiutata finché il percorso composto non è attivato.

Il conteggio delle colonne non è un parametro del chatbot. Le colonne delle attività sono ordinali validati sul profilo verificato. L'identità persistente comprende servizio, soggetto, tenant, asset e profilo; nuova chat, correlation ID o riavvio non creano un budget nuovo. Una variazione del profilo o del manifest blocca il riuso.

## Dimensionamento, senza coefficienti inventati

Il lavoro utile disponibile coincide con le attività uniche pianificate. Le durate massime delle singole chiamate e i massimi byte derivano dai contratti delle capacità e vengono sommati. Una ricerca identica riutilizzata da più colonne conta una volta; una nuova verifica necessaria aggiunge lavoro esplicito mantenendo la storia.

Esempio aritmetico: 400 ricerche distinte e 70 letture di riferimenti sono 470 chiamate utili. Se quelle attività coprono 1024 colonne, restano 470; non si moltiplica automaticamente tutto per 1024. Non è un benchmark e non implica che siano sufficienti per un oggetto reale.

Il budget di tempo è la somma degli inviluppi delle chiamate pianificate, non una promessa sul tempo totale dell'analisi. Attese, tempi del provider, approfondimenti e retry restano visibili e distinti. Il primo controllo del profilo è un costo di preparazione ammesso dalla quota pagine, separato dalle attività semantiche.

## Attesa, ripresa e limiti dichiarati

La finestra a 60 letture semantiche/minuto continua a proteggere la dipendenza. Un rifiuto di finestra prima dell'invio diventa WAITING con `notBefore`, senza chiamata al proprietario e senza consumo di un retry dell'attività. Le altre quote, i controlli di query equivalenti e la capacità dei comandi non sono aggirati.

Per READ con HTTP 429/503: attesa progressiva 5/15/60/300/900 secondi, jitter positivo fino al 20%, rispetto di Retry-After e massimo persistito di 128 tentativi/24 ore per attività. I guard preesistenti possono fermare prima. Errori ignoti, comandi ambigui e processi interrotti dopo la prenotazione restano HELD: nessun replay alla cieca.

La ripresa avviene chiamando nuovamente `step` con un'identità attualmente autorizzata. Non è uno scheduler in background; nessun token delegato viene salvato. Una prenotazione transazionale impedisce doppie esecuzioni e risultati tardivi. Nessun lock viene mantenuto durante una chiamata remota o un'attesa.

Limiti di capacità espliciti: 16.384 attività uniche per analisi, 128 per aggiunta/pagina, 8 KiB di argomenti in ingresso per attività (più la chiave server per la discovery), 256 KiB per risposta e 64 MiB di risposte contabilizzate per analisi, comprese le prenotazioni in corso. Esaurimento conservato e visibile, senza cancellazioni automatiche. Sono protezioni finite; la loro saturazione completa e il carico concorrente multiutente sul VPS non sono qualificati dalle prove a 1024 attività.

## Discovery delle proprietà delle colonne

Il flusso resta: ricerca di riferimenti OUF pubblicati → lettura esatta → eventuale discovery esterna PROPERTY/RELATIONSHIP con contesto → verifica dei candidati → normale adozione/validazione/pubblicazione.

Per `tipologia` si cerca la proprietà che esprime quel significato nel contesto dell'oggetto, verificando definizione, dominio e range. Un'etichetta uguale o un vocabolario di valori non dimostrano equivalenza della proprietà. URI assenti o corrispondenze ambigue restano irrisolti, senza inventare riferimenti.

La richiesta di discovery ha una chiave stabile generata dal coordinatore. Gli aggiornamenti di stato sono attività esplicite numerate, sequenziali e distanziate almeno 31 secondi. Un HTTP riuscito con stato PENDING non chiude la discovery. `columnsWithCompletedPlannedWork` indica soltanto chiamate pianificate terminate: non dichiara mapping corretto, pubblicazione o classificazione OPEN.

Le risposte conservate sono evidenza storica con data: prima dell'adozione va verificato lo stato corrente presso il proprietario. Nessuna nuova associazione OntoPiA alle colonne Teatri è stata attestata in questo intervento.

## Prove e prossime azioni

[Evidenza del candidato e CI](../evidence/profile-analysis-discovery-20261107.json). Prove native Go/race, SDK MCP e PostgreSQL: 20/50/100/200/300/400/1024 colonne; otto blocchi a 1024 attività con una sola lettura autorevole; deduplicazione, riconnessione, autorizzazione revocata, fencing, rifiuto della 61ª lettura, attesa dopo 503, storia retry e capacità delle risposte in corso. I servizi remoti delle prove di coordinamento sono fixture: non equivalgono a un test del provider OntoPiA o del VPS.

Ordine residuo:

1. Gateway applicato e verificato; Semantic c2dae77b è pronto con V12 dopo la correzione della chiave. MCP PR83 è installato con migrazione 14 verificata e readiness 204: [ricevuta](../evidence/mcp-analysis-ready-operator-20261108.json). Prossimo passo la [lettura Onboarding](OUF_ONBOARDING_WIDE_PREFLIGHT_20261108.md), poi i candidati 1024 degli altri moduli, conservando i binding SeaweedFS. Non distribuire PR82 da solo come soluzione dinamica.
2. Verificare sul target provider/worker, pubblicazione delle capacità e grant correnti. La connessione non espone discovery; una lettura del catalogo CAPABILITIES ha restituito HTTP 400, quindi i grant attuali non sono stati verificati e la causa non è attribuita.
3. Prima discovery reale di proprietà sul profilo Teatri conservato; motivare associazioni e irrisolti per ogni colonna.
4. Bozza/review THS e Ingestion→UDP→grafo; normale operazione lake su SeaweedFS e seconda esecuzione riuscita.

F1 rimane acquisito; F2–F6 sono aperti. Non ripetere upload, profilazione, pubblicazione Teatri o ripristino del produttore token. OPEN vale per Teatri, non automaticamente per SUE. Nessun DR/RPO/RTO aggiunto.

La precedente correzione della sola finestra e le sue prove restano nello [storico](../evidence/semantic-analysis-budget-review-20261107.json). [Descrizione tecnica del candidato](https://github.com/GioNob/ouf-mcp-server/blob/907ace32100d44a0fcf1fcbda5d713ee7bd8fd94/docs/PROFILE_ANALYSIS_20261107.md).

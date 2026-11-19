# M2 — Riutilizzare Teatri per il flusso completo; Farmacie è il caso corrente

30 ottobre 2026, Europe/Rome. Questo è il checkpoint dell'incremento PR54.
La continuazione di progetto resta [CSV E2E](https://github.com/GioNob/ouf-deploy/blob/fix/registry-bound-owner-lineage-20261023/docs/handoffs/OUF_CSV_E2E_CONTINUATION_20261029.md).

## Obiettivo e stato da conservare

L'owner ribadisce che Teatri è stata completata a passi singoli: se ne riusano
componenti e prove per un flusso completo, ripetibile e resiliente per ogni file.
M1/G4, tecnico8/8 e funzionale6/6 restano acquisiti per quel caso; non sono
accettazione del percorso generale M2. Non eseguire una terza acquisizione Teatri.

Farmacie è la prova corrente: stesso asset/job/profilo SUCCEEDED,61righe/10colonne;
codice ministeriale STRING e10campi OPEN già confermati. Non ricominciare upload,
profiling o decisioni di dominio per superare un blocco installativo.

| Passaggio ordinario | Riuso | Residuo da dimostrare nella composizione |
| --- | --- | --- |
| Upload e profiling | Asset gestito e job owner durevole; Farmacie già completata | Ripresa del lavoro senza dipendere dalla memoria della chat |
| Proposta/onboarding | Compiler, tipi e regole esistenti | Proposta consolidata per tutte le colonne e review attuale |
| Semantica locale | semantic.search/get e publication pin | Riferimenti esatti adeguati, senza significati inventati |
| Eventuale OntoPiA | Registry/provider/Gateway/MCP già composti nei candidati | Capability stabilmente pubblicate, discovery reale, adozione e HUMAN |
| Configurazione fonte | Versione/hash, validazione e THS owner | Attivazione esplicita e una sola identità logica dell'intento |
| Ingestion | Bundle pinned, trasformazioni, outbox, ACK e watermark esistenti | Esecuzione di Farmacie con progresso recuperabile |
| UDP/grafo | MATCH/NEW/REVIEW, riconciliazione, contributi e lineage già provati | Esiti di tutte61righe e lettura owner della materializzazione |

Search sugli oggetti è una capability successiva e separata dal caricamento.
La futura E2E verticali/API con scheduler e delta segue il completamento di questo
percorso file. Nessun motore parallelo o pipeline riscritta da zero.

## Incremento eseguito

Il test della risposta persa richiede ora l'esatto errore del trasporto Engine e
verifica dispatch, consumo dell'ACK simulato e stadio CLAIMED prima della ripresa.
Un errore precedente di autorità/journal non può soddisfare quell'asserzione.

La nuova qualifica nativa usa Docker29.8.1/Engine, firmeEd25519, file e journal,
GET HTTP e clock monotonic reali. Dopo un avvio reale con risposta persa,
ricostruisce l'owner, riconcilia senza un secondo avvio e conserva montaggi e
restart policy. La variante successiva restituisce davvero503/Retry-After poi204:
durante il backoff persistito vieta nuovi GET di health e lifecycle; ricostruisce
ancora l'owner e conserva start originale e tentativi cumulativi.

Initiale `d4410db9`: push41123284685/job124295154220 e
PR41123296106/job124295188395 PASS, entrambi report finali letti.
Successore `dc16fa46`: PR41123610248/job124296342265 e
push41123600168/job124296302282 PASS, entrambi report finali letti.
Suite completa `d4410db9`:391test/46suite per evento, zero skip;
push41123284691/job124295154658 e PR41123296096/job124295188542 PASS,
entrambi report finali letti. Stessi sorgenti protocollo nel successore nativo.
[Evidenza e limiti](../../evidence/m2-discovery-mcp-native-qualified-20261030.json).

L'applicazione del fixture è un serverHTTP statico; pacchetti, parent/HUMAN e
ammissione Registry sono sintetici. Questo prova il componente di installazione,
non il vero binario MCP, la coorte completa, pubblicazione capability o CSV→UDP.
Il primo errore locale MCP_INVOKING_RECORD_DRIFT rimane senza causa dimostrata;
un rerun mirato PASS non è una risoluzione causale. La suite locale successiva
finisce13test/1errore DETACHED_VERIFICATION_UNPROVEN durante un fixture,207.590s:
nessuna causa dimostrata e nessun PASS locale completo dichiarato. Nessuna guardia
indebolita.

## Prossimo lavoro e confini

Comporre le prove native provider/worker e gli owner Registry/MCP/Gateway con la
coorte corrente, TLS/IAM/DB/fencing/trust, compilatore/review privata e CLI
sigillati. Poi manutenzione qualificata una volta e pubblicazione coordinata,
discovery reale Farmacie, mapping pinned, Ingestion/UDP e rendiconto per riga.
Ripetizione invariata, fault/ripresa/cambio chat, boot/rotazione e due client
rimangono da qualificare al livello richiesto.

M2/G5–G7,24AT,8UX e8stabilità restano OPEN. Non c'è un nuovo comando operatore
pronto: i precedenti scope/input sono consumati. Nessun effetto target, grant,
nuova authority, reset/replay, merge o accettazione finale è dedotto dalla CI.

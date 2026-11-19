# OUF — M2: discovery OntoPiA governata, composizione MCP qualificata

28 ottobre 2026, Europe/Rome. [Evidenza](../../evidence/farmacie-domain-and-ontopia-discovery-20261028.json), [PR MCP81](https://github.com/GioNob/ouf-mcp-server/pull/81), [miniPET M2 v1.2](../OUF_M2_MINIPET_v1_0_20261026.md).

## Scelte di dominio acquisite

L'utente conferma codice_ministeriale come identificativo stabile della fonte, conservato stringa, e tutti i dieci campi inclusi con classificazione OPEN. Ha richiesto espressamente discovery di un'ontologia adatta in OntoPiA attraverso le capability OUF. Il percorso obbligatorio è chatbot → MCP OUF → Gateway → Registry → provider OntoPiA/schema.gov.it. Non sostituire questo passaggio con web research/manual import o una nuova ontologia locale inventata.

La scelta OPEN non autorizza ad aggirare le redazioni delle API o a esporre vecchi dati tramite canali alternativi. Le label della futura configurazione passano ancora attraverso la review owner/HUMAN.

## Impedimento osservato e lavoro completato

Gli strumenti disponibili nella connessione e il manifest della sorgente MCP installata d2454f3c non contengono discovery.request/status/candidates. semantic.search consulta solo il catalogo pubblicato: le sue risposte vuote precedenti non sono una ricerca nazionale.

Esiste già l'implementazione candidata, riusata senza riscrittura:
- MCP discovery candidate0debc57fd1e4531072fa479d845d83fecf40259d.
- Gateway PR57/sourceace683b1019f79adaace86796b67e463b93ec12e.
- Registry discovery durevole/source3ec99277b8383e496913b9fd3bb05c877825abf5.

PR81 compone i soli tre descrittori INACTIVE, le tre route Gateway fisse e i test SDK sul codice M2 corrente. Preserva le capability esistenti e le route proposal/review/revision/file recovery. maxDistinctObjects100 solo per i nuovi candidati; maxResultBytes262144 e input chiusi. Request COMMAND con idempotencyKey stabile; status/candidates READ sul requestId. Nessun endpoint libero, query arbitraria, accesso diretto al provider o approvazione aggiunti.

## Qualifica realmente eseguita

Commit `09d1f521703f2e896398c751b41008f22c6dca0d`. Workflow push40783225346/job123149874207 e PR40783229870/job123149892054 entrambi SUCCESS. Job mirato:9 test principali,0errori/0skip,go test-race; dispatch su vere sessioni MCP SDK, cache autorizzativa reale, client HTTPS e schemi del Gateway fissato. Le risposte Gateway sono fixture sintetiche: non è una queryOntoPiA né una prova del Registry installato o del jobdurabile.

Letture dirette dei log di5job:discovery/schema/semantic proposal/CSV recovery/source revision. Le relative regressioni passano. Il package httpclient non aveva test separati selezionati dal filtro; il suo trasporto è esercitato dai test kernel. Non espandere la dichiarazione di conformità oltre queste prove.

## Blocco residuo e prossimo tratto tecnico

1. Comporre e qualificare l'owner Registry e il Gateway correnti con la discovery durevole già esistente, preservando i percorsi file già funzionanti.
2. Acquisire tramite il percorso autorizzato di manutenzione una prova corrente e bounded di generazioni, configurazione provider, Gateway routes, workload identity/secretRef/custody/TLS, rete e ammissione DB. Le catture di ottobre7–11 sono storiche; non costituiscono autorità né vanno rilanciate.
3. Qualificare il delta effettivamente necessario e preparare la review concreta con nuova authority finita, se occorre manutenzione. Nessun restart/reinstall del Registry o riapertura implicita dei worker/R9-R12/budget consumati.
4. Verificare policy, scope e grant correnti; pubblicare coordinatamente i descrittori solo quando l'installazione è pronta. Nessuna pubblicazione è stata effettuata da PR81.
5. Con la capability effettivamente esposta, creare UNA discovery CLASS/ONTOLOGY Farmacie su provider nazionale, preservare l'idempotencyKey, leggere lo stesso requestId/stato/candidati e distinguere FAILED da vuoto. Conservare canonicalURI/provenienza/snapshot/revisione dei candidati.
6. Confrontare candidati reali; poi lifecycle di adozione, validazione, review e pubblicazione HUMAN. Solo riferimenti esatti pubblicati possono entrare nell'onboarding Farmacie.

Questa nuova richiesta di dominio non conferisce all'agent authority per attivare container o approvare una review HUMAN. Source preparation e qualifica rimangono autorizzate. Non esiste ancora un comando runtime pronto da consegnare.

## Lavoro conservato

Stesso asset9c502da5-b5d8-405e-b3f5-60eb31ecb513, job677480c8-3d10-44fd-9dad-f72ddeed20a4 SUCCEEDED, profilof3061699-4fde-4085-89c8-bc8703f65686 con61righe/10colonne. Policy59 e preview già acquisite. Nessun nuovo upload, profiling, budget, resume o acquisizione. M1/G4 preservati; M2/G5/G6/G7, compiler vocab/relazioni D5, tutte le righeUDP, ripetibilità/fault/dueclient e dossier ancora aperti. Nessun merge o release acceptance.

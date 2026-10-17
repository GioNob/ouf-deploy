# CSV — tappa funzionale 3: rendiconto delle13righe
17 ottobre2026 · tecniche8/8, funzionali2/6

La tappa3 storica richiede13commit effettivi UDP con provenienza. La scelta dell'utente di mantenere un caso in quarantena resta conservata: un rendiconto12commit+1eccezione può essere completo, ma non modifica silenziosamente quel criterio.

## Riscontro corrente dalla chat

source.onboarding.read, account ouf-admin, conferma fonte teatri-csv-6609b245 e versione9860853e-e8f3-4b93-b9d2-03521a039962 ACTIVE, configurazione e pubblicazione immutate. urban.object.search per il tipo canonico pubblicato restituisce12ID distinti ACTIVE, revisione1, pagina completa. Ritrovato anche l'oggetto originario d6051381-934b-4a11-8e71-e1d89cee4e49.

La ricerca espone properties vuoto per ogni oggetto e nessuna provenienza. Questo non prova assenza dei dati: la proiezione è autorizzata per proprietà e la causa concreta dell'omissione non è ancora provata. Neppure il conteggio12 dimostra da solo l'appartenenza di ogni oggetto alla fonte Teatri. ingestion.status rifiuta la lettura, non ripetuta; permissions.read non supera lo schema del connettore e non legge grant. [Evidenza minimizzata](../evidence/csv-functional-stage3-chat-readback-20261017.json).

## Lettura puntuale riusata

Si estende scripts/read-teatri-post-resolution-materialization-20261017.py, preservando il controllo della ricevuta delle11decisioni. Il trasporto e i controlli di custodia/generazione provengono dal lettore post-rollout già qualificato: contesto linked-property-execution-cjecd1en, journal55, UDP35 e helper root esatto.

La diagnosi è specifica dell'installazione e della fixture; nessuna regola di prodotto specifica per Teatri. Due transazioni READ ONLY con rollback e timeout, nessuna lettura di token o valori di proprietà:
- Ingestion: run conservata, handoff, ACK e legame al lineage;
- UDP: tutte13le righe visibili nel tenant, job, source binding, revisione/osservazione verificata, numero di contributi e issue aperte;
- confronto degli ID handoff fra i due registri, senza interpretare il campo envelope ingestion_run_id come un UUID di run;
- rendiconto completo, commit13/13, eccezione e11decisioni sono condizioni distinte.

Le righe sono identificate dall'handoff durevole: l'ordine tecnico dell'elenco non è presentato come numero di riga CSV. Nessuna riacquisizione, decisione o ripresa job. La sola quarantena aperta non viene attribuita a una nuova decisione HUMAN.

## Esecuzione e prove

Il workflow csv-functional-stage3-read.yml esegue prima le prove su PostgreSQL17 e i controesempi. Solo dopo usa il runner VPS già esistente e un tentativo di sudo non interattivo, con hash dei byte verificato prima dell'esecuzione root. Non cambia permessi, non apre login e non cerca trasporti alternativi se l'accesso è negato.

Risultati aggiornati nella sezione seguente; i test non sostituiscono il readback del VPS. Il contatore funzionale resta2/6 finché il criterio storico non è soddisfatto o rivisto esplicitamente.

## Qualifica conclusa e limite di trasporto accertato

[CI39072444327](https://github.com/GioNob/ouf-deploy/actions/runs/39072444327), job117512659326: **9test PASS,0skip**. Il test PostgreSQL17 esegue entrambe le query e verifica anche ACK assente, lineage mancante, revisione mancante, job duplicato, isolamento tenant e omissione dei valori. Il launcher supera il controllo sintattico. La prima fixture è stata corretta aggiungendo il campo source_id della contribution; nessuna modifica di semantica del reader per superare il test.

Il tentativo sul runner in [CI39072364964](https://github.com/GioNob/ouf-deploy/actions/runs/39072364964), job117512471194, termina con **sudo: a password is required**. Il lettore root non viene eseguito:0sessioni SQL e0mutazioni target. Questo è un limite accertato del trasporto non interattivo, non una richiesta di ulteriore consenso utente. Nessun tentativo automatico successivo: il job target è disabilitato dopo il rifiuto.

La consegna è un solo launcher da eseguire come oufadmin nella sessione VPS già usata. Riusa il client GitHub portabile e l'autenticazione già presenti, scarica i byte prima di sudo e verifica SHA256 sia nel download sia nel processo privilegiato. Non richiede OAuth o un worker temporaneo. Non stampa né richiede token.

| Artefatto | Commit immutabile | SHA256 |
| --- | --- | --- |
| Lettore | 19f7da2cee7d4367181feb8b7fbb95eafa600306 | a026c82c257e1929677976484760ba669eb94c64fb8f7e84075cdbd3ecac7730 |
| Launcher | ca119dc9292cbf2e127da9e96d5245d1c44fccaa | 777c102bb313a984f85b04ff9c169d0dbe5852240dac5484f3ffeff7d53e83ee |

[Evidenza di qualifica e blocco di trasporto](../evidence/csv-functional-stage3-reader-qualified-20261017.json). Dopo l'esecuzione servono i record ACQUISITION_DATABASE e END: solo quelli possono completare il rendiconto corrente delle13righe. complete=true significa lettura terminata; readbackProven, expectedCurrentDispositionProven e allThirteenMaterializedProven hanno significati distinti. Il contatore resta2/6; nessuna ridefinizione tacita della tappa3.

## Readback VPS ricevuto: rendiconto e provenienza verificati

L'operatore ha eseguito il launcher qualificato e fornito i record BEGIN, ROLLOUT_READBACK, ACQUISITION_DATABASE(Ingestion/UDP) ed END. Il risultato supera il limite di trasporto del runner per questa lettura: non occorre ripeterla. [Evidenza target normalizzata](../evidence/csv-functional-stage3-target-readback-20261017.json).

| Controllo | Risultato |
| --- | --- |
| Generazioni applicative e contesto rollout | Coerenti, journal55; UDP35 checksum -376865285 |
| Run Ingestion conservata | Una run SUCCEEDED,13tentativi,0fallimenti |
| Handoff e lineage | 13ACKED,13ricevute,13lineage verificati; gli stessi13handoff presenti in UDP |
| Materializzazione | 12job SUCCEEDED,12binding/oggetti distinti,12osservazioni con revisione verificata |
| Proprietà persistite | 20contributi per ogni oggetto materializzato;240totali derivati dal rendiconto |
| Decisioni CREATE_NEW | 11decisioni consumate,11oggetti distinti con revisione e contributi verificati |
| Oggetto precedente alle11decisioni | d6051381-934b-4a11-8e71-e1d89cee4e49 conservato |
| Quarantena | Un handoff DURABLE, job QUARANTINED, una issue OPEN, nessun binding/contributo; escluso dal pacchetto confermato |
| Confronto con ricerca MCP | Gli ID dei12oggetti coincidono esattamente con quelli della ricerca precedente |
| Schedule | DISABLED, triggerOnce=true, pubblicazione1 già consumata,0failure e activationBlocked=false |
| Esito del lettore | complete=true,readbackProven=true,allRowsAccounted=true,upstreamHandoffsAndLineageMatch=true |
| Effetti | 0mutazioni,0retry job,0pubblicazioni,0grant,0OAuth |

La schedule disabilitata è coerente con il consumo della pubblicazione MANAGED corrente; non è un hold preventivo già qualificato per una nuova pubblicazione.

### Rendiconto per handoff

Questo elenco segue l'ordine degli ID tecnici, non l'ordine delle righe del CSV. I lineage completi sono conservati nell'evidenza JSON. Nessun valore di proprietà è pubblicato qui.

| Handoff | Oggetto UDP | Esito | Contributi |
| --- | --- | --- | --- |
| 0aab7d69-624e-4d76-853c-ce3fbc778255 | 63d4fde8-044f-4f36-9db0-86debe078973 | SUCCEEDED | 20 |
| 0aff252f-f9a6-46eb-9149-d64219030cc9 | d6051381-934b-4a11-8e71-e1d89cee4e49 | SUCCEEDED | 20 |
| 387f2a31-444c-4f80-b724-026cdeb7a296 | 2606bba6-2799-4275-833e-00cf10f7e03b | SUCCEEDED | 20 |
| 54ca77cc-165e-4b17-9e63-412f57ad0b34 | f4f18054-8b90-48be-b355-c8358a2d019d | SUCCEEDED | 20 |
| 62ddbb50-a5e1-4720-a628-5a9d55d56ce3 | 3db3a213-05f2-4817-a643-475cf7b3868b | SUCCEEDED | 20 |
| 77327abb-c7ec-4427-9b50-aa70515c4b42 | 76d5d321-6585-4c8a-92a0-588bf691a0cd | SUCCEEDED | 20 |
| 7e1c39ab-6733-4a4b-9229-9869158ab9e4 | ec6897bf-74e2-4534-94e0-3fff1204c250 | SUCCEEDED | 20 |
| 9fde61f1-8d3c-4de7-b3fe-b534b32e45e3 | — | QUARANTINED | 0 |
| a82a4173-132d-4baa-a538-3705c8db535a | 43d6d5c7-1b01-4fbb-9ec0-a7575399981a | SUCCEEDED | 20 |
| b09a9644-0ee6-4218-be30-3e4949b9aa38 | c2f83340-bf65-44f1-803b-347ae1246e5d | SUCCEEDED | 20 |
| b3176149-cddb-4e44-a594-fdf99c89bda2 | fe0f7632-96bb-4fc7-8641-5dca487f1c75 | SUCCEEDED | 20 |
| e9709c11-b8e4-46ee-b09f-ab42667299e5 | 535ea2cc-163a-49f0-94f0-1797dc31e521 | SUCCEEDED | 20 |
| ea3f1144-e1db-47c5-965b-157232168062 | 96aa4cb9-c51c-4316-8c9e-472c11c8e302 | SUCCEEDED | 20 |

L'eccezione è l'handoff9fde61f1-8d3c-4de7-b3fe-b534b32e45e3, lineage419ec184-7116-4ce8-b57c-6106938c65fb. Il codice del job è UDP_RESOLUTION_REVIEW_REQUIRED; la issue resta UNRESOLVED_IDENTITY/OPEN. La volontà di lasciarla in quarantena proviene dalla conversazione, non da una nuova decisione HUMAN creata dal lettore.

### Significato dell'avanzamento

**Verifica della tappa3 conclusa per l'esito scelto:12commit+1eccezione, tutte13le righe rendicontate e tracciate.** Il criterio storico13commit rimane aperto: allThirteenMaterializedProven=false,historicalCriterionChanged=false. Contatore formale ancora funzionali2/6, con tappa3 documentata come “rendiconto verificato con eccezione conservata”. Non richiedere un altro import o una decisione sulla quarantena per ripetere questa prova.

L'attivazione del profilo proprietà rimane un gate distinto: profileActivationProven=false e nessuna pubblicazione è stata eseguita. Il readback dimostra contributi persistiti; non risolve da solo la ricerca che restituisce properties vuoto. Il prossimo controllo funzionale è la tappa4: completare il riscontro dal chatbot sui dati autorizzati, riusando i12ID già ottenuti e questa provenienza.

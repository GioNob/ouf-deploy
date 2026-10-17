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

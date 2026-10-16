# Fase 2/8: identità del container di migrazione MCP

Roadmap stabile: [8 fasi tecniche e 6 tappe funzionali](../docs/CHATBOT_CSV_ROADMAP.md). Stato: fase 2 sospesa, CSV 0/6. Questo pacchetto diagnostico non riprende il delivery e non accetta il rilascio.

## Problema riprodotto

Sorgente diagnostico `adaa828255be7437a06b405db759c891343cd6a0`; CI [38837043139](https://github.com/GioNob/ouf-deploy/actions/runs/38837043139), job `116768385629`, tutti gli step conclusi con successo. Otto test unitari coprono fixture completa, redazione, drift degli archivi, mutazioni concorrenti dei record, identità DB e valori inattesi. La query completa è stata eseguita con transazione read-only e timeout su PostgreSQL 17 reale.

La CI ha scaricato l'artefatto MCP originale `11906464158` senza ricostruirlo: ZIP SHA256 `554d04fc354cf48b56b32914ed0e63def8cca100606e24a8a5f62f7ee8c69208`, sorgente modulo `f249b3dcc58c2a96742092d90fa09fd90b705bd0`, config image ID `sha256:e8538c64407757396b13da8e586507900cf126030ce4f25aafd8a5b7de6d60e5`. Su Docker 29.8.1/containerd l'ID nativo è `sha256:4dfefd95c88048b86cc13006bca1b0dbfd173feed12e0e1e32f35691f593eaeb`.

La richiesta equivalente di migrazione, con URL DB sintetico, produce un container `created`, PID 0, mai avviato. Il vecchio predicato fallisce esattamente su `Config.Env` e `Config.Labels`; entrambe le proiezioni coincidono con i default dell'immagine integrati dalla richiesta. Gli altri confronti del vecchio predicato passano, incluso `NetworkID`. Nessun default arbitrario è stato accettato e nessun predicato runtime è stato modificato in questa consegna.

La precedente CI del delivery non aveva coperto questo round-trip create/inspect dell'immagine MCP reale: il successo dei test con engine simulato non garantiva il comportamento Docker osservato qui.

## Lettura target necessaria

`scripts/read-chatbot-mcp-migration-state-20261016.py` è vincolato al contesto della revisione `225d317b485939ebf2a5b2582d0f5168a5ff6fe19be17e0e68109c9003dade1c`, autorità `ce4fcdc3b0af1aaee503582f00af4beed06786641d15afe4a55efa0cd29584d7`. Verifica custody root, hash della revisione/autorità/bundle, sorgente, arresto del processo delivery, journal DB e intent della migrazione.

Legge e ricontrolla i quattro archivi completi, i journal correnti, i conteggi del nuovo worker, lo stato del container di migrazione e i confronti booleani del predicato. Rilegge OID/storia migrazioni/ruolo audit/privilegi temporanei/proprietario e ACL preservata di security_incident con SELECT amministrativa locale. Non stampa ambiente, URL DB, contenuti dei file, etichette o stderr. Non legge credenziali dedicate o chiavi. Il bundle e l'inspect possono contenere valori privati: restano in memoria, senza stampa.

Massimo 180 secondi complessivi; GET Docker bounded; SELECT con statement timeout 10 s, lock timeout 3 s e timeout remoto 15 s. Zero dump, grant IAM, migrazioni, start/stop, modifiche ai servizi, ripristini, autorità emessa o aggiornamenti ai journal. Usa solo una directory privata temporanea del reader/config Docker e il log diagnostico. Nessun retry automatico. Il lettore osserva i privilegi, non li revoca.

`scripts/launch-chatbot-mcp-migration-state-20261016.sh` usa prima il client gh portatile già presente sul VPS, controlla il reader per SHA256, lo ricopia da descrittore verificato in custody root e lo esegue in Python isolato. Non eseguire direttamente il programma CI: esso crea fixture solo su runner GitHub usa e getta e non è una procedura VPS.

## Ripresa dopo la diagnosi

Prima di ogni effetto distinguere il claim creato dall'avvio e dalla storia DB realmente osservati. Confermare tutti i backup, contatori cumulativi e privilegi rimasti; conservare i dieci effetti Registry e il claim originale. Il numero cumulativo precedente era 5, quello nuovo va letto, non supposto.

La futura correzione deve confrontare i valori finali attesi ricavati esclusivamente dall'immagine e dalla richiesta verificate, preservando la verifica dei valori richiesti e rifiutando extra non spiegati. Il vecchio intent non può essere riscritto né il create ripetuto. Un eventuale start del container creato va trattato come prosecuzione governata esplicita, non come replay automatico del vecchio launcher. Servono nuova verifica completa, autorità valida e la revisione HUMAN richiesta dal piano concreto; nessuna estensione della vecchia finestra.

La fase 2 termina solo con storia migrazioni esatta e revoca verificata dei privilegi temporanei, preservando proprietario e privilegi preesistenti. Fasi 3–8 e dimostrazione CSV rimangono aperte.

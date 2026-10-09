# Regole operative obbligatorie OUF

Aggiornate su istruzione esplicita dell'utente l'8 ottobre 2026.

1. Ogni script o procedura deve includere l'analisi dell'eventuale errore: fase, motivo concreto, differenze rilevanti e posizione delle evidenze conservate. Un solo messaggio generico BLOCKED non è una diagnosi sufficiente. Non stampare segreti o contenuti privati per diagnosticare.
2. Eliminare controlli ridondanti, verifiche delle verifiche e ripetizioni prive di una ragione concreta. Eseguire solo i controlli necessari al cambiamento. Procedere con l'azione autorizzata e diagnosticare gli errori nello stesso flusso.
3. Non far ripetere all'utente preparazioni, trasferimenti, installazioni o prove già completati. Riprendere dagli snapshot esistenti; se serve un nuovo intervento, spiegare il motivo concreto.
4. Proseguire autonomamente oltre le milestone; fermarsi soltanto quando serve davvero l'intervento dell'utente. Durante il lavoro inviare aggiornamenti almeno una volta al minuto.
5. Obiettivo: file → onboarding e semantica assistita dal chatbot → approvazione umana → ingestion con controlli di duplicati/merge → UDP e lettura via chatbot/MCP. Non perdere questo obiettivo in attività infrastrutturali senza rendere chiaro quale blocco risolvono.
6. Non dichiarare completamento o prova sul VPS a partire dalla sola CI. Distinguere ciò che è stato osservato in CI da ciò che è stato osservato nell'ambiente reale.
7. Sul VPS `gh` può essere assente dal PATH: l'installazione già documentata è `$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh`. Risolvere l'eseguibile esistente e invocarlo esplicitamente sia nel blocco esterno sia nei launcher interni; verificarne l'eseguibilità prima del download. Non riproporre `gh` nudo, non reinstallarlo e non richiedere una nuova approvazione target per correggere questo solo problema di consegna. Coprire nei test il caso reale di CLI disponibile fuori dal PATH.

Le prime due regole sono state richieste testualmente dall'utente: «d'ora in poi metti sempre dentro l'eventuale analisi dell'errore» e «la smetti di fare trecento controlli dei controlli della verifica». Sono vincolanti per il prosieguo e per i futuri handoff.

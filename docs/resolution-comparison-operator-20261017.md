# Resolution: confronto e selezione dei casi

Per ogni caso la tabella usa le stesse colonne per il record in ingresso e per l’oggetto candidato selezionato. Il cambio di candidato aggiorna la seconda riga; i dettagli JSON restano consultabili. Le differenze sono evidenziate. Riferimenti e revisioni distinguono la riga sorgente dall’oggetto già presente in UDP.

“Lascia in quarantena” esclude il caso dall’invio corrente. Non registra una decisione e non modifica il caso: resta OPEN e il lavoro resta QUARANTINED. La scelta della casella è locale alla pagina; dopo averla riaperta, ricontrollare la selezione. La conferma applica atomicamente i soli casi inclusi e verificati. Se tutti i casi sono esclusi, la conferma è disabilitata.

I valori visualizzati e la revisione del candidato entrano nell’hash di revisione del caso. Una modifica dei casi esclusi non blocca i casi inclusi; una modifica dei dati selezionati richiede di aggiornare e rivedere. Nessuna ripetizione automatica dell’invio.

L’aggiornamento sostituisce prima UDP, poi Onboarding e conserva i vecchi container. Non applica decisioni, non modifica Gateway, grant o schema e non avvia un worker policy. Le prove CI includono 219 test UDP (2 skip preesistenti), 4 test browser senza skip e 24 test del rollout senza skip, compreso Docker reale. Il risultato del VPS e la verifica dell’operatore restano distinti dalle prove CI.

Tecniche 8/8; funzionali 2/6. La materializzazione completa non è ancora provata.

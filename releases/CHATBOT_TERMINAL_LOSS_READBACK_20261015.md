# Recupero dopo perdita del terminale — 15 ottobre 2026

L'operatore riferisce che l'approvazione del nuovo prompt è stata accettata e che l'esecuzione è avanzata, poi è rimasta senza nuovo output visibile. Dopo circa venti minuti di assenza il terminale sul telefono è stato resettato. Mancano ricevuta di avvio, unità e ultimo stato: esito operativo sconosciuto. L'approvazione accettata da sola non dimostra l'avvio o il completamento.

Non rilanciare il comando di applicazione. Il sorgente6959b1d avvia una unità systemd transiente con Restart=no e RuntimeMaxSec entro la scadenza del mandato. Il terminale si limita a osservare; se il processo è stato avviato, la perdita del terminale non è una prova che sia terminato. La durata massima rimane un'ora dalla decisione.

Il lettore scripts/read-chatbot-finite-action-status-20261015.py osserva al massimo tre contesti firmati recenti: binding della review, tempi della decisione, proprietà selezionate systemd, delivery-status.json e fino a venti record pubblici selezionati tra gli ultimi mille del journal. Non legge chiavi, token, password o sorgenti CSV; non stampa la review privata o il journal grezzo. Legge review e decisione private solo per estrarre i campi selezionati. Nessun riavvio, replay, rinnovo o mutazione applicativa viene eseguito.

SHA256 del lettore:12abb896993748b10377ee7babdb9afd8703ea51adc0b473c51d27c1201288f6. Verifica locale: fixture temporanea con stato conservato, mandato scaduto, osservazione systemd, filtro journal ed esclusione di valori privati. Non è una prova sul VPS.

Esito del target da acquisire dall'operatore. La baseline e l'accettazione CSV rimangono ai livelli già documentati fino a tale acquisizione.

# Stato corrente OUF

Aggiornato il **7 novembre 2026**, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile; industrializzazione dopo**. Giovanni ha fermato il filone parallelo: esecuzione in carico al solo agente principale.

## E2E CSV da chatbot

- **Obiettivo** CSV dalla chat al grafo UDP con un flusso ripetibile. Conservare rotte, script e contratti.
- **Ingresso utente sbloccato** Dopo policy `:60` il selettore si apre. Giovanni riferisce di aver caricato prima Farmacie e poi tentato Teatri nello stesso selettore. Il readback dell'handoff `1d3c1a27-5a57-4e81-bbbc-2f6bc606c6ce` è `STAGED`, asset `8061fad3-1a8b-4f65-9e4a-bfead7974cb7`; il servizio non espone il nome file. Non attribuire questa ricevuta a Teatri.
- **Diagnosi nuova** La lettura live della policy `ouf-lab-authorization:59` mostra che il grant di upload del ruolo admin richiede `dataAccessLabel` e `detailLevel`. Nel sorgente identificato per il runtime conservato, il selettore usa un contesto `capability` senza questi attributi. Il valutatore originale riprodotto localmente nega questo caso. La correzione della sola voce upload lo consente; 13 controlli passano. Il token di esempio Keycloak ha i claim attesi, ma non è il token della richiesta browser.
- **Correzione pubblicata e riletta** Giovanni ha confermato nella THS. La proposta risulta `PUBLISHED`, revisione 1, policy `ouf-lab-authorization:60`. Il catalogo live coincide esattamente con quello proposto: solo il permesso upload admin corretto, 9 ruoli, 13 assegnazioni e altri 65 permessi conservati. [Ricevuta di verifica](../evidence/ths-upload-policy60-published-20261107.json).
- **Nuovo errore e prossimo passo** Il secondo invio ha mostrato `HTTP_500`. Sul sorgente originale è riprodotto il rifiuto di riassociare lo stesso handoff a un altro asset; il selettore riabilita il pulsante e controlla il riuso dopo la scrittura. È coerente con il caso riferito, ma manca l'eccezione live. Il secondo file potrebbe essere stato salvato: non ripetere il caricamento e non cancellare asset. Conservare il primo risultato; correzione del selettore e riconciliazione del secondo upload restano aperte. [Evidenza](../evidence/ths-upload-reuse-storage-next-20261107.json).
- **Diagnostica precedente** La [build 42382365071](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42382365071) è fallita a Trivy dopo i test. Il commit `380e8dcb` parte da `194b5865`, 20 commit prima del sorgente conservato `73498c17`. Non distribuirlo direttamente: l'eventuale log va riportato sulla generazione scelta e verificato.
- [Evidenza e limiti della diagnosi](../evidence/ths-upload-role-diagnosis-20261107.json) · [MiniPET M2](OUF_M2_MINIPET.md) · [Avvio VPS](OUF_RUNTIME_RESTART_20261107.md)

## MinIO → SeaweedFS

- **Verificato nelle ricevute** SeaweedFS OCI33 privato avviato con TLS; copia storica di 120 oggetti verificata. Lo stack E2E usa ancora MinIO.
- **Blocco** PUT Onboarding isolato terminato 502; readback del primo tentativo senza ACK, asset o oggetto riservato. La causa del 502 resta aperta e distinta dal difetto di policy.
- **Binding attuali verificati** Readback VPS 15:29 UTC: Onboarding immagine `7b9d3e91…`, endpoint `http://ouf-minio:9000`, rete `ouf-backend`; SeaweedFS immagine `d23a50eb…` su `ouf-seaweedfs-private`. Nessuna rete Docker condivisa, connettività non testata. [Ricevuta](../evidence/storage-current-bindings-operator-20261107.json).
- **Prossimo risultato** Eseguire il [confronto minimo curl/client Java](OUF_STORAGE_CLIENT_COMPARISON_20261107.md): una sola immagine temporanea uguale all'Onboarding installato, rete/CA/identità target condivise dai due client, un oggetto diagnostico di 29 byte e confronto PUT/GET. Preparazione validata localmente; risultato VPS pendente. Lo stack originale resta su MinIO; il confronto non chiude da solo F1/F2.
- **Poi** Collegare scrittura e lettura dello stack, riconciliare i dati correnti dopo la riapertura di MinIO, eseguire CSV fino al grafo e ripetere senza riparazioni manuali.
- **Piano funzionale** [PR #55](https://github.com/GioNob/ouf-deploy/pull/55), ancora proposta documentale; nessuna prova funzionale acquisita dal solo riordino. DR, RPO/RTO e industrializzazione rinviati.

## Aggiornamenti

Aggiornare qui blocco e prossima azione. Conservare gli eventi nel [log dei checkpoint](OUF_M2_CHECKPOINT_LOG.md) e nelle evidenze, senza trasformare una proposta in un esito runtime.

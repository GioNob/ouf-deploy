# Stato corrente OUF

Aggiornato il **7 novembre 2026**, Europe/Rome. Priorità: **SeaweedFS funzionante, poi E2E ripetibile; industrializzazione dopo**. Giovanni ha fermato il filone parallelo: esecuzione in carico al solo agente principale.

## E2E CSV da chatbot

- **Obiettivo** CSV dalla chat al grafo UDP con un flusso ripetibile. Conservare rotte, script e contratti.
- **Runtime riportato** Stack originale su MinIO; rinnovi host ripristinati; handoff del selettore emesso. Il browser ha risposto 403 `ONB_CAPABILITY_DENIED`; upload Teatri ancora da verificare.
- **Diagnosi nuova** La lettura live della policy `ouf-lab-authorization:59` mostra che il grant di upload del ruolo admin richiede `dataAccessLabel` e `detailLevel`. Nel sorgente identificato per il runtime conservato, il selettore usa un contesto `capability` senza questi attributi. Il valutatore originale riprodotto localmente nega questo caso. La correzione della sola voce upload lo consente; 13 controlli passano. Il token di esempio Keycloak ha i claim attesi, ma non è il token della richiesta browser.
- **Correzione pubblicata e riletta** Giovanni ha confermato nella THS. La proposta risulta `PUBLISHED`, revisione 1, policy `ouf-lab-authorization:60`. Il catalogo live coincide esattamente con quello proposto: solo il permesso upload admin corretto, 9 ruoli, 13 assegnazioni e altri 65 permessi conservati. [Ricevuta di verifica](../evidence/ths-upload-policy60-published-20261107.json).
- **Prossima azione** Nuovo handoff emesso per ouf-admin: `1d3c1a27-5a57-4e81-bbbc-2f6bc606c6ce`, stato `AWAITING_FILE_SELECTION`. Giovanni apre il selettore e sceglie il CSV Teatri; leggere poi `source.file.upload.status` con questo handoff. Apertura browser, assenza del 403 e upload **non ancora verificati**. Il solo handoff non prova il funzionamento dell'upload o di SeaweedFS.
- **Diagnostica precedente** La [build 42382365071](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42382365071) è fallita a Trivy dopo i test. Il commit `380e8dcb` parte da `194b5865`, 20 commit prima del sorgente conservato `73498c17`. Non distribuirlo direttamente: l'eventuale log va riportato sulla generazione scelta e verificato.
- [Evidenza e limiti della diagnosi](../evidence/ths-upload-role-diagnosis-20261107.json) · [MiniPET M2](OUF_M2_MINIPET.md) · [Avvio VPS](OUF_RUNTIME_RESTART_20261107.md)

## MinIO → SeaweedFS

- **Verificato nelle ricevute** SeaweedFS OCI33 privato avviato con TLS; copia storica di 120 oggetti verificata. Lo stack E2E usa ancora MinIO.
- **Blocco** PUT Onboarding isolato terminato 502; readback del primo tentativo senza ACK, asset o oggetto riservato. La causa del 502 resta aperta e distinta dal difetto di policy.
- **Prossimo risultato** Un upload e una lettura applicativa su SeaweedFS con riferimenti e hash coerenti: identificare immagine e binding effettivi, verificare il trasporto della JVM e correggere il difetto concreto.
- **Poi** Collegare scrittura e lettura dello stack, riconciliare i dati correnti dopo la riapertura di MinIO, eseguire CSV fino al grafo e ripetere senza riparazioni manuali.
- **Piano funzionale** [PR #55](https://github.com/GioNob/ouf-deploy/pull/55), ancora proposta documentale; nessuna prova funzionale acquisita dal solo riordino. DR, RPO/RTO e industrializzazione rinviati.

## Aggiornamenti

Aggiornare qui blocco e prossima azione. Conservare gli eventi nel [log dei checkpoint](OUF_M2_CHECKPOINT_LOG.md) e nelle evidenze, senza trasformare una proposta in un esito runtime.

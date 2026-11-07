# Stato corrente OUF

Aggiornato il **7 novembre 2026**, Europe/Rome. Questa pagina raccoglie il blocco e la prossima azione di ciascun filone. **Priorità dell'owner: SeaweedFS funzionante, poi E2E ripetibile; industrializzazione dopo.**

## E2E CSV da chatbot

- **Obiettivo** Portare un CSV dalla chat fino al grafo UDP con un flusso ripetibile. Conservare rotte, script e contratti. Teatri, Farmacie e Cinema sono fixture.
- **Verificato** Stack originale avviato su MinIO. Cinque rinnovi host ripristinati. MCP ha risposto HTTP 204 alla readiness e ha emesso un handoff per il selettore.
- **Blocco** Onboarding ha risposto HTTP 403 `ONB_CAPABILITY_DENIED` per `ouf.managed-source.file.upload` nella sessione browser. L’upload Teatri resta da eseguire. La policy `ouf-lab-authorization:59` espone un ruolo configurato con la capability per `ouf-admin`. Il `403` si ripete in InPrivate. Il login THS richiede già lo scope di upload. L’operatore ha confermato che la finestra InPrivate è autenticata come `ouf-admin`.
- **Prossima azione** Leggere i claim che il client THS genera per `ouf-admin` nella configurazione Keycloak installata. La [lettura sul VPS](../scripts/read-ouf-ths-upload-scope.py) riporta soltanto scope, corrispondenza del soggetto e del tenant come esiti booleani. Con questi esiti distinguere il binding IAM dalla decisione della policy OUF. Una volta riaperto il selettore, seguire lo stesso file attraverso Onboarding, semantica, Ingestion e UDP fino alla verifica nel grafo.
- [MiniPET M2](OUF_M2_MINIPET.md) · [Registro M2](../releases/csv-m2-plan-20261026.json) · [Avvio VPS](OUF_RUNTIME_RESTART_20261107.md)

## MinIO → SeaweedFS

- **Verificato nelle ricevute** Copia storica cifrata su Windows, restore isolati, parità di 120 oggetti su OCI33. Avvio di SeaweedFS privato con TLS riportato dal VPS. MinIO serve ancora lo stack E2E.
- **Blocco storage** Il POST Onboarding isolato è fallito con 502; il readback del primo tentativo non ha trovato ACK/asset/oggetto riservato. La causa non è provata. Il cambio dei binding applicativi resta da verificare sullo stack effettivo.
- **Prossimo risultato F1** Un upload e una lettura applicativa riusciti su SeaweedFS: byte/hash, riferimento asset e ricevuta coerenti. Verificare binding e trasporto della JVM usata dal flusso, correggere il difetto concreto, senza costruire un altro laboratorio generale.
- **Poi F2** Collegare scrittura e lettura di Onboarding/UDP/Gateway, riconciliare i dati correnti e dimostrare che il percorso usa SeaweedFS. MinIO è stato riavviato dopo la copia storica: i 120 oggetti di allora non provano la parità attuale.
- **Coordinamento** Il 403/THS sopra è già in lavorazione altrove. Non duplicarlo né assumerlo causa del 502. Riceverne l'esito prima della prova E2E completa.
- **Rinviato** DR, RPO/RTO, HA, hardening esteso e accettazione produttiva. Nessun nuovo gate formale chiuso; la percentuale euristica storica non misura il funzionamento.
- [MiniPET funzionale](OUF_STORAGE_MINIPET.md) · [Registro funzionale](../releases/storage-functional-status-20261107.json)

## Aggiornamenti

Aggiornare qui il riepilogo e la prossima azione. Aggiungere le evidenze e i passaggi sostituiti in fondo al [log dei checkpoint](OUF_M2_CHECKPOINT_LOG.md).


# Stato corrente OUF

Aggiornato il **7 novembre 2026**, Europe/Rome. Questa pagina raccoglie il blocco e la prossima azione di ciascun filone.

## E2E CSV da chatbot

- **Obiettivo** Portare un CSV dalla chat fino al grafo UDP con un flusso ripetibile. Conservare rotte, script e contratti. Teatri, Farmacie e Cinema sono fixture.
- **Verificato** Stack originale avviato su MinIO. Cinque rinnovi host ripristinati. MCP ha risposto HTTP 204 alla readiness e ha emesso un handoff per il selettore.
- **Blocco** Onboarding ha risposto HTTP 403 `ONB_CAPABILITY_DENIED` per `ouf.managed-source.file.upload` nella sessione browser. L’upload Teatri resta da eseguire. La policy `ouf-lab-authorization:59` espone un ruolo configurato con la capability per `ouf-admin`. Il `403` si ripete in InPrivate. Il login THS richiede già lo scope di upload. La lettura dei grant configurati per `giovanni-chatgpt` non contiene questa capability.
- **Prossima azione** Verificare il nome utente Keycloak nella stessa finestra. Se coincide con `ouf-admin`, isolare scope e decisione effettiva della sessione THS. Una volta riaperto il selettore, seguire lo stesso file attraverso Onboarding, semantica, Ingestion e UDP fino alla verifica nel grafo.
- [MiniPET M2](OUF_M2_MINIPET.md) · [Registro M2](../releases/csv-m2-plan-20261026.json) · [Avvio VPS](OUF_RUNTIME_RESTART_20261107.md)

## MinIO → SeaweedFS

- **Verificato** SeaweedFS OCI33 è avviato sul VPS, su una rete Docker privata, con TLS verificato. MinIO serve ancora lo stack E2E.
- **Blocco** Il cambio dei binding applicativi resta da applicare. I 120 oggetti confrontati nella prova isolata sono un risultato distinto dalla migrazione operativa.
- **Prossima azione** Applicare i binding S3 per Onboarding, UDP e il percorso di lettura. Verificare scrittura e lettura tramite il flusso reale.
- [MiniPET SeaweedFS](OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md) · [Registro avanzamento](../releases/minio-seaweedfs-closure-status-20261105.json) · [Procedura di cambio](OUF_STORAGE_OFFLINE_CUTOVER_RUNBOOK_20261106.md)

## Aggiornamenti

Aggiornare qui il riepilogo e la prossima azione. Aggiungere le evidenze e i passaggi sostituiti in fondo al [log dei checkpoint](OUF_M2_CHECKPOINT_LOG.md).

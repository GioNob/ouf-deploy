# Pacchetto di fermo per il backup prima di MinIO → SeaweedFS

**Stato: proposta tecnica, non eseguibile e non ammessa.** Il pacchetto non richiede altre prove di cifratura: [VPS → Windows verificato dall'operatore](../evidence/storage-backup-cross-platform-operator-20261106.json),512byte/hash coincidenti, privata rimasta sulPC. Nessun archivio dei dati applicativi ancora catturato.

## Perimetro fissato

Piano privatoSHA2561c0bb62ceba85f748e43465d36f016b4c575c586d40390dc92095a1dbc71bd0f, scadenza **7 novembre2026ore20:53:39Europe/Rome**. Nessun rinnovo automatico.14ruoli,34fonti,5directory runtime,intero PostgreSQL condiviso. Le osservazioni appartengono alla preparazione: non sostituiscono la verifica immediatamente precedente a un'operazione ammessa.

Cambiare a no esclusivamente le35restart policy che lo richiedono:13ruoli selezionati e22container condividenti già fermi. Conservare policy originali e identità complete prima del cambio. semantic e81condividenti sono già no; non modificarli senza motivo. Nessun container condividente deve essere avviato. Gli altri28container fermi non rientrano nelle modifiche; un nuovo attivo fuori roster blocca la proposta.

Il compilatore puro tools/storage_planning/cold_stop_proposal.py associa ID completi del piano e dell'inventario conservato, verifica fingerprint/generazioni/policy/condivisioni e genera un documento privato di comandi in forma argv. Non fa IO,non espone env,segreti o corpi,non esegue Docker e non ha modalità execute. Non è stato eseguito sui file privati target; non esiste un nuovo digest di pacchetto operativo target. Nessun documento prodotto diventa autorizzazione.8test locali PASS,nessun test nativo del fermo dichiarato.

## Ordine proposto e condizioni tra gruppi

Tutte le precondizioni operative sotto devono essere risolte prima della prima mutazione. Il raggruppamento seguente è una proposta da qualificare sui meccanismi effettivi dei servizi; non costituisce una procedura già provata sul VPS.

| Fase | Azione proposta | Condizione di uscita |
|---|---|---|
| Inibizione dei riavvii |35update restart=no sugliID esatti; ricevuta prima/dopo per ciascuno |Nessuna risposta ambigua o drift; blocco distinto dei ricreatori e accessi amministrativi |
| Ingress |caddy,apisix,mcp,gateway-owner |Nuove ammissioni già bloccate anche dai percorsi diretti; tutti i processi del gruppo fermi |
| Applicazioni |onboarding,ingestion,udp,semantic,ingestion-evidence-read,udp-evidence-read |Drain o disposizione degli esiti ambigui verificati separatamente; processi fermi |
| Identità |keycloak |Nessuna ulteriore scrittura al cluster condiviso da questo owner |
| Dati |postgres,minio |PID0,uscita0,nessunOOM/errore/paused/restarting; nessun altro writer diretto |
| Control plane |etcd |Uscita0 e nessun ricreatore dipendente ancora attivo |
| Cattura |Produttore v3 già qualificato, recipient già vincolato |Guardia offline integrale,manifest/hash e nessuna mutazione durante la cattura |

I comandi proposti usano il segnale benigno configurato (SIGTERM/SIGINT,varianti equivalenti) e rifiutano SIGKILL o segnali non revisionati. Il segnale viene inviato una sola volta con docker kill --signal=...; se non termina,si mantiene HELD senza forzare,ritentare o riavviare. [Docker kill](https://docs.docker.com/reference/cli/docker/container/kill/) usa il segnale indicato; [docker stop](https://docs.docker.com/reference/cli/docker/container/stop/) invece può arrivare aSIGKILL alla scadenza del timeout. Per questo non è generato uno stop con timeout e kill implicito. Comandi dati soltanto,nessun invio effettuato.

Applicativi con uscita143 dimostrano cessazione fisica,non drain o consistenza. Le condizioni del produttore v3 restano invariate. Nessun success di questa proposta prova common-cut,quiescenza dei writer o G3/G4.

## Blocchi reali e responsabilità

| Evidenza mancante | Come va risolta prima del fermo |
|---|---|
| Generazioni e inventario correnti |Verificatore nell'operazione ammessa,non riuso della vecchia raccolta come live |
| Ricreatori e scrittori amministrativi/esterni |Identificare scheduler,azioni di deploy,accessi privilegiati e consumer diretti; barriera persistente e prova efficace. restart=no non li blocca |
| Nuove ammissioni e drain owner |Meccanismi effettivi per upload/profile,ingestion/outbox,store/shadow/purge/maintenance; nessuna inferenza daPID oexit143 |
| Transazioni e risultati incerti |Disposizioni per transazioni aperte/preparate,ACK/watermark ed effetti S3 ambigui; preservare e riconciliare,mai replay cieco |
| Custodia mount effettivi |Prova dei binding visibili al processo; la sola fonte host non sostituisce questa prova |
| Finestra e gestione del mancato rientro |Vincolo di indisponibilità dell'owner,inizio/fine e gestione del mantenimento inHOLD; non inventare unRTO |
| Autorità applicabile |Decisione riferita al pacchetto concreto e ai suoi hash; decision-reference non autenticaHUMAN/THS |
| Driver operativo e segnali |Implementazione e qualifica dell'esecuzione con registro durevole,esiti incerti e timeout,prima di consegnare comandi mutativi |

La parte tecnica resta a carico dell'agente; all'owner serve soltanto definire il vincolo reale di indisponibilità e,quando il pacchetto sarà completo,la decisione operativa applicabile. Non chiedere adesso un sì generico al fermo né trasformare la risposta sulla finestra in autorità di stop.

## Budget e uscita

Proposta del compilatore: massimo35mutazioni policy e14segnali,un invio per azione; attesa massima120s per gruppo,limite complessivo proposto1200s per fase di fermo. Il futuro driver deve contare anche le verifiche e custodire l'esito prima di avanzare; queste soglie sono dati di progetto,non budget già autorizzati.

Cattura esistente:1tentativo,3600s,256comandi,64GiB complessivamente prodotti incluse copie intermedie. Il limite di un'ora non include trasferimento alPC,decifratura,restore e riapertura. Finché questi tempi non sono misurati non può essere promesso un ritorno entro un'ora o una finestra totale di due ore. Se la scadenza del piano non copre la futura operazione,fermare la pianificazione e riesaminare il binding senza modificare il piano originale.

Nessun riavvio automatico dopo arresto/cattura/restore. Nessun cambio endpoint,deploySeaweedFS,grant o ritiroMinIO in questo pacchetto. La riapertura e l'ammissione della generazione sono separate.

## Criterio MiniPET

Chiusa la sola dipendenza tecnica di compatibilità cifratura/custodia della chiave. G3 richiede ancora backup completo,copia indipendente,restore rappresentativo e obiettivi validati;G4 i writer e la procedura completa. **18,3/46=39,78%,0/8gate,0/21AT,0/120migrati**,120corpi verificati separatamente. Nessun credito per questi8test o per il documento.

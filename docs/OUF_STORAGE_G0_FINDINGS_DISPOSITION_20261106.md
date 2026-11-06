## Aggiornamento coorte — origine conservata ricostruita

La label194b non identifica il sorgente dell'immagine Onboarding: consegna e custodia legano7b9d3e91 a73498/9d19,stesso tree Git. [Decisione e limiti](OUF_STORAGE_COHORT_DECISION_20261106.md). La riserva sulla membership live resta,ma non occorre ricominciare la ricostruzione dell'origine. I18rilievi e le disposizioni sottostanti restano immutati;nessuna proprietà o accettazione aggiunta.

# G0 — disposizione dei rilievi raccolti, 6 novembre 2026

**Review delle evidenze disponibili completata con rilievi ancora aperti. G0 non chiuso.** Il risultato originale HELD_RECONCILIATION_FINDINGS con18rilievi resta immutato. Questo dossier descrive cosa significano i rilievi e quale prova manca; non li cancella o converte in PASS.

Fonte: output VPS restituiti da Giovanni, non accesso diretto dell'agent. [Raccolta](../evidence/storage-g0-host192-collection-operator-20261106.json), [readback](../evidence/storage-g0-sealed-findings-operator-20261106.json), [classificazione](../evidence/storage-g0-reference-classification-operator-20261106.json), [review finale](../evidence/storage-g0-final-local-review-operator-20261106.json). L'ultima review ha letto10file locali, senza provider, credenziali, corpi o scritture. Non ripetere i comandi già riusciti; le due raccolte sono consumate.

## Disposizioni

| Famiglia | Conteggio | Esito documentato | Residuo |
|---|---:|---|---|
| ASSET_OWNER_UNRESOLVED |10|Tutti tenant NULL;1receipt owner candidata/9assenti;0upload coerenti;2source_ref/8assenti |Proprietà non autenticata. Conservare dati e prove; nessun backfill o10riparazioni HUMAN inferite. Per G0 serve disposizione di dominio sostenuta dal contratto della coorte effettiva |
| ADDITIONAL_REFERENCE_REQUIRES_CLASSIFICATION |4|sample_ref collegati esattamente ad asset/job/profile DB |Sono riferimenti logici, non corpi S3 mancanti. Preservare il contenuto dei campioni mediante backup/restore DB completo; contenuto non esportato dal G0 |
| QUARANTINE_REFERENCE_REQUIRES_CLASSIFICATION — evidence_ref |2|Etichette diagnostiche CONTRACT_MAPPING_DIAGNOSTIC_LABEL |Non creare oggetti S3 per queste etichette; preservare le righe |
| QUARANTINE_REFERENCE_REQUIRES_CLASSIFICATION — payload_ref |2|Asset unico, bucket Onboarding vincolato, hash/size e source/run coerenti; run/attempt collegati |Collegamento fisico osservato. Tenant NULL, snapshot senza exact asset+staging binding: proprietà non provata, non dedotta dal solo hash |
| ACL_OWNER_OR_GRANTS_UNPROVEN, sezione ACCESS separata |2|Grant CanonicalUser FULL_CONTROL, senza Owner.ID o grantee ID; nessuna policy bucket; publicAccessBlock unsupported |Autorizzazione effettiva ed equivalenza target da dimostrare. Non prova bucket pubblico né isolamento corretto |

Le18impronte dei rilievi sono state confrontate esattamente. Gli8riferimenti non-owner sono ora tutti tipizzati:4campioni DB,2etichette,2collegamenti fisici. **Tipizzazione completata non equivale a18rilievi risolti.** Nessun rilievo missing/hash/size/unclassified/dangling nel breakdown restituito, sui120corpi verificati e referenziati; non è una prova di common-cut o completezza dei consumer.

## Feature, runtime e capacità

Entrambi i bucket: versioning Status e MFADelete NOT_SET;0destinazioni Lambda/Queue/Topic, EventBridge assente. PRESENT nelle precedenti risposte era lo stato della risposta, non feature abilitata. CORS/encryption/lifecycle/objectLock/replication ABSENT nei riscontri precedenti. Le esigenze future e le policy effettive richiedono comunque review.

Host-before e host-after hanno digest63cfa2294e173082a2891aeefcaef43747002fffc36312906b6d01c6d0342b71.13ruoli noti tutti running/non paused;132container fuori roster,1running. Quest'ultimo non mostra binding storage né condivisione mount MinIO nei segnali raccolti: non dimostra assenza di scritture via rete. Censimento writer e assenza consumer esterni non provati. Hash e revision dichiarate sono osservazioni della raccolta, non probe live o sigillo storico indipendente.

Capacità:293049417728byte disponibili su539792977920; source, destination e backup sullo stesso device. Lo staging non è backup indipendente; nessuna inferenza sull'esistenza di altri backup. Manca accettazione di crescita, restore, throughput e finestra.

## Contratto della coorte applicativa

La qualifica client33 usa Onboarding d5155899; il ruolo osservato dichiara194b586508c6661b40a74d9c7f99ed3b876f5fbc. Il confronto Git delle interfacce e degli adapter dimostra una differenza: put con UUID interno contro putReserved, e timeout/retry espliciti introdotti nel codice più recente. Non prova quali byte siano installati. Non trasferire garanzie di d515/V37/V38 al servizio osservato sulla sola base dello schema o della label.

Il worker/service di194b confermano il formato profile://managed-files/{asset}/jobs/{job}/redacted-sample e il contenuto inDB. Il contratto ingestion4165 distingue payload RAW e label diagnostiche. Le proiezioni raccolte non comprendono subject/source-review/redacted_sample: non possono provare il predicato di proprietà completo. I contratti più recenti conservano NULL legacy e ammettono prove alternative, ma la loro applicabilità al servizio reale va stabilita.

Riferimenti esatti e differenza di coorte nel [runbook](OUF_STORAGE_OFFLINE_CUTOVER_RUNBOOK_20261106.md). Il filone HUMAN/recovery non riparte automaticamente: prima stabilire quali operazioni la migrazione richiede davvero.

## Otto sezioni G0

| Sezione | Stato dopo la review | Prova mancante |
|---|---|---|
| OBJECTS |120corpi/referenze verificati sul raccolto |Generazione comune, funzioni richieste e inventario accettato |
| DB |353righe proiettate;18rilievi con disposizione esplicita |Disposizione owner coerente con coorte effettiva; backup completo e common-cut |
| RUNTIME |13ruoli e1attivo fuori roster osservati |Membership sorgenti effettiva, censimento completo |
| ACCESS |Forma ACL e policy note |Autorizzazione effettiva/equivalenza |
| CAPACITY |Spazio e stesso device osservati |Adeguatezza, crescita, custodia/restore |
| CUSTODY |Non attestata |Custodia dati, chiavi, immagini e backup indipendente |
| WINDOW |Non attestata |Finestra e obiettivi RPO/RTO accettati |
| WRITERS |11percorsi senza evidenze operative complete |Responsabili, binding, fermo/verifica e consumer esterni |

La cattura e la lettura raggruppata sono concluse. La riconciliazione complessiva G0 rimane aperta sulle prove sopra. Il prossimo lavoro usa il [piano offline](OUF_STORAGE_OFFLINE_CUTOVER_RUNBOOK_20261106.md), non un altro riepilogo degli stessi export.

MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120migrati;120verificati è distinto. Nessuna modifica dei dati, merge, deploy, grant o traffico. Storico delle disposizioni preliminari conservato in Git.

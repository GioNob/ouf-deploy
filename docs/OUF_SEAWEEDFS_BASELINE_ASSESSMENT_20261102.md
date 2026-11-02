# SeaweedFS — inventario e piano privato acquisiti, migrazione non ammessa

2 novembre 2026. I controlli16 e17 sono completati e consumati. L'inventario S3 e il piano privato descrivono i dati osservati; non provano uno snapshot atomico. Tutti gli 8 gate / 21 AT e M2 restano OPEN.

| Evidenza | Risultato | Implicazione |
|---|---:|---|
| Bucket / record | 2 / 120 | Insieme rilevato dalle API supportate |
| Byte logici | 203743 | Non include allocazione storage, filer, DB, backup e margini |
| Hash OUF dichiarati / mancanti | 110 / 10 | Tutti i120 corpi reali devono ancora essere letti e verificati |
| Versioni non-null / marker / multipart incompleti | 0 / 0 / 0 | Osservazione della raccolta, non N/A automatico per gli AT |
| Namespace | PASS | Nessuna collisione file-directory, chiave non sicura o slash finale rilevata |
| Corpi reali verificati / oggetti copiati | 0 / 0 | Piano privato PLANNED_NOT_COPIED |
| Richieste S3 del16 / del17 | 265 / 0 | Solo metadata; nessuna scrittura |
| Controlli / Docker GET cumulativi | 17 / 52 | Cinque vecchi comandi13–17 consumati: non ripetere o cancellare |
| Letture metadata offline17 | 4 file / 93238 byte | Stabilità della raccolta16 durante l'analisi provata |

Inventario privato SHA256 `43571bb43921f74adfa5974a0903acb54ee1eadecbc9d5d0d70539ce5cadba55`; piano privato SHA256 `debed37f949b00f008eae77feecd103c8d4834e105c0d6c727b188e6aafbb501`. [Ricevuta17](../evidence/seaweedfs-offline-plan-target-20261102.json) e [valutazione strutturata](../evidence/seaweedfs-offline-plan-target-assessment-20261102.json). Nessun nome di oggetto, credenziale o documento privato pubblicato.

## Funzioni classificate dal controllo17

| Funzione | Stato sui2 bucket | Conclusione ammessa |
|---|---|---|
| publicAccessBlock | UNSUPPORTED2 | Sono queste le due risposte non supportate; non significa assenza della funzione |
| ACL | PRESENT2, configured0 | I grant non sono classificati dal riepilogo: accesso privato non ancora provato |
| Bucket policy, CORS, cifratura default, lifecycle, objectLock, replication | ABSENT2 per tipo | Nessun documento policy da tradurre nella raccolta |
| Versioning e notification | PRESENT2, configured0 | Nessun bucket versionato o notification configurata rilevati; conservare il valore privato |
| Cifratura/KMS, retention/hold, tag, cache/encoding degli oggetti | Conteggi0 | Nessuno di questi attributi rilevato sui120 record; non è una verifica dei corpi |

I ruoli con binding storage nello snapshot14 sono onboarding, udp e udp-evidence-read. Non prova chi stia scrivendo oggi, che i consumer esterni siano assenti o che i riferimenti DB siano completi. Le altre12configurazioni, RAM e capacità del14 non sono state rinfrescate.

La password del16 è stata risolta da un file dichiarato regolare0600, con un solo collegamento e dimensione ammessa, appartenente a un utente diverso da root; letti65byte senza pubblicare o spooling del valore. L'utente S3 proviene dall'ambiente esplicito. La fonte non è ammessa alla custodia operativa. NON_ROOT_OWNER è sufficiente a violare il vecchio guard allo stato osservato16: mancano i metadati15 per attestare retroattivamente quel preciso predicato. Il17 non ha aperto file credenziali e non ha modificato proprietà o permessi.

## Stato di SW-WP4 e prossimi vincoli

Il compilatore offline già qualificato ha prodotto il piano. Il nuovo [core di copia sintetica](OUF_SEAWEEDFS_COPY_CORE_20261102.md) ha superato CI41504703184 e readback indipendente41507064288: 120 oggetti generati copiati/riletti su due processi SeaweedFS, CAS, crash reali e503 post-salvataggio. Non prova il trasferimento dal MinIO reale. Nessun entrypoint VPS, nessuna copia reale o autorità emessa. Versioni/marker e multipart copy non implementati nel core; massimo256 oggetti/16MiB ciascuno/64MiB totali, soli bucket dichiarati.

Per il target restano aperti ACL e controllo equivalente di publicAccessBlock, censimento completo writer/consumer/DB, custodia delle credenziali, profilo destinazione indipendente, backup coerente, fence/delta finale, capacità fresca, throughput e validazione degli obiettivi recovery PET UDP§81 (RPO iniziale900s, RTO14400s; perdita di scritture confermate al passaggio pianificato0). L'assenza di policy o versioni non chiude questi vincoli.

SW-G1 conserva il gate raw HELD: zero HIGH/CRITICAL e1UNKNOWN. [Valutazione limitata di applicabilità](OUF_SEAWEEDFS_G1_APPLICABILITY_REVIEW_20261102.md) ora accettata dall’owner, decisione OUF-SW-G1-20261102-01 e qualifica CI41519037628 PASS: unico rilievo classificato not_affected, zero HIGH/CRITICAL/UNKNOWN irrisolti nel perimetro esaminato. Criterio MiniPET v1.1 emendato per questa sola valutazione; rapporto raw invariato e nessun ignore. SW-G1 complessivo resta OPEN. Nessuna nuova operazione VPS dopo17. MinIO resta in uso e vulnerabile. Teatri/M1 8/8tecniche,6/6funzionali e stessa Farmacie preservati; originali PET non disponibili nella conversazione, nessuna attestazione di conformità completa.

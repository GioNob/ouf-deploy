# Generazione 29: vista tecnica corrente e confini delle prove

Il [piano](../releases/minio-seaweedfs-plan-20261102.json) punta ora all'esatta generazione 29, con immagine, coorte e laboratori verificati separatamente. Lo stato è `TECHNICAL_COHORT_AND_SYNTHETIC_RUNTIME_VERIFIED_NOT_ADMITTED`: non costituisce ammissione release o accettazione target.

| Passaggio | Fonte effettiva | Risultato |
|---|---|---|
| Immagine e readback | [41696541570](https://github.com/GioNob/ouf-deploy/actions/runs/41696541570), commit 041992ea | 6.156 test PASS / 5 skip, scan grezzo zero, SPDX e firma publisher verificati |
| Coorte e testi legali | [41701381292](https://github.com/GioNob/ouf-deploy/actions/runs/41701381292), commit 7a712185 | 262 ZIP/h1, 353 testi, 17 archivi MPL e binding nuovo binario/OCI |
| Runtime sintetico | stesso run, job 126147936979 | cinque oggetti ripristinati; MIME GET/HEAD PASS prima/dopo; 23 casi S3, 2 TLS negativi, 2 egress negati |

La ricevuta [coorte](../evidence/seaweedfs-452-generation29-cohort-hosted-20261103.json) è uno snapshot effettuato quando il laboratorio era ancora in corso: il suo campo storico rimane invariato. La successiva [ricevuta runtime](../evidence/seaweedfs-generation29-runtime-hosted-20261103.json) prova il successo finale di tutti e tre i job. Il checker verifica i due documenti con hash distinti, tutti i 74 file grezzi trattenuti, le 29 patch con hash fissati, i sorgenti del laboratorio e la prova dei job. Lo ZIP predecessore coincide con quello effettivamente consumato dai laboratori.

## Storia preservata

`historicalQualification15` contiene esattamente la precedente vista tecnica: immagine 15, receipt SDK27 e profilo28 byte-identico al binario 85fa52c6. I vecchi controlli vengono eseguiti su questa vista storica, con un hash canonico fisso. Non si forza l'uguaglianza di quel binario con il nuovo a0c74718.

`historicalGeneration29PhaseA` conserva lo snapshot immagine 29 con coorte/runtime allora PENDING. Le ricevute originali, la vista 4.51, i dossier, gli scope consumati e il cold 15 rimangono immutati. Il cold 15 continua a registrare `CONTENT_TYPE_MISMATCH`; il nuovo PASS riguarda solo la regressione octet-stream della nuova immagine. Non ripara metadati persi in oggetti precedenti e non qualifica tutta la compatibilità S3.

## Lifecycle e lavoro successivo

La presenza di zero AWS SDKv1 e zero S3 manager deprecato non equivale a dichiarare mantenute tutte le dipendenze. I quattro fronti di rimozione selezionati non esauriscono l’audit della generazione 29:

- Shopify Sarama 1.38.1 e rcrowley/go-metrics 20201227;
- boltdb/bolt 1.3.1;
- mitchellh/mapstructure 1.5.1-0.20220423185008-bf980b35cac4;
- armon/go-metrics 0.4.1.

Il [nuovo inventario dei 262 moduli compilati](OUF_SEAWEEDFS_GENERATION29_LIFECYCLE_INVENTORY_20261103.md), legato al binario esatto, risolve i metadata GitHub di 250 moduli su 181 repository e conserva 12 origini non risolte, senza considerarle mantenute per presunzione. Individua 10 moduli compilati con repository archiviato. La policy del pin MongoDB v1 limita fix e aggiornamenti critici a inizio 2026, finestra ormai trascorsa; il detector GCP dichiara di non essere più mantenuto. L’inventario conserva anche le altre policy di deprecazione e manutenzione: non le traduce tutte in fine del supporto, e un repository non archiviato non prova il mantenimento del pin.

La ricevuta inventario `2ba40208…` e il documento completo `43a2fbaa…` sono vincolati dal checker insieme a tutti i 17 file di evidenza. Lo stato lifecycle complessivo rimane OPEN indipendentemente dal PASS tecnico della coorte 29.

I prototipi di rimozione successivi sono lavoro sorgente non qualificato. Il checker nega la promozione automatica della patch count o dell'immagine, qualsiasi trasferimento delle prove runtime 29 e qualsiasi credito aggiuntivo. Saranno necessari un nuovo profilo integrato, regressioni e nuova coorte immagine/scan/SPDX/licenze/provenienza prima di cambiare ancora la vista corrente.

## Avanzamento e limiti

La stima rimane **38% ±10**, 17,5/46 secondo i pesi originari. Il credito ingegneristico del ripristino è già registrato nella precedente decisione; il nuovo runtime 29 è una prova effettiva separata e non una duplicazione di credito. Restano 0/8 gate, 0/21 AT, 0/120 oggetti reali.

Review licenze e redistribuzione, custodia durevole, PostgreSQL/PITR coordinato, fencing writer, rotazione chiavi/certificati, capacità e RPO/RTO rappresentativi, binding e autorizzazioni target restano OPEN. Nessun tempo misurato in laboratorio diventa SLA. MinIO resta attivo. Scope 17 / 52 GET, risultati Teatri/M1 e Farmacie preservati; nessun merge, deploy o nuova autorità HUMAN/THS.

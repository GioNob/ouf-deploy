## Upload sospeso riconciliato sulle copie

La lettura sul VPS ha trovato un intento `DISPATCHED` senza ACK, collegamento asset, asset o ricevuta. SeaweedFS ha risposto `404 NoSuchKey` sulla chiave riservata. Le due richieste S3 erano GET e i container di lettura sono stati rimossi. I log precedenti non identificano la causa del 502. [Ricevuta VPS](../evidence/storage-oci33-onboarding-upload-readback-operator-20261107.json).

## Upload isolato sospeso su HTTP 502

L'operatore ha riportato HTTP 502 dopo un solo POST. Onboarding era UP e la lettura pre-upload di SeaweedFS era riuscita. Il 502 è compatibile con la risposta che l'adapter Onboarding usa per gli errori S3 di scrittura e lascia l'esito da riconciliare. L'area e i log privati sono conservati e i container sono stati rimossi. [Ricevuta VPS](../evidence/storage-oci33-onboarding-upload-http502-held-operator-20261107.json).

## Onboarding avviato sul VPS in isolamento

Il VPS ha avviato Onboarding sull'immagine esatta. PostgreSQL e SeaweedFS TLS erano disponibili, la readiness era UP e Flyway ha confermato V39, V40 e V41. I tre container sono stati rimossi e le copie di lavoro conservate. [Ricevuta VPS](../evidence/storage-oci33-onboarding-boot-ready-operator-20261107.json).

## Immagini applicative disponibili sul VPS

Il VPS ha caricato e vincolato l'immagine Onboarding testata e confermato l'immagine UDP conservata. L'ID del daemon per Onboarding è registrato accanto al digest raw della configurazione verificato in precedenza. [Ricevuta VPS](../evidence/storage-oci33-application-images-ready-operator-20261107.json).

## Accessi S3 isolati verificati sul VPS

L'operatore ha riportato `ISOLATED_OCI33_APP_BINDINGS_READY`. Le due identità esistenti hanno letto il rispettivo oggetto con hash coincidente e ricevuto AccessDenied sul bucket dell'altra, via TLS verificato. Sei GET complessive, due attese di avvio, container rimosso. Nessun container applicativo avviato. [Ricevuta operatore](../evidence/storage-oci33-app-bindings-ready-operator-20261107.json).

## Staging OCI33 riuscito sul VPS

Il VPS ha restituito `ISOLATED_OCI33_STAGE_READY`. La copia dei file è verificata, SeaweedFS ha elencato 2 bucket e 120 oggetti in rete isolata con 5 GET, poi il container è stato rimosso. I dati staged sono disponibili per configurare gli accessi applicativi. [Ricevuta operatore](../evidence/storage-retained-oci33-stage-ready-operator-20261107.json).

## 7 novembre — censimento amministrativo ed esterno

Giovanni riferisce «nessun noto» per ulteriori strumenti amministrativi e consumer esterni con scritture dirette su MinIO o PostgreSQL. [Ricevuta](../evidence/storage-external-writers-owner-observation-20261107.json). I percorsi applicativi già mappati e i contenimenti host osservati restano acquisiti. La dichiarazione registra quanto noto all'operatore. L'assenza tecnica dei percorsi e la tenuta del blocco devono risultare dal pacchetto operativo.

Per la preparazione non produttiva, il pacchetto mantiene fermi gli originali, usa copie isolate con endpoint privati e separa le identità di manutenzione da quelle applicative. I servizi dati restano senza porte pubblicate. Prima del cambio servono un elenco esatto dei binding ammessi, una verifica dei dinieghi da percorsi esclusi e una generazione comune PostgreSQL, oggetti e stato di controllo. Riapertura con decisione distinta. [Matrice e condizioni di uscita](../releases/storage-offline-writer-containment-20261106.json).

## 7 novembre — sorgenti originali e inventario G0 corrispondono

Il riscontro operatore ha verificato la custodia e trovato zero differenze per 5.032 voci PostgreSQL e 325 voci MinIO. I 120 oggetti coincidono con G0 per bucket, chiave, dimensione e SHA-256. I due container sorgente corrispondevano alle identità catturate e i controlli Docker prima e dopo hanno osservato zero container attivi. [Ricevuta](../evidence/storage-retained-source-comparison-match-operator-20261107.json).

Il backup cifrato verificato su Windows, i due restore isolati e la parità OCI33 restano le evidenze da riusare. Il confronto non attesta la copertura degli eventi della cattura, un common cut temporale o una barriera persistente alle scritture esterne. G4 resta aperto. MiniPET 18,3/46 (39,78%), gate 0/8, AT 0/21, oggetti migrati operativamente 0.

Il lavoro passa alla preparazione del pacchetto operativo. Le dipendenze immediate sono i due percorsi di scrittura esterni/amministrativi ancora senza censimento completo, i binding effettivi S3 e PostgreSQL della coorte applicativa e la prova di accesso e isolamento sul target. La scelta già acquisita di una finestra non produttiva senza orario di rientro si riusa. La messa in servizio e la riapertura richiedono le decisioni distinte previste dal runbook.

## 7 novembre — parità verificata sul VPS

Il rehearsal isolato del dataset storico è riuscito. SeaweedFS OCI33 contiene i 120 oggetti dei due bucket (203.743 byte) con insieme delle chiavi, corpi, metadati e tag coincidenti. La continuazione ha riusato l'immagine verificata e distinto il digest della configurazione dall'ID del daemon. [Ricevuta operatore](../evidence/storage-retained-oci33-rehearsal-parity-operator-20261107.json).

Il restore isolato di PostgreSQL aveva già aperto 7 database e letto una riga in ciascuno. Le due prove si riferiscono alla stessa custodia storica. Restano aperti la baseline comune corrente, il contenimento verificabile dei writer e i binding applicativi. Credito aggiunto 0, G4 aperto, oggetti operativi migrati 0. Avanzamento MiniPET 18,3/46 (39,78%), gate 0/8, AT 0/21.

Il [confronto sul VPS](OUF_STORAGE_RETAINED_SOURCE_COMPARISON_20261107.md) è stato completato e ha trovato corrispondenza. L'ammissione operativa resta separata.

## Binding applicativi da preparare per il cambio

| Percorso | Configurazione nel sorgente candidato | Delta da vincolare sul VPS |
| --- | --- | --- |
| Onboarding, staging upload | `ouf.onboarding.staging.endpoint`, `bucket`, `access-key-file`, `secret-key-file` nello stesso prefisso. Firma in `us-east-1`. [Adapter d5155899](https://github.com/GioNob/ouf-source-onboarding/blob/d5155899b09dda298494b68cefa7e1f281167652/src/main/java/it/comune/trieste/ouf/onboarding/application/MinioManagedFileStagingStore.java) | Endpoint SeaweedFS con TLS e identità limitata allo staging. Conservare bucket e chiavi `managed-files/`. |
| Onboarding, lettura tramite gateway | `ouf.onboarding.object-store.gateway-base-url`, `read-path`, `token-file` nello stesso prefisso. Capability `ouf.object-storage.content.read`, scope `ouf.internal.object-storage.read`. [Client d5155899](https://github.com/GioNob/ouf-source-onboarding/blob/d5155899b09dda298494b68cefa7e1f281167652/src/main/java/it/comune/trieste/ouf/onboarding/application/GatewayManagedFileObjectStore.java) · [Contratto gateway](https://github.com/GioNob/ouf-api-gateway/blob/81fdf7a5f9f3ef02ed930a1db911d34cab1a9415/ouf-config/capabilities/ouf.object-storage.content.read.yaml) | Conservare il contratto interno e verificare a quale backend punta il percorso effettivamente installato. |
| UDP, lake | `OUF_UDP_S3_ENDPOINT`, `OUF_UDP_S3_BUCKET`, `OUF_UDP_S3_REGION`, `OUF_UDP_S3_PATH_STYLE`. L'SDK usa la catena standard di credenziali. [Configurazione 0d40da05](https://github.com/GioNob/ouf-udp-object-resolution/blob/0d40da05408a14db31d4d41af2372d6a71480291/src/main/resources/application.yml) · [Client](https://github.com/GioNob/ouf-udp-object-resolution/blob/0d40da05408a14db31d4d41af2372d6a71480291/src/main/java/it/comune/trieste/ouf/udp/S3LakeConfiguration.java) | Fissare endpoint, modalità di addressing, identità distinta, bucket e trust TLS. Mantenere chiusi i worker di manutenzione e shadow durante la verifica. |
| Ingestion | Il profilo candidato espone il datasource e l'autenticazione gateway-read. [Configurazione 4165b9e1](https://github.com/GioNob/ouf-ingestion-runtime/blob/4165b9e149be467d5d7c6bed35e4e1af4e249db1/src/main/resources/application.yml) | Verificare percorso di archiviazione e consegna a UDP, riferimenti e ACK prima di assegnare eventuali nuovi binding. |

Per PostgreSQL, conservare i database e le identità effettive dietro `OUF_ONB_DB_URL`, `OUF_UDP_DB_URL` e `OUF_ING_DB_URL`. Legare versione schema e migrazioni V39–V41 di Onboarding alla stessa coorte candidata. La barriera esterna deve restare attiva durante l'avvio della coorte.

Le fonti Git identificano i punti di configurazione. L'istanza effettiva richiede ancora il confronto privato di endpoint, CA, bucket, identità e mount. Per amministratori e consumer esterni è acquisita l'osservazione operatore. La matrice descrive le verifiche tecniche ancora da fare. I cinque timer e il servizio registry già contenuti restano evidenza acquisita. La barriera del pacchetto dovrà coprire anche eventuali accessi diretti non visibili ai container.

## Stato corrente — cifratura conclusa, residuo operativo del fermo

[VPS → Windows verificato](../evidence/storage-backup-cross-platform-operator-20261106.json):512byte/hash coincidenti,privata rimasta sulPC. Non ripetere preparazioni o prove di cifratura. [Pacchetto di fermo](OUF_STORAGE_COLD_STOP_PACKAGE_20261106.md):proposta privata di35policy e14segnali,ordine/barriere/timeout espressi; compilatore puro con8test locali,nessun driver esecutivo o qualifica target. Restano contenimento dei writer/ricreatori,drain/disposizione degli esiti incerti,mount effettivi,qualifica del driver,finestra e autorità applicabili. Il vincolo di indisponibilità dell'owner serve alla pianificazione e non autorizza lo stop. Nessun backup applicativo/restore o creditoMiniPET;1h di capture non è durata totale del fermo. Le istruzioni sotto per ripetere prove ormai concluse sono storiche.

## Stato corrente — impatto VPS e custodia PC verificati dall'operatore

Entrambi gli output sono acquisiti. Non ripetere reader,prepare v3 o client Windows. Piano valido alla lettura,scadenza7novembre2026ore20:53:39Europe/Rome;35policy necessarie (13ruoli+22condividenti),nessuna mutata. PC roundtrip reale4096byte riuscito. Prossima azione: [preparazione cifratura Linux qualificata e collegamento al PC](OUF_STORAGE_BACKUP_CIPHER_LINK_20261106.md),poi completare pacchetto concreto di contenimento/fermo/finestra/autorità. VPS age assente,installazione e decrypt della prova512byte ancora pendenti; nessun backup/restore/creditoMiniPET. La sequenza sotto è storico e non richiede ripetere le prove concluse.

## Aggiornamento — piano backup concreto, fermo non ancora ammesso

Piano v3 preparatoSHA1c0bb62ceba85f748e43465d36f016b4c575c586d40390dc92095a1dbc71bd0f:14ruoli (etcd incluso),34fonti,103container già fermi condividenti,intero clusterPG. [Custodia e impatto corrente](OUF_STORAGE_COLD_PLAN_DECISION_20261106.md). Prossima coppia:reader policy/scadenza del piano conservato,prova Windows locale di cifratura/decifratura. Nessuna nuova raccolta Engine o replay prepare. DestinazionePC Windows,custodeGiovanni,SSH/SCP già noti;le proposte storiche di richiederli sono superate. Rimangono recipient target,compatibilità age,policy realmente da modificare,contenimento/finestra/decisioni applicabili e backup/restore. Nessuno stop/deploy/grant autorizzato da questo aggiornamento.

## Aggiornamento corrente — identità fuori roster risolta

[Ricevuta operatore e join storico](../evidence/storage-g0-unmapped-runtime-operator-20261106.json): l'unico attivo fuori roster è **ouf-etcd**, con image ID e SHA256 del nome/ID coincidenti con la ricevuta indipendente del9ottobre. Non è prova di consumer S3,assenza writer esterni o dipendenza routing corrente. Includere review della custodia/stato control plane;nessuno stop/restore automatico. Il roster G0 storico resta13ruoli,non viene riscritto.

Nessuna mount copre /app/application.jar nel documento raccolto;byte del JAR e layer scrivibile non verificati. Lettura dei2file riuscita senza provider/credenziali/write;non ripetere helper. [Proposta concreta di custodia backup](OUF_STORAGE_OFFHOST_BACKUP_CUSTODY_20261106.md): copia cifrata fuoriVPS,prima opzione PC operatore oppure storage remoto già disponibile. Destinazione/custode/finestra non inventati;serve ora la scelta del mezzo di custodia,non un'altra lettura diagnostica.

# MinIO → SeaweedFS: procedura proposta con fermo completo

Stato: **DRAFT — NON ESEGUIBILE / NON AMMESSA**. Base repository deploy f02ba458a7e536c848abca001154dbf5f665a16e; source d5155899b09dda298494b68cefa7e1f281167652. Questo documento seleziona una procedura da completare e qualificare, non autorizza deploy, grant, stop, copy, switch o riapertura. [Piano strutturato](../releases/storage-offline-cutover-plan-20261106.json).

## Scelta e perimetro

Prima scelta: copia completa con tutti i writer fermati e verifica di una baseline comune DB/oggetti. I120corpi osservati rendono ragionevole valutare questa strada prima di implementare delta online; numero e durata reali devono essere ricontrollati nella finestra ammessa. Non si deduce un RTO dal numero di oggetti o dai tempi sintetici.

Conservare bucket/key, contenuti, metadati richiesti, riferimenti DB, campioni profile in PostgreSQL, tenant NULL e prove originali. Le etichette diagnostiche non sono oggetti S3. La migrazione non attribuisce proprietà ai10asset legacy. Non modificare il risultato originale con18rilievi: la disposizione è un documento separato. Un eventuale cambio di endpoint/riferimenti persistiti richiede una trasformazione esatta, qualificata e approvata; non un replace globale.

Fonte corrente: [ricevuta operatore](../evidence/storage-g0-final-local-review-operator-20261106.json) e [dossier](OUF_STORAGE_G0_FINDINGS_DISPOSITION_20261106.md). Osservazioni al momento della raccolta, non attestazione live. Le autorizzazioni delle raccolte01/02 sono consumate e non sono utilizzabili per questa procedura.

## Binding già noti e lacune concrete

| Elemento | Evidenza disponibile | Condizione ancora necessaria |
|---|---|---|
| Sorgente | MinIO image ID sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e; percorso privato vincolato nell'input G0 | Binding corrente di processo/rete/mount e capacità; image ID locale non equivale a digest manifest OCI |
| Destinazione proposta | /var/lib/ouf-storage-migration/seaweedfs, creata e osservata vuota nella preparazione | Custodia, capacità comprensiva di crescita/restore, topologia e TLS ammessi |
| Staging backup | /var/lib/ouf-storage-migration/backup-staging | È sullo stesso device della sorgente: serve una copia indipendente con custodia e restore verificati |
| Candidato | OCI33 sha256:3b972a3ca20f98b73554f0772a2df4f1a5ef4441298299a443f0e605f10ec9b6; lock SHA256 c2b30130b078a86ca440351980c3e745d4132e256591ec05fe98a9bdfc9058f8 | Nessuna ammissione operativa; licenze, custodia durevole, scansioni valide e coorte finale restano G1 |
| Servizi |13ruoli tutti running e non paused nella raccolta;132fuori roster di cui1running | Identità del restante risolta come ouf-etcd;funzione/accessi effettivi e consumer esterni ancora da provare;assenza di mount/binding storage non esclude un writer via rete |
| Oggetti e DB |120corpi verificati/referenziati,353righe di proiezione;4campioni DB,2label,2payload fisicamente collegati | I3export di proiezione non sono backup DB completi e non provano un common-cut |
| Accessi |2bucket senza policy; grant CanonicalUser FULL_CONTROL senza ID; publicAccessBlock unsupported | Protezione effettiva ed equivalenza autorizzativa sul target; non dedurre anonimato né sicurezza |
| Feature osservate |Versioning Status/MFADelete NOT_SET;0destinazioni notifiche; EventBridge assente | Contratto delle funzioni richieste dai consumer, incluse quelle non ricavabili dai dati già presenti |

### Coorte applicativa: scelta di sviluppo e origine conservata

[Decisione e confronto esatto](OUF_STORAGE_COHORT_DECISION_20261106.md). La catena conservata associa l'immagine7b9d3e91 ai sorgenti testati73498c17/revisionati9d19fad3, stesso tree091a10a5. La label container194b5865 non è la fonte di identificazione. Non è una lettura del JAR attualmente in esecuzione.

Confermata per lo sviluppo la candidata già proposta d5155899 (intero modulo), OCI33, UDP0d40 e Ingestion4165. Delta Onboarding:58file/20Java produzione eV39–V41;qualifiche native riusate,integrazione del servizio e dipendenze client ancora aperte. Non introdurre HTTP/HUMAN senza operazione concreta che lo richieda.

**Fermo esterno durante startup:** V39 crea controllo locale ACTIVE; questo non deve poter riaprire traffico. Mantenere isolamento e inibizione dei writer durante migrazioni,verifiche e fino alla decisione distinta. Nessun downgrade DB distruttivo per tornare al vecchio servizio.

### Pacchetto di contenimento dei writer

[Matrice strutturata](../releases/storage-offline-writer-containment-20261106.json):9percorsi applicativi associati a3owner;2percorsi amministrativi/esterni senza censimento completo. Le image ID sono quelle osservate e vincolate nella raccolta G0,non dichiarazioni di attività dei singoli job.

| Owner da contenere | Percorsi | Effetto del fermo proposto |
|---|---:|---|
| Onboarding |3|Interrompere nuove ammissioni e drenare upload/profile; poi fermare intero owner e impedirne ricreazione/restart |
| Ingestion |2|Fermare nuovi claim e drenare esecuzione/replay e ACK/outbox prima dello stop |
| UDP |4|Drenare store/shadow/purge/maintenance; includere writer DB anche quando non scrivono S3 |
| Amministratori e consumer esterni |2|Identificare credenziali,connessioni,scheduler e procedure manuali; applicare barriera anche ai client fuori Docker |

Il fermo dei3owner da solo non prova quiescenza. Servono barriera persistente al restart/ricreazione,blocco degli accessi mutativi diretti a S3/DB,risoluzione delle transazioni/effetti in volo e identità separata per backup/copia. Meccanismo esatto e comandi restano non qualificati;nessun stop o cambio privilegi autorizzato da questa matrice.

Lettura locale preparata: scripts/read-storage-g0-unmapped-runtime-20261106.py. Solo host-before e input base con SHA256 esatti: emette image ID del solo attivo fuori roster,indizi del nome limitati a registry/runner/backup (non ruoli autenticati),hash del nome/ID e conteggio mount che coprono il JAR Onboarding. Non stampa nomi/path/env privati,non legge il JAR,non contatta Docker o altri provider. Il risultato serve a restringere il censimento;non prova assenza di writer esterni o membership eseguibile. Esecuzione VPS riuscita:ouf-etcd identificato,0mount coprenti il JAR;ricevuta nel nuovo aggiornamento iniziale. Non ripetere.

## Sequenza e condizioni di arresto

| Fase | Azione prevista e prova di uscita | Arresto |
|---|---|---|
| Preparazione G0–G4 |Risolvere coorte, accessi, writer, custodia; accettare capacità/finestra/RPO/RTO; qualificare solo delta e scenari mancanti su binding rappresentativi |Qualunque input o prova obbligatoria mancante |
| Ammissione G5 |Pacchetto unico con hash, input privati, comandi esatti, attori, budget e scadenza; decisioni applicabili riferite a quel pacchetto |Nessuna autorità valida, digest/binding diversi o budget già consumato |
| Fermo |Bloccare nuove ammissioni da chatbot/API/worker/strumenti; drenare o riconciliare in-flight e outbox; fence durevole dei writer, poi verificare il fermo |Writer ignoto, ambiguo, non fermabile o effetto pendente; stop del solo Gateway insufficiente |
| Baseline e backup |Acquisire sotto fence inventario e backup coerenti di DB completi, oggetti, configurazioni e chiavi; copia indipendente e restore isolato verificato; sigillo della generazione |Nessun common-cut, backup solo sullo stesso disco, restore fallito o incoerenza |
| Copia |Avviare il target soltanto nel perimetro ammesso, copiare l'intera generazione con manifest/checkpoint e limiti; MinIO originale conservato sotto fence |Timeout/budget, risultato ambiguo, mutazione sorgente o differenza non riconciliata: niente replay cieco |
| Verifica e switch controllato |Confrontare tutti gli oggetti/metadati richiesti e riferimenti DB; verificare auth/TLS e percorsi applicativi ammessi; applicare binding del target con writer ancora chiusi |Parità incompleta, accessi più ampi, trasformazione DB non qualificata o nuovo writer |
| Riapertura G6 |Decisione distinta sulla generazione verificata; nuova pubblicazione/ammissione dove richiesta; riaprire gradualmente e osservare scritture/letture reali |Non riammettere automaticamente dopo restart/restore o sulla sola disponibilità PostgreSQL |
| Osservazione G7 |Finestra MiniPET proposta almeno48h, ciclo backup/restore e manutenzione rappresentativi; poi decisione separata su ritiro accessi MinIO/conservazione |Finestra non rappresentativa, divergenze, budget esauriti o ripristino non dimostrato |

Il censimento deve coprire tutti gli11percorsi mancanti: onboarding-human-upload, onboarding-delegated-upload, onboarding-profile-worker, ingestion-execution-replay, ingestion-outbox-ack-watermark, udp-store, udp-shadow, udp-purge-compaction, udp-maintenance, administrative-tools, external-consumers. Per ciascuno servono responsabile, binding, modalità di fermo e verifica. Censimento e decisione di fermo non sono la stessa cosa.

### Rollback: il confine è la prima nuova scrittura

Prima di qualsiasi nuova scrittura accettata sul target, inclusi test applicativi mutativi: mantenere i writer chiusi, verificare che la generazione sorgente sia ancora integra e coerente col DB, ripristinare i binding secondo il pacchetto qualificato. Riapertura sempre governata, mai automatica.

Dopo qualsiasi nuova scrittura sul target: bloccare nuove ammissioni, preservare entrambi gli store e DB, riconciliare effetti ambigui, riferimenti e mutazioni (aggiunte, overwrite, metadati, cancellazioni). Il semplice ritorno dell'endpoint a MinIO può perdere scritture confermate. Serve ritorno coordinato DB/oggetti qualificato oppure forward recovery governato; finché manca, **la riapertura con scritture è bloccata**. La rehearsal sintetica di ritorno degli oggetti non soddisfa questo requisito applicativo.

Non cancellare owner.database/latch, non azzerare budget con restart o nuova sessione, non mantenere fence locale durante query/attese. Chiudere Approved/Prepared ove usati; la riconciliazione dell'autorità termina REVOKED e nuova ammissione è separata.

## Backup, obiettivi e prove riutilizzabili

I piani esistono. La foundation del3novembre è sintetica; il backup semantic del7ottobre è parziale; la catena chatbot del16ottobre ha una correzione successiva per MCP, ma non attesta un backup attuale e indipendente dell'insieme DB+oggetti+configurazioni+chiavi. Non eseguire quei vecchi launcher né riusarne scope o autorizzazioni. Fonti: [foundation](OUF_SEAWEEDFS_452_RECOVERY_FOUNDATION_20261103.md), [semantic](../evidence/discovery-semantic-target-backup-20261007.json), [chatbot](../evidence/chatbot-mcp-backup-target-20261016.json), [correzione](../releases/CHATBOT_MCP_BACKUP_CORRECTION_20261016.md).

PET UDP §81 indica backup PostgreSQL completo+WAL/PITR e restore periodico; profilo oggetti con versioning/immutabilità o replica; obiettivi iniziali DB RPO<=15min e core RTO<=4h da confermare/validare. §89 richiede capacità/crescita rappresentativa, anche3xfootprint. Per il cutover è proposto RPO0 sulle scritture confermate, non ancora accettato. Durata massima del fermo, destinazione indipendente, custode e tempi misurati sono ancora non definiti. La Matrix §4 non equipara fixture a binding rappresentativi.

Riutilizzare senza riesecuzione immotivata:
- [client33](../evidence/storage-clients33-qualified-20261105.json):12casi su fixture, Onboarding d515 e UDP0d40; dipendenze fixture distinte, non interi servizi installati. [AT mapping](../releases/storage-clients33-acceptance-mapping-20261105.json) resta OPEN.
- [rehearsal](../evidence/storage-minio33-rehearsal-qualified-20261105.json):120corpi sintetici, crash/ambiguo e ritorno con4mutazioni; nessuna prova di rollback applicativo DB. Il configuration ID MinIO69b2ec20 della fixture coincide con quello collegato al root/native ID14cea493 del target nelle prove conservate; non è una diversa immagine dedotta dalle stringhe. La rehearsal resta sintetica.
- Artefatti CI client/rehearsal scadono il3febbraio2027: non sono custodia durevole.

## Prossima coppia utile

1. **Origine e scelta di sviluppo completate:** catena conservata dell'immagine ricostruita, candidata d515/OCI33 confermata e delta definito. Membership live e qualifica del modulo completo restano aperte;vedere decisione coorte.
2. **Fermo e ritorno:** completare il pacchetto operativo con censimento degli11percorsi e del container attivo fuori roster, evidenza di accessi, backup indipendente/restore, finestra e comandi legati ai binding. Uscita: proposta realmente eseguibile e reviewabile, o elenco minimo degli input che richiedono l'azione di Giovanni. Non richiedere ora un'approvazione al cutover incompleto.

MiniPET18,3/46=39,78%;0/8gate,0/21AT,0/120migrati. Questo runbook e la registrazione degli esiti non sono nuovi passi di migrazione e non aggiungono credito.

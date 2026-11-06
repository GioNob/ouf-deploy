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
| Servizi |13ruoli tutti running e non paused nella raccolta;132fuori roster di cui1running | Identità/funzione del container attivo restante e consumer esterni; assenza di mount/binding rilevato non esclude un writer via rete |
| Oggetti e DB |120corpi verificati/referenziati,353righe di proiezione;4campioni DB,2label,2payload fisicamente collegati | I3export di proiezione non sono backup DB completi e non provano un common-cut |
| Accessi |2bucket senza policy; grant CanonicalUser FULL_CONTROL senza ID; publicAccessBlock unsupported | Protezione effettiva ed equivalenza autorizzativa sul target; non dedurre anonimato né sicurezza |
| Feature osservate |Versioning Status/MFADelete NOT_SET;0destinazioni notifiche; EventBridge assente | Contratto delle funzioni richieste dai consumer, incluse quelle non ricavabili dai dati già presenti |

### Coorte applicativa: differenza da risolvere prima della qualifica finale

Onboarding dichiara194b586508c6661b40a74d9c7f99ed3b876f5fbc, image ID sha256:7b9d3e918beea500929cb9e3e88165b6c574cedac6067e56206fb2ffa1d65b51. La qualifica client33 usa d5155899. Confronto dei sorgenti Git esatti:

| Contratto |194b5865 dichiarato |d5155899 qualificato |
|---|---|---|
| ManagedFileStagingStore |put(InputStream,long,String) restituisce riferimento |putReserved(String,InputStream,long,String) usa riferimento riservato |
| MinioManagedFileStagingStore |UUID generato nell'upload; builder endpoint/credenziali |Riferimento già riservato; region us-east-1, retryOnConnectionFailure(false), callTimeout60s |

Sorgenti: [interfaccia194b](https://github.com/GioNob/ouf-source-onboarding/blob/194b586508c6661b40a74d9c7f99ed3b876f5fbc/src/main/java/it/comune/trieste/ouf/onboarding/application/ManagedFileStagingStore.java), [adapter194b](https://github.com/GioNob/ouf-source-onboarding/blob/194b586508c6661b40a74d9c7f99ed3b876f5fbc/src/main/java/it/comune/trieste/ouf/onboarding/application/MinioManagedFileStagingStore.java), [adapterd515](https://github.com/GioNob/ouf-source-onboarding/blob/d5155899b09dda298494b68cefa7e1f281167652/src/main/java/it/comune/trieste/ouf/onboarding/application/MinioManagedFileStagingStore.java).

Prima usare prove di consegna conservate per legare immagine, eventuali mount e classi effettive al sorgente; una label non basta. Poi scegliere esplicitamente tra qualifica della coorte installata e aggiornamento applicativo governato. Non sostituire un adapter isolato con interfaccia incompatibile. Non attribuire al servizio osservato i predicati tenant o le garanzie recovery del ramo più recente. Non introdurre HTTP/HUMAN come prerequisito generico: serve solo se la procedura concreta richiede quella capability.

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
- [rehearsal](../evidence/storage-minio33-rehearsal-qualified-20261105.json):120corpi sintetici, crash/ambiguo e ritorno con4mutazioni; nessuna prova di rollback applicativo DB. MinIO di fixture differisce dall'immagine osservata.
- Artefatti CI client/rehearsal scadono il3febbraio2027: non sono custodia durevole.

## Prossima coppia utile

1. **Coorte e copertura:** ricostruire dalle prove di consegna la coorte realmente installata, scegliere la coorte finale e produrre il delta esatto di qualifica G1/G2. Uscita: mapping fonte→build→immagine/classi→binding, con lacune esplicite; non un nuovo conteggio di test generici.
2. **Fermo e ritorno:** completare il pacchetto operativo con censimento degli11percorsi e del container attivo fuori roster, evidenza di accessi, backup indipendente/restore, finestra e comandi legati ai binding. Uscita: proposta realmente eseguibile e reviewabile, o elenco minimo degli input che richiedono l'azione di Giovanni. Non richiedere ora un'approvazione al cutover incompleto.

MiniPET18,3/46=39,78%;0/8gate,0/21AT,0/120migrati. Questo runbook e la registrazione degli esiti non sono nuovi passi di migrazione e non aggiungono credito.

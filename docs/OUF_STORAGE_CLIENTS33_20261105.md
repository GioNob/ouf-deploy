# Client applicativi correnti sulla SeaweedFS OCI33 esatta

Questo dossier collega la qualifica degli adapter applicativi al candidato finale dello storage. Le prove storiche dei client usavano una generazione precedente; inoltre Onboarding corrente espone `putReserved` al posto di `put`. La nuova fixture importa senza modifiche le cinque classi originali da Onboarding `d5155899b09dda298494b68cefa7e1f281167652` e UDP `0d40da05408a14db31d4d41af2372d6a71480291`, conserva i due POM originali e compila il contratto contro l'OCI33 esatta. Non assume che questi commit siano installati sul target.

La [ricevuta](../evidence/storage-clients33-qualified-20261105.json) è la fonte dei risultati, degli identificativi e dei digest. Il workflow usa Java21, endpoint TLS, namespace con sola loopback e nessuna rotta/porta pubblicata; il server ha rootfs read-only, capability rimosse e risorse finite. Maven risolve le dipendenze prima dell'isolamento; la prova esegue offline, senza retry AWS nella fixture. Il codice degli adapter e il vecchio contratto SeaweedFS restano intatti.

## Risultato verificato

Run42100237756/job127500797778, commit `1d6173e2b6dfc25279c6ad9f31cc4106772b0932`: **12/12 test PASS, zero errori/fallimenti/skip; scan zero rilievi e stop pulito**. Archivio13448767414,365853byte,SHA256 `1e2d0e1bf06a787459dbcd02f741b0391e3add6fb73165f1ce96addf31ae5d92`; custodia Actions fino3febbraio2027, non durevole. Readback locale22membri/21checksum,127sorgenti deploy e7applicativi confrontati coi tre alberi Git esatti. Tre alterazioni con checksum ricalcolati respinte: omissione sorgente, falso credito AT e commit applicativo alterato. Non è una seconda esecuzione nativa.

## Cosa copre il contratto e cosa resta aperto

| Criterio MiniPET | Casi della nuova fixture | Residuo di accettazione |
|---|---|---|
| AT01 — provenienza e sicurezza | Binding del publisher/coorte/OCI; cinque classi e due POM originali; scan bloccante dei JAR della fixture | Dipendenze e immagini dei servizi completi, G1 licenze/lifecycle/custodia; la fixture non aggiorna i POM applicativi |
| AT02 — staging | CSV e Content-Type, stesso riferimento riservato e stessi byte; 10MiB, oltre limite, MIME e riferimenti invalidi | Flusso applicativo installato, asset/intento/DB e rifiuti E2E |
| AT03 — UDP | PUT/HEAD/GET/DELETE dell'adapter, hash ricalcolato dai byte e metadati | Coerenza del catalogo applicativo e lineage reali |
| AT04 — multipart | Upload10MiB, upload incompleto inventoriabile senza oggetto pubblicato | Retry/interruzione/abort/cleanup completi; la presenza del multipart incompleto non prova cleanup |
| AT05 — paginazione | 1003chiavi, controllo duplicati/presenza; Unicode e caratteri riservati | Profilo applicabile e inventario reale senza omissioni; non solo insieme sintetico |
| AT06 — namespace/delete | Delete di una chiave senza rimuovere il prefisso simile | Tutta la matrice `a`, `a/b`, slash finale e collisioni reali |
| AT07 — policy | Dinieghi cross-bucket, credenziale sconosciuta, prefisso vietato, delete staging e POST form | Anonimo/admin/tenant e identità effettive installate; non inferire assenza di accessi esterni |
| AT08 — rete/segreti | TLS reale e rifiuto trust vuoto; container senza egress/porte pubblicate | Accessi laterali e binding target, firma invalida, custodia e rotazione operative |
| AT09 — caratteristiche | MIME/hash, Unicode, due versioni e delete marker nella fixture | Funzioni realmente richieste, tag/hold/retention/cifratura/notifiche/presigned applicabili; nessun credito di migrazione versionata |

Tutti questi AT restano OPEN. Le altre prove esatte OCI33, incluso il rehearsal MinIO→OCI33/ritorno e restore/rotazioni già qualificati, si riusano nei rispettivi perimetri: non sono state rieseguite. Non si trasferiscono automaticamente le prove di generazioni precedenti. L'archivio client non contiene un servizio completo, un database applicativo, un IdP remoto o un passaggio operativo.

## Blocchi emersi e correzioni limitate

Il primo candidato `689734a7dd7e5595245251fe9a19667f6f7b8d1b`, run42098209864/job127493764483, è stato fermato **prima dell'avvio nativo** da `CLIENT_SECURITY_GATE_HELD`. Il rapporto Trivy grezzo rileva due HIGH: CVE-2026-54399 (`httpcore5`5.3.6) e CVE-2026-54428 (`httpcore5-h2`5.3.6), più MEDIUM CVE-2026-64607 (`httpclient5`5.5.2). Nessun ignore o esenzione aggiunto.

Il candidato `d7f6af85aa77d4901d228dfce7518603c48792c3` seleziona nella sola fixture HttpClient5.6.5 e HttpCore5.4.4. [Note ufficiali Apache](https://hc.apache.org/news.html) confermano la coppia stabile; lo scan e l'esecuzione effettivi, non le note, determinano la qualifica. Le versioni restano distinte dalla chiusura delle dipendenze dei servizi originali: non dichiarare risolta la sicurezza dei deployment Onboarding/UDP. Conservare il primo ZIP13449360247,355147byte,SHA256 `0e57ceab45c0d3a5e45e2b44edcf420a015555a9fd3e8cc60edc9690b5ee22be`, scadenza3febbraio2027.

Il secondo tentativo, run42099114105/job127496926140, supera lo scan con zero rilievi e avvia/arresta pulitamente OCI33, ma esegue zero test: JUnit segnala `OutputDirectoryCreator not available` per launcher/engine disallineati. Il candidato `d731634985c93188dcdbe381112e0c433c89703f` allinea il launcher6.0.3 nel provider e nel classpath di test. ZIP13448332025,360957byte,SHA256 `048a82c27664fbe0dbe06441258382a2569e4a3cc026f96264530a46f6ff4491`. I primi due ZIP sono stati riletti localmente:14/21membri,13/20checksum e127sorgenti deploy esatti per ciascuno; integrità verificata, qualifica fallita conservata.

Il terzo tentativo, run42099690705/job127498919751, esegue ancora zero test: l’override del launcher nel realm del plugin escludeva dalla preparazione offline la versione1.12.2 richiesta internamente da Surefire. Il candidato `1d6173e2b6dfc25279c6ad9f31cc4106772b0932` mantiene il launcher6.0.3 soltanto nelle dipendenze di test e conserva la risoluzione interna originale del provider. Scan zero rilievi, server arrestato pulitamente; archivio13450270047 verificato localmente, digest e contatori nella ricevuta. Nessuna asserzione funzionale indebolita.

Separatamente, la CI del precedente checkpoint466209aa si è chiusa50/51SUCCESS: run42083213153/job127441412782 falliva nella fixture `m2_admitted_provider_sealed_worker_native.py` quando chiedeva nuovamente l'ID owned dopo le attese di recupero. Diniego osservato: `CURRENT_EXPLICIT_DISCOVERY_INSTALLATION_AND_NORMAL_USE_DECISION_REQUIRED`. Il nuovo test acquisisce l'ID esatto all'inizio, mentre l'autorità sintetica è corrente, e lo conserva per il successivo SIGKILL di laboratorio. Nessuna modifica a TTL, guard, policy, recupero o autorità di produzione; non si attribuisce ai log una misurazione della scadenza non presente. Run42098209923 e42098229380 qualificano la correzione della fixture; consultare la ricevuta per lo stato finale.

## Chiusura dello storage

Il primo passo di questa coppia produce la [richiesta unica G0](OUF_STORAGE_G0_COLLECTION_REQUEST_20261105.md), otto sezioni e undici percorsi writer. È REVIEW_READY_COLLECTION_NOT_EXECUTABLE: **collector target completo ancora mancante**, nessuna raccolta reale eseguita e nessun comando pronto da approvare. Servono implementazione del collector corrente e join DB/oggetti, poi esecuzione unica con perimetro ammesso e contributo dell'operatore su finestra e consumer esterni. I controlli13–17 non si riaprono.

MiniPET invariato18,3/46=39,78%;0/8gate,0/21AT,0/120oggetti reali. Nessun merge/deploy/grant/riapertura, nuova autorità o reset budget. Il JSON storico e il source-lock sono invariati. Questa coppia riduce l'incertezza sui client e rende esplicito il lavoro G0 ancora da consegnare; non chiude la sostituzione.

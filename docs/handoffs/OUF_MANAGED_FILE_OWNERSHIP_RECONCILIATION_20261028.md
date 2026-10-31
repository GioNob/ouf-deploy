# SUPERSEDED — lettura riuscita e consumata, correzione V38 qualificata

Seguire soltanto [handoff corrente V38](OUF_MANAGED_FILE_OWNER_RECOVERY_V38_20261028.md). La precedente lettura target è riuscita; il NEXT e le qualifiche sotto descrivono il checkpoint storico precedente e non autorizzano replay.

# OUF — ownership persistente, confronto Farmacie/Teatri — 28 ottobre 2026

## Stato acquisito e limite attuale

L'utente ha aperto la THS dello stesso asset/job e riportato HTTP403, **ONB_FILE_OWNER_SCOPE_UNPROVEN**, correlazione **e8c96213-6537-42c1-a726-311d6eb7898a**. [Osservazione](../../evidence/managed-profile-ths-ownership-denial-20261028.json). Il messaggio dichiara che nessuna azione è stata inviata. Browser esclusivo dell'utente; l'agente non lo ha aperto. Nessun budget o resume inviato dal connettore o da questa preparazione.

Nel codice installato `ManagedFileService.requireTenantOwner` richiede `uploaded_by=subject` e una ricevuta persistente upload oppure review sorgente nello stesso tenant/subject. Questo controllo precede card e policy di recupero e non contiene una scadenza. Il superamento dei900secondi non spiega questo codice. La finestra della recovery decorre dalla concessione del budget; l'ultima prova target è FAILED/tentativi5 e zero budget/eventi.

L'APPLY THS è riuscito e **CONSUMATO**: [ricevuta completa](../../evidence/managed-profile-ths-request-update-target-20261028.json), [output originale integrale](../../evidence/managed-profile-ths-request-update-target-20261028.log), [handoff installazione](OUF_MANAGED_PROFILE_THS_REQUEST_INSTALLED_20261028.md). Review0990401fb938c73c13bd6be090c04a5291bfe52aa06d9546cdaf7e13659a10b8; authorityce93c610fee96883a11fb806d283565340ffe6d1e6e629acf883eaabae0956ba. Scope `/etc/ouf/deploy-snapshots/managed-profile-ths-request-update-e22a443d-20261028-v1`. Non riconsegnare, rieseguire o riapprovare. La scadenza dell'authority conclusa non rimuove la configurazione installata. Anche tutti i predecessori sono consumati.

Onboarding installato: source9890b31868641e5be43c949a56f4ef69dd23bdfd, native sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3; generazionePID3462703/start88998673, binding2c5295203d6f190e04f2add429a617be69b2a72dd264b45f241a80d1aac09d0b. Schema36,12peer invariati compreso MCPd2454f3cb8cd410d284b9dc78349a170187aea1c/a52180123104ac97e4979ad1b9b291654b076692da51708bb2a377301fef1220; Registryworker intatto. Backup735390byteSHA5cdda140c580e2fe69df57366ac6725d302ec126854cef32799d2f0c10056a6f verificato. Nessuna reinstallazione o migrazione da ripetere.

Policy56 SERVICE e Policy58 ruolo exact-job restano acquisite. Non riproporre grant temporanei, descrittori, ruoli o correzione IAM. Identità browser/tenant e ownership correnti non sono ancora provati. L'ultima verifica connettore esplicita ouf-admin non sostituisce la sessione browser.

## Lacuna di produzione verificata nel sorgente

Il percorso nativo `ManagedFileStagingApi`/`ManagedFileApi.register` registrava soltanto il soggetto; il percorso delegato registra anche una ricevuta tenant/subject. Una sorgente già revisionata, come nel percorso Teatri, può fornire la seconda prova ammessa dal controllo. Un file nativo ancora fermo prima del profiling può non avere né upload receipt delegata né review. Questo è un difetto di composizione del percorso, non la prova che i dati Farmacie abbiano esattamente tale condizione: serve la lettura seguente.

[PR53](https://github.com/GioNob/ouf-source-onboarding/pull/53), source **bd113e7f8c428d7c167142e1f38df0db12b3b3e6**, aggiunge la prevenzione persistente:

- V37__managed_file_intake_tenant.sql: tenant nullable sull'asset; nessun backfill dei file storici. Tenant e uploader immutabili; status e source binding mantengono le transizioni esistenti.
- `registerOwned`: nuovo asset e tenant autenticato nella stessa transazione. Identica registrazione riconciliata; tenant/soggetto diverso o asset storico unbound negati, senza adozione.
- Native staging/registration e delegated intake persistono il tenant dal principal verificato. Il client non lo sceglie nel body.
- ASSETS e recovery riusano lo stesso predicato. Le prove upload/review preesistenti, incluso il percorso Teatri, restano ammesse solo per righe legacy NULL. Una ricevuta contraddittoria non supera un tenant esplicito.
- Test PostgreSQL: persistenza attraverso nuova istanza servizio, card FAILED5 senza budget/resume, isolamento tenant/soggetto, concorrenza, immutabilità, rifiuto dell'adozione legacy. Test upgrade reale36→37 conserva asset/job/quarantena/storia e zero budget/eventi; test35→36 fissato a36 per restare storico.

**Sorgente candidato, NON INSTALLATO.** Il VPS resta schema36. La migrazione37 e una nuova immagine richiederebbero piano/fence/review nuovi dopo la riconciliazione; questo handoff non consegna un APPLY. V37 da sola non risolve una mancanza di provenienza storica e non attribuisce il file a un tenant.

Il primo giro CI ha trovato il test storico che migrava fino all'ultima versione anziché36; il test è stato fissato e aggiunto il37 separato. Sourceac55f2b045994c02781648b467d3e246d5bcd6dd ha347test/0fail/0error/0skip. Lo scan della nuova immagine ha poi segnalato tre HIGH preesistenti transitivi: Guava33.4.8-jre e Snappy1.1.10.7. Sourcebd113e7f gestisce Guava33.7.2-jre/Snappy1.1.10.9; nessuna esclusione o riduzione dello scanner. Esiti finali, job e limiti sono nella [qualifica corrente](../../evidence/managed-file-ownership-reconciliation-qualified-20261028.json). Non confondere unit/runtime CI, immagine o manutenzione con E2E applicativo.

## Lettura nuova, nessuna riparazione

Source reader **f7a7199f26bc89a6533c4e7e17314af48d0d88b5**, scriptSHA **14ccad386c764663b6ce03ce23bb77fe134ab6bed6fcb5c67aeef30d9a79747a**. Builder persistente `tools/build_managed_file_ownership_reader.py`, contratto/controllore `tools/managed_file_ownership/{contract,reader}.py`. Riusa esattamente custodia privata, pin processi e EngineUnix/SO_PEERCRED del percorso precedente, senza invocarne main, review, authority o contatori.

Wrapper **0278b2c84c525cced1471d6ffa851ce8844580b8**, SHA **292a16fd2abaf2057898f3238069c15173dbf4f7e1da4d709b39281023bed1e7**. Qualifica consegna **3aab13a60b82717a1c489bbdd80d27a0c169e05c**. Nuovo scope esclusivo **/etc/ouf/deploy-snapshots/managed-file-ownership-read-0990401f-20261028-v1**, NON ESEGUITO. Codice root0400 in `/usr/local/lib/ouf-managed-file-ownership-read-14ccad386c764663/read.py`, operator.log root0600 nella stessa directory. Primo STOP/claim consuma il nuovo scope: conservare prove, non rilanciare. Non dedurre effetti assenti da un errore.

Limiti nuovi, indipendenti dai predecessori: **90secondi,24MiB,3metadata,5GET Engine,UNA SQL**. I metadata sono esclusivamente review.json/result.json/recovery.json del successo THS fissato. I valori privati Env/config nei metadata possono contenere credenziali preesistenti: restano root0600 e non vanno pubblicati. Non vengono aperti file di configurazione, credenziali, token o chiavi.

I5GET sono info e due osservazioni ciascuna SOLO di Onboarding e PostgreSQL. Pin del successo, root/boot/processi/socket/peer e generazioni verificati prima e dopo. CLI Docker già qualificata, isolata con config vuota e ambiente pulito; nessun cache credenziali. UNA transazione `REPEATABLE READ READ ONLY`, default read-only imposto, statement5s/lock1s/processo20s, ROLLBACK. Riserva fsync prima del dispatch; stdout/stderr privati e ricevuta prima del parser/guard finale. Nessun retry o nuova sessione dopo ambiguità.

Confronta esclusivamente:

- Farmacie asset **9c502da5-b5d8-405e-b3f5-60eb31ecb513**, job **677480c8-3d10-44fd-9dad-f72ddeed20a4**. Originale13903byte, hashsha256:f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311.
- Teatri asset conservato **6609b245-86ed-4315-8ce0-73f2a8555bf3**, già documentato in [prova autorizzata](../../evidence/teatri-authorized-profile-20261011.json). La sua lettura storica non prova la ownership Farmacie odierna.
- Principal ATTESO ouf-admin, subject **b93d8cf6-cd14-4ee6-91d7-84cd76c4f500**, tenant **ouf-lab**. Non dedotto dal nome SSH/IAM e non dichiarato come identità browser osservata.

Output soltanto hash/dimensione asset, bool di match uploader/prove tenant, contatori ricevute e stato/tentativi/versione/generazione/presenza sessione del job esatto. Nessun uploaded_by estraneo, ref storage/fileId/filename, last_error, campione o byte CSV. Distingue uploader diverso, uploader atteso senza prova tenant e predicato atteso provato ma identità browser ancora ignota. Se Teatri non è presente lo dichiara, senza sostituirlo con altri asset.

Zero scritture DB, lifecycle, import, IAM/OAuth, grant, budget/resume, job/upload/acquisizioni/attivazioni, firme/authority runtime. Nessun Registryworker toccato. Il codice può solo osservare; una correzione storica resta successiva alle prove.

## Consegna all'operatore

Usare il comando seguente soltanto quando la qualifica collegata conferma `currentDeliveryUsable=true`. Come **oufadmin** sul VPS, TTY interattivo; può richiedere sudo, nessun login IAM o APPROVO. Non confondere SSHoufadmin con identità applicativaouf-admin.

Comando storico rimosso dalla consegna: reader eseguito con successo e scope CONSUMATO. Non rilanciare.

Riportare JSON finale/Exit/Directory/Log/DeliveryExit/DeliveryDirectory/DeliveryLog. Non inviare dump, metadata privati, credenziali, token o wrapper backend THS/CSRF. Se STOP conservare e non rilanciare; riconciliare quello stesso scope senza nuova lettura automatica.

## Dopo la lettura, vincoli invariati

Se manca una prova tenant storica, non inferirla dal superadmin o dal nome del file. Distinguere l'effettivo principal browser e verificare la provenienza originale; preparare solo una riconciliazione owner governata con prove e review concrete. Se il predicato atteso è già provato, indagare il principal/tenant effettivo del Gateway/browser. Non ripetere login/grant alla cieca e non installare il candidato37 come sostituto di una prova.

La THS resta esclusiva dell'utente. Inviare nuovamente il link esatto soltanto quando necessario dopo una correzione verificata:
https://api.ouf-lab.it/trusted-human/managed-files/recovery/?asset=9c502da5-b5d8-405e-b3f5-60eb31ecb513&job=677480c8-3d10-44fd-9dad-f72ddeed20a4

Dopo accesso/stato/review freschi: **budget3tentativi/900s** e poi **resume** sono DUE decisioni HUMAN distinte sullo STESSO job/sessione; cumulativi6–8, mai azzeramento. Esito ambiguo: stesso comando/sessione, nessun altro budget. Poi originale/hash/parser/preview, Farmacie61righe/10colonne UTF8BOM/semicolon, semantica/Ingestion/UDP/provenance, D5–D7 e dueclient. Riutilizzare Teatri/M1/typed/ASSETS/LATEST, nessuna terza acquisizione.

M1/G4 acquisiti; M2/G5/G6/G7/E2E ancora aperti. Supervisor dopo E2E completo. No reset/nuovo upload/job/acquisizione di aggiramento/attivazione implicita/Registryrestart o reinstall/merge/release acceptance/subagenti/automazioni. [Piano M2](../../releases/csv-m2-plan-20261026.json),[roadmap](../OUF_M2_ROADMAP_20261026.md),[industrializzazione](../OUF_MANAGED_PROFILE_THS_INDUSTRIALIZATION_20261028.md). PET originali non esposti nei file correnti: nessuna nuova pretesa di lettura integrale.

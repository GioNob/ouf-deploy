# SUPERSEDED — preparazione V38 riuscita e consumata; nuovo controller qualificato

Seguire soltanto [handoff corrente aggiornamento nativo V38](OUF_MANAGED_FILE_OWNER_V38_NATIVE_UPDATE_20261028.md). I NEXT e le qualifiche sotto descrivono il checkpoint storico precedente. Non autorizzano replay.

# OUF — immagine esatta V38 e piano condizionale del solo Onboarding

## Stato corrente, 28 ottobre 2026

La [nuova cattura target](../../evidence/managed-file-owner-inputs-target-20261028.json), [output riportato](../../evidence/managed-file-owner-inputs-target-20261028.log), è riuscita: complete/Exit0/DeliveryExit0, hash inputs **8a4c84756a663c3eb3a6b6c615d5efccf0c67b3c6ac2281ff9633c9a93de6224**, hash canonico risultato **e79af0afea1ae9518cbb9dea9f45efbf423757e1d5786cca7255308392d9ffb1**. Scope `/etc/ouf/deploy-snapshots/managed-file-owner-recovery-inputs-1c0cff56-20261028-v1` CONSUMATO: non riconsegnare/rilanciare il comando, non richiedere nuovamente il log.

4 metadata,27 GET Engine,719512 byte; coorte esatta13 e12 peer conservati. Zero SQL,configfile/credenziali/chiavi,IAM/OAuth,import/lifecycle/ownership/grant/budget/resume/acquisizioni. Contabilità dalla lettura ownership:7metadata/32GET/1SQL/1293351byte; non contabilità dell'intero progetto. Questa cattura non osserva nuovamente DB/job/budget o identità browser. Directory `/home/oufadmin/ouf-managed-file-owner-inputs-delivery.3os8j8LW`; log root `/usr/local/lib/ouf-managed-file-owner-inputs-f5fe26b895ca600d/operator.log`; bootstrap nella directory di consegna. L'ultima riga incolla DeliveryDirectory e DeliveryLog adiacenti: entrambi interpretati, nessuna richiesta di ripetizione.

La precedente [lettura ownership](../../evidence/managed-file-ownership-read-target-20261028.json) rimane acquisita e consumata: Farmacie ha uploader atteso ma nessuna prova tenant; Teatri ha reviewtenant/subject esatta. Farmacie asset **9c502da5-b5d8-405e-b3f5-60eb31ecb513**,13903byte,hash **sha256:f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311**; stesso job **677480c8-3d10-44fd-9dad-f72ddeed20a4**,ultima osservazione FAILED/tentativi5/version0/generation0,un job,nessuna recoverySession,zero sessioni/eventi. Principal atteso ouf-admin subject **b93d8cf6-cd14-4ee6-91d7-84cd76c4f500**,tenant **ouf-lab**: non è prova del principal browser. Il403 ownership non è causato dalla durata900s di un budget.

Produzione resta Onboarding **9890b31868641e5be43c949a56f4ef69dd23bdfd**,native **sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3**,schema36. Ultimo APPLY THS riuscito/consumato,review **0990401fb938c73c13bd6be090c04a5291bfe52aa06d9546cdaf7e13659a10b8**,authority **ce93c610fee96883a11fb806d283565340ffe6d1e6e629acf883eaabae0956ba**,binding **2c5295203d6f190e04f2add429a617be69b2a72dd264b45f241a80d1aac09d0b**,PID3462703/start88998673. [Ricevuta APPLY](../../evidence/managed-profile-ths-request-update-target-20261028.json). Anche tutti i predecessori/IAM/publisher/review/authority/capture sono consumati. Policy56 SERVICE e Policy58 exact-job acquisite;MCPd2454f3c/a5218012 e gli altri12peer invariati,Registryworker intatto.

## Immagine e codice persistente

Source **9d19fad3dd750dd5b9e77253d3e7e82029c1aca7**,[PR53](https://github.com/GioNob/ouf-source-onboarding/pull/53), ancora NON installato.365test applicativi/0fail/0error/0skip,9browser reali,scan/bootPASS. V37 persiste tenant autenticato all'intake senza backfill; V38 crea una tabella append-only vuota per una decisione HUMAN esplicita dell'uploader originario. La futura decisione ownership è distinta da budget e resume e non cambia job/tentativi/quarantena/budget/eventi/sorgente/upload. Stesso comando/intento riconciliato dopo restart o risposta persa;storage browser indisponibile blocca il dispatch. [Disegno e qualifica sorgente](OUF_MANAGED_FILE_OWNER_RECOVERY_V38_20261028.md),[prove](../../evidence/managed-file-owner-recovery-v38-qualified-20261028.json).

Scaricato e verificato l'originale artifact CI **12836316286**,run **40732932645**,ZIP **213064533byte**,SHA **7719c1045753fe38bbdc498adb8f540c61bad411c25969badf71ec4d3ec5d91b**. TestedCommit **73498c17596ae155a3ed9ab36acfd6bb69da9846**,testedTree **091a10a53da04ed46759f345e877a69e8db87021**: il commit merge CI verificato non sostituisce il source commit revisionato. Nessun rebuild/import/relabel/release.

Riutilizzata la custodia Teatri `image_custody.py`: tutti i layer/config/manifest verificati,derivazione senza tag con byte invariati,un JAR111533336byte/SHA **152159de758ead299d53eaf9cf113c01445b7e1d6fa86590ba0a1248bf4ef681**. Config imageId **sha256:5140811b44623c7035843c955509a387336bc11ffb24b72ffe26a73434fb5ebd**; identità manifest nativo **sha256:7b9d3e918beea500929cb9e3e88165b6c574cedac6067e56206fb2ffa1d65b51**. Archivio nativo444405760byte/SHA **3c630445a142c45dfdf7e5ab5d8e2f7054f6e377e0fa15418037eb1c49bf3dc6**. YAML/ruolo non assegnato e tutte le36migrazioni esistenti identici;solo37/38 nuovi con SHA e CRC Flyway corrispondenti ai blob sorgente revisionati.

Lo ZIP originale è conservato su branch di sola consegna `delivery/managed-file-owner-v38-ci-20261028`,commit immutabile **def3a36da119d5cfc28704338b238028796b960a**,9parti≤24MiB. Workflow finito40751650814/job123039630879PASS: conserva gli stessi byte,nessun rebuild/import/release. PR53 resta9d19fad3. [Ricevuta immagine](../../releases/managed-file-owner-v38-image-custody-20261028.json),[qualifica completa](../../evidence/managed-file-owner-v38-image-plan-qualified-20261028.json).

## Nuova preparazione da eseguire sul VPS

Source preparazione **816b5cc6a06f8c3a6c092bf815fe183bebec9494**;wrapper **63d7370f50814adda04f8cdcaf40cd4d7f619e54**,SHA **f185922cea4d0b9980d46408fbc6778569adeffef830125b2bd9cc86e0a23919**;qualifica consegna **89d73ad5adf1f7b922982af53a726588fdf1f6a1**. Chiusura10file **83465836310ad2bdbe7552e87599fa7a5ee253661d825ea60326362efbc138ae**;codice root0400 in `/usr/local/lib/ouf-managed-file-owner-image-plan-83465836310ad2bd`.

NUOVO scope esclusivo **/etc/ouf/deploy-snapshots/managed-file-owner-v38-image-plan-8a4c8475-20261028-v1**,NON eseguito.3metadata del successo conservato:inputs.json/result.json/engine-get-1-response.json;nessuna nuova GET.1ZIP originale e1archivio nativo. Scaricamento finito senza credenziali,max720s;checksum di ogni parte e dell'intero ZIP,poi copia root0400 verificata. Preparazione300s;2GiB liberi richiesti. Nuovi metadata/piano root0400;logbootstrap privato0600. Config/Env contenuti nei metadata restano privati,non vengono letti file di configurazione o credenziali.

Compilatore persistente `tools/managed_file_owner_recovery/image_plan.py`,con custodia/rete/MAC/allocazioni del percorso Teatri già qualificato. Conserva l'intera request installata compresi scope THS,IP/MAC/porte/mount/resource policy; propone soltanto Onboarding,12peer invariati. Migrazione36→38 indicata come condizione futura,NON eseguita. Nessuna authority/APPLY. Zero Engine/SQL/IAM/OAuth/configfile/credenziali/chiavi/import/lifecycle/ownership/grant/budget/resume/job/upload/acquisizioni/attivazioni.

Qualifica separata:9test del compilatore,archivio CI originale/JAR/38migrazioni/manifest nativo reali e metadata runtime sintetici,porte/processi vietati,privati0400,predecessori invariati,no replay. CI non prova lo stato attuale del database né un E2E target. Consegna reale HTTPS/nonroot/sudo/root0400 con rifiuto di un seal privato errato,nessuna elaborazione archivio e conservazione dello STOP;verificare `preparation.currentDeliveryUsable=true` nella qualifica prima della consegna.

Come **oufadmin** sul VPS,una sola volta. Non richiede login IAM o APPROVO e non è un APPLY:

Comando storico rimosso: preparazione riuscita e CONSUMATA. Non riconsegnare/rilanciare.

Riportare nuovo JSON finale/Exit/Directory/Log/DeliveryExit/DeliveryDirectory/DeliveryLog. Non inviare archivio,metadata privati,token/credenziali. STOP o esito ambiguo conserva e consuma:non rilanciare,non eliminare file/root/log. Non ripetere i due reader ownership/current-input già riusciti.

## Passi successivi e lacune reali

Dopo la preparazione riuscita:qualificare un controller nuovo del SOLO Onboarding36→38 con snapshot/fence correnti,backup quiescente verificato,stesso asset/job/FAILED5/quarantena/zero sessioni-eventi e12peer invariati. Serve preservare tutte le righe operative,tenant storicoNULL e tabella owner receipt vuota;la nuova colonna non è una prova ownership. Poi nuova concreta review HUMAN e authority finita. Controller,review,authority,APPLY e migrazioni non sono ancora qualificati/autorizzati/eseguiti da questo checkpoint. Nessun riuso di authority precedenti.

Solo dopo manutenzione installata e verificata inviare all'UTENTE il link THS;mai aprirlo come agente:
https://api.ouf-lab.it/trusted-human/managed-files/recovery/?asset=9c502da5-b5d8-405e-b3f5-60eb31ecb513&job=677480c8-3d10-44fd-9dad-f72ddeed20a4

Tre decisioni HUMAN distinte con principal/stato/review freschi:ownership legacy;budget3tentativi/900s;resume dello STESSO job/sessione,cumulativi6–8,mai reset. Ambiguità:riconciliare lo stesso comando/sessione senza un altro budget. Verificare identità effettiva ouf-admin prima di chiamate governate;la sessione browser è esclusiva dell'utente.

Poi originale/hash/parser/preview,Farmacie61righe→UDP/provenance,D5–D7 e dueclient reali,riusando Teatri/M1/typed/ASSETS/LATEST. M1/G4 acquisiti;M2/G5/G6/G7/E2E aperti;Supervisor dopo E2E completo. No terza acquisizione/nuovojob/upload/replay/reset/attivazione implicita/Registryrestart o reinstall/merge/release acceptance/subagenti/automazioni pianificate. [Piano M2](../../releases/csv-m2-plan-20261026.json),[roadmap](../OUF_M2_ROADMAP_20261026.md),[industrializzazione](../OUF_MANAGED_PROFILE_THS_INDUSTRIALIZATION_20261028.md). PET originali ancora assenti dalle fonti esposte:nessuna dichiarazione di lettura integrale.

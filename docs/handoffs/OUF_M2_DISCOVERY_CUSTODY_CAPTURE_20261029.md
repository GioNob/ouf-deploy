# OUF — custodia discovery acquisita; scope consumato; preparazione coordinata

29 ottobre2026. [PR54](https://github.com/GioNob/ouf-deploy/pull/54). [Qualifica custodia](../../evidence/m2-discovery-custody-capture-qualified-20261029.json), [frame Docker reale](../../evidence/m2-discovery-native-frame-qualified-20261029.json), [owner nodo](../../evidence/m2-discovery-node-owner-source-qualification-20261029.json), [pacchetti](../../evidence/m2-discovery-native-witness-and-packages-20261029.json).

## Esito di questo avanzamento

Il percorso sorgente ora comprende profilo discovery distinto, proposta completa OCI a sette mount, tre capability con un solo scope, witness collegato aPausedNodeObservation, rientro13fasi alle posizioni9/10 e owner del nodo con recipe/phase-intent firmato. Il vecchio profilo file-only e il suo rientro7/8 restano distinti. L'owner rifiuta firma mancante, finestra scaduta, intent diverso anche se firmato, recipe mutata o transizione file-only.

Frame nativo verificato su Docker29.8.1/overlayfs/systemd/containerd, push40845016640/job123350264235 e PR40845022690/job123350284460, entrambiSUCCESS e log letti. La policy deriva dal baseline indipendente, non dall'OCI da controllare. Cinque file readonly e configtree DB osservati realmente; container in pausa e Java mai eseguito. La CLI riordinava Env: il qualifier usa ora l'effettiva API Engine JSON/Unix con peer root, senza modificare il confronto OCI. Immagine/input sono sintetici: token owner, IAM/provider/TLS, firma di accettazione target e E2E restano non provati.

Pacchetti MCP e Gateway prodotti e riletti indipendentemente: MCP imagea013bceb...,artifact12882394596,Go1.26.10/user10005:10005,9checksum/261blob/config/layer/binario verificati; Gateway artifact12882339953,6checksum/378blob/6file materializer verificati. Gate HIGH/CRITICAL/UNKNOWN inclusi unfixed PASS; report filtrati non dimostrano assenzaLOW/MEDIUM. Tutti i digest e limiti nel dossier pacchetti. Nessuna prova publisher trust o ammissioneOCI/rootfs host. Registry conserva il pacchetto qualificato già selezionato.

109PASS/0errori/0skip per esecuzione su push40846711261/job123355871936 e PR40846716178/job123355889523:102regressioni/profilo/owner e7nuovi test della custodia. File POSIX e proprietari/modi reali nel runner root, process/boot fixture esplicita con un test separato sul proprio processo Linux reale. Il runtime locale cloud non supporta chown/proc necessari: nessuna pretesa di qualifica POSIX locale.

## Perché la lettura richiedeva l'operatore

Il connector non espone accesso manutentivo al filesystem del VPS e non c'è un esecutore SSH collegato. La preparazione necessita della verifica locale dei candidati credenziale/chiave già creati dall'owner: non occorre scegliere nuovi segreti, recuperare budget o fare login IAM. Sono candidati storici, non authority corrente; la nuova lettura confronta impronte e metadata effettivi e ricontrolla i pin dei quattro processi e il boot prima/dopo.

Sono selezionati esattamente due metadata: inputsf759d397 e manifest732a633e del precedente rootsemantic-discovery-runtime-inputs-682nr5ky. Quattro file esatti: una credenziale provider, le due copie della chiave applicativa discovery (Registry/Gateway) e il CA pubblico. Massimo45secondi/4MiB; nessun valore grezzo di credenziale/chiave viene stampato o salvato. Le impronte specifiche restano nel record privato root0600. L'output pubblico riporta solo esito/counter/hash del nuovo record. File e scope preesistenti restano invariati.

ZeroEngineGET/write/SQL/IAM/OAuth/login/chiavi nuove/chiavi di firma deployment/firme/import/lifecycle/grant/budget/upload/job/resume/acquisizione. Il successo dimostra soltanto continuità e custodia di candidati: non validitàIAM, scopeOAuth, providerTLS, ammissioneDB, tutti13peer correnti o authority. Queste verifiche restano nel percorso coordinato successivo.

Il nuovo scope è `/etc/ouf/deploy-snapshots/m2-discovery-custody-f759d397-20261029-v1`, ora eseguito con successo e CONSUMATO sul target. È diverso dal vecchio scope f759, consumato e non rilanciabile. Riferimenti storici sono input di provenienza, mai un reset o una ripetizione delle vecchie authority.

## Esito target acquisito e comando ritirato

[Esito completo](../../evidence/m2-discovery-custody-target-20261029.json): `MATERIAL_CUSTODY_CANDIDATES_CAPTURED_NOT_ADMITTED`, candidateBindingHash `eed64887cfcf18dc4be6de32c954b67649adf72ff384c3296d4bfe21ba1188c5`, complete=true, scopeConsumed=true, OperatorExit=0/DeliveryExit=0. Quattro file e quattro pin di processo verificati,33558byte;2metadata,1credenziale,2copieMACapplicativa,1CApubblico. Nessun valore esposto;zeroEngine/SQL/IAM/OAuth/firme/nuovechiavi/import/lifecycle/grant/budget o effetti applicativi. La fonte è il JSON/footer incollato dall'operatore, non la lettura indipendente dei log o del record privato.

Directory `/home/oufadmin/ouf-m2-discovery-custody-delivery.3SS9XDP4`; log operatore `/usr/local/lib/ouf-m2-discovery-custody-834dd9b0b7e9f7b0/operator.log`, log consegna `/home/oufadmin/ouf-m2-discovery-custody-delivery.3SS9XDP4/bootstrap.log`. Il nuovo scope è RIUSCITO e CONSUMATO: non rilanciare bootstrap/reader, non cancellare o ricreare lo scope. Launcher ritirato. Il vecchio f759 resta riuscito/consumato. Nessuna nuova istruzione operativa pronta.

Una lettura effettiva della capability `ouf.system.status` conaccount `ouf-admin` restituisce MCP HEALTHY/actionRequired=false/partial=false, proiezionePUBLIC_OPERATIONAL redatta. Non è una prova della disponibilità delle nuove capability discovery o degli owner provider.

La preparazione usa il record privato esatto e le relative impronte localmente: non richiedere credenziali, chiavi o file privati inchat. Le proiezioni proposte saranno copie nel nuovo ambito protetto, senza mutare i file sorgente o generare nuovechiavi. Rimangono necessarie verifica del CApubblico e truststore, validitàIAM/scope, TLS/provider,Native/DB/cohort correnti,backup/fencing, pubblicazione governata e review/authorityHUMAN finite. Il compilerproiezioni7c6c28399897e52e8c7c32156516e34a9884a69e è inqualificaCI; non è ancora esecuzione.

## Dopo il risultato

Vincolare il record privato candidato alla preparazione completa e agli owner correnti: eventuali proiezioni di file devono rispettare UID/modi effettivi senza cambiare i file storici; validità della credenziale, scope del workload, chiave coerente APISIX/Registry e fiducia TLS richiedono ancora ammissione attuale. Preparare la review coordinata con generazioni correnti, backup/fencing/DBV11–V12, source/pacchetti/OCI/rootfs indipendenti, rinnovo e autoritàHUMAN finite quando richieste. Nessuna semplice accensione di flag o bare restart.

Poi installazione/pubblicazione governata e prova reale chatbot→MCP→Gateway→Registry→OntoPiA, stessa idempotencyKey/requestId e provenienza/snapshot, adozione/pubblicazione e sorgente canonica, fault/reboot/rotazione e due client. Le capability discovery non sono ancora esposte dal connector; tutti8criteri di stabilità edE2E sonoOPEN.

Farmacie invariato: asset9c502da5-b5d8-405e-b3f5-60eb31ecb513/job677480c8-3d10-44fd-9dad-f72ddeed20a4/profilof3061699-4fde-4085-89c8-bc8703f65686 SUCCEEDED,61righe/10colonne,ministerialeSTRING,CAPSTRING e10campiOPEN confermati. Nessun nuovo upload/profiling/budget/resume/acquisizione. M1/G4 acquisiti; M2/G5–G7/D5–D7 aperti. Nessun merge/releaseacceptance/subagente/automazione. Non sostituire OntoPiA con web/Turtle/ontologia locale.

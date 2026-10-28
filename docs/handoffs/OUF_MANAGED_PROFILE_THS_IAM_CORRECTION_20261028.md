# OUF — correzione IAM minima e persistente della recovery THS — 28 ottobre 2026

## Stato acquisito

[Ultima ricevuta integrale](../../evidence/managed-profile-ths-iam-binding-read-target-20261028.json): lettura riuscita,complete/Exit0/DeliveryExit0,identità amministrativa protetta verificata,1auth/14GET IAM/5GET Engine/2metadata/135305byte. **THS_IAM_BINDINGS_OBSERVED_CONFIGURATION_PROFILE_BLOCKED** significa che la lettura è completa e il profilo di configurazione è bloccato. Non è un errore di consegna o un nuovo mandato.

Parent resultSHA **bfbff1b10039bcca43ad587167bb0fe4314055866c214926daaf4c2570f3fa7b**,clientinputs5dfd7b7a...,baseline IAM **ba556e9fce5fb31de5f53af0bf6d3fe7a77e8e09d9048529d8283eaaa6afabc2**. Scope/read/comando precedenti CONSUMATI:NON rilanciare o riconsegnare. Directory/log in ricevuta; JSON letto integralmente in chat, log host NON riletto indipendentemente. Non richiederlo di nuovo.

Client **ouf-authorization-ths**,UUID **a53bc77e-1b21-4a54-8f1a-b236fadb759a**,realmouf,issuerhttps://auth.ouf-lab.it/realms/ouf; registrationIdouf-ths non è clientId.69definizioni,14DEFAULT/6OPTIONAL preservati. Previewe369f8fd... e file.profile226b20cd... sono definiti,include-token=true e senza restrizioni ruolo,ma bindingNONE. Quarantine.release è assente. Nessuna modifica IAM o runtime,grant,budget/resume/job/upload/acquisizione è avvenuta nel read. Policy58 resta PUBLISHED e il ruolo exact-job non va riproposto.

Richiesta Onboarding ancora cinque scope:openid,authorization.policy.admin,file.upload,resolution.issue.read,resolution.match.approve. Mancano preview,file.profile,quarantine.release. Nessun profilo Env pronto da applicare: binding e richiesta sono due gate distinti,token browser un terzo.

## Nuova correzione e revisione concreta

[Qualifica](../../evidence/managed-profile-ths-iam-binding-correction-qualified-20261028.json). Il compilatore riusabile iam_correction.py propone soltanto:

1. Creazione dello scope OIDC **ouf.onboarding.quarantine.release**,UUID preapprovato **3dbfa25c-89da-53ec-89b0-4ba6458017c9**,include.in.token.scope=true,zero protocol mapper e zero role mapping. Nessun Realm Default (tipo None). UUIDv5 e marker **ouf.provisioning.operation-ref** legano l'oggetto alla stessa operazione.
2. TRE link **OPTIONAL** allo stesso client:previewUUIDe369f8fd-fe4d-4fa2-8ff2-4cd806398417,file.profileUUID226b20cd-7798-4da9-af03-eb2bca3d2c5a,quarantine.releaseUUID3dbfa25c-89da-53ec-89b0-4ba6458017c9. OPTIONAL richiede richiesta OAuth esplicita; non sostituisce/defaulta i14DEFAULT.
3. Postcondizione:70definizioni,14DEFAULT/9OPTIONAL; tutte le69definizioni e tutti i20link precedenti restano esatti. Realm Default e proprietà client non credenziali invariati; nessun endpoint per aggiornare client,secret,ruoli/mapper o altri client è selezionato.
4. Solo dopo prova completa:compila configuration-profile.json privato600 col delta additivo delle richieste Onboarding sulla stessa immagine. Non installa il profilo e non emette authority/APPLY.

OperationRef **a258d03d9283225f938e658a01db474a949afe2bb206d127f96a56fd253b89e9**. Prima del login viene mostrata una NUOVA review con piano esatto,baselineHash,UUID,namespace/processi,limiti e hash. L'utente inserisce **APPROVO <hash mostrato>** e Invio nel TTY,poi password **IAM oufadmin** nascosta,distinta da sudo e dall'account applicativoouf-admin. Non inserire password/token in chat. Nessuna approvazione viene simulata sul target.

Si riusa tools/human_terminal_line_review.py:editing nativo,Backspace/Ctrl+U,riga errata correggibile entro gli stessi90s,max128eventi di input,nessun reset/deadline nuovo. Tutto è preparato prima di chiedere consenso; dopo il login l'identità è verificata con API protetta e lo snapshot deve uguagliare la review già approvata,altrimenti zero write. Così la review non consuma la breve vita del token.

È una nuova operazione amministrativa finita,non rinnovo del read. Parentauth1 resta consumata; nuovaauth al massimo1,catena read+correction al massimo2. Vecchie finestre/budget/claim/HUMAN e tutti predecessori APPLY/publisher/capture restano immutati. Appouf-admin e admintecnicoIAMoufadmin sono identità diverse.

## Codice, qualifica e persistenza

- Source **78282b120dffa063ff8bc86f96071de1f2e8766f**,scripts/correct-managed-profile-ths-iam-bindings-20261028.py,82522byte,SHA **3e3d665eaee8c9f4699259b52a5c8403ad64cf494e9cf92684fb6cf1b74eed1a**.
- Wrapper **dc848eba194a4e43abffcd97ba9791f37fc44884**,SHA **ca018484e6196366cd0c83f4ec17e09a6bc4b94a66bb871a2c4232a0a0db40d5**.
- Qualifica **8986be7b38b1ef7df6fe8a1b5fda3c4b987457ad**:push40697903097 e PR40697916270 PASS,81test/0skip (22nuovi+59preservati),matrixKeycloak26.0.8/26.2.5,due realm/client di fixture per versione,caso positivo e perdita di tutte le risposte di write.4write osservate/29GET per caso,nessuna write ripetuta,preesistenti e Realm Default preservati.
- Sei job/log diretti letti:push122849489267/122849489628/122849489632,PR122849536931/122849537614/122849537636. Consegna HTTPS/nonroot/sudo/root400/checksumROOT/private600/nonTTY-before-scope/STOP conservato/no replay PASS. Typo in un filename del solo test causava404 prima della source; corretto senza modificare wrapper/source.
- Sorgente riproducibile da tools/build_managed_profile_ths_iam_correction.py e receipt versionata. AST dei moduli/helper sigillati confrontato nei test; nessun vecchio main o cache/token invocato. Planner/trasporto/controller sono persistenti e parametrizzati,non una correzione manuale di database.
- Le fixture usano Docker/process-root/mount/netns/PTY e Keycloak reali; storia precedente/input e consenso sono soltanto di fixture. Non sono chiamate al VPS,identità browser o accettazione applicativa. Il server target è vincolato all'immagine/generazione già catturata,non si deduce equivalenza d'immagine dalla versione fixture.

Il guard già presente nel verificatore nativo tools/source_revision_update/configuration.py:verify nega un JAR con ManagedProfileRecoveryThs.class se la richiesta THS è incompleta. Non è provato che ogni bootstrap indipendente usi questo entrypoint. [Contratto di industrializzazione](../OUF_MANAGED_PROFILE_THS_INDUSTRIALIZATION_20261028.md). M2/due client reali restano aperti.

## Scope, custodia e limiti

Nuovo scope **/etc/ouf/deploy-snapshots/managed-profile-ths-iam-binding-correction-ba556e9f-20261028-v1**,NON ESEGUITO. Rootcode **/usr/local/lib/ouf-managed-profile-ths-iam-correction-3e3d665eaee8c9f4/apply.py**.

Tre letture metadata NUOVE:result.json del read IAM (hashbfbff1b1...),inputs.json5dfd... e result.json della selezione client precedente. Sono provenienza,non autorità riusata.7GET Engine:info e due owner Onboarding/IAM prima review,prima effetti e dopo. Socket/rootpeer,boot,PID/start/net/mnt,configurazioni/immagini,file/mount già letto e sigilli correnti;nessun contenuto config/credenziali/chiave aperto. Non adotta processi/URL/client arbitrari.

**600s totali;90s review e90s password;210s massimi dopo approvazione,ristretti a120s dopo password;min30s di token prima della prima write.3metadata/7EngineGET/1auth/29AdminGET normali,40massimi/4write IAM/24MiB.** GET transitorie:stesso stage/token/deadline,5/15s+jitter20%,max3/stage e4retryglobali,Retry-After entro finestra originale. Nessun refresh,login automatico o vecchio budget riaperto.

Claim fsync prima dispatch e receipt HTTP fsync **prima** di parser/guard/processo/expiry. Una sola POST sul UUID fissato e una sola PUT per ogni link. Risposta persa:GET dello STESSO UUID/marker o binding nella STESSA sessione. Oggetto estraneo,permesso negato,esito non provato,drift o expiry:STOP,non altro POST/PUT e nessun rollback automatico. I claim/counter e la root esclusiva impediscono replay anche con altra directory di consegna. Un esito parziale non va reinterpretato come zero effetti.

Password e token freschi non finiscono in argv/Env/log/journal;refresh restituito scartato. Metadata Env IAM ripersistiti solo come hash di binding. Il profilo Onboarding conserva Env preesistente privato600 e può contenere credenziali già presenti:non dichiarare che ogni file privato sia privo di segreti. Le risposte pubbliche espongono solo esito,UUID/hash,contatori e gate.

## Unico comando, SSH interattivo oufadmin UNA volta

Il plugin OUF non espone questa amministrazione IAM. La regola API-only/consenso esplicito del progetto è in [AGENTS.md](../../AGENTS.md):“If credentials or human consent are indispensable, prepare a separately explicit terminal/API step; never silently log in, refresh, reset budgets/windows, or replay claims.” Nessuna console/browser amministrativa richiesta.

```bash
(
  set -euo pipefail
  umask 077
  ouf_ths_iam_fix_launch=$(mktemp -d "$HOME/ouf-ths-iam-fix-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/dc848eba194a4e43abffcd97ba9791f37fc44884/releases/correct-managed-profile-ths-iam-bindings-20261028.sh' \
    -o "$ouf_ths_iam_fix_launch/run.sh"
  printf '%s  %s\n' 'ca018484e6196366cd0c83f4ec17e09a6bc4b94a66bb871a2c4232a0a0db40d5' "$ouf_ths_iam_fix_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_ths_iam_fix_launch/run.sh"
  bash --noprofile --norc "$ouf_ths_iam_fix_launch/run.sh"
)
```

Atteso **THS_IAM_BINDINGS_CORRECTED_CONFIGURATION_PROFILE_PREPARED_NOT_AUTHORIZED**,complete=true,Exit0/DeliveryExit0,iamMutations4/newScopeDefinitions1/newOptionalClientBindings3,14DEFAULT/9OPTIONAL/70definizioni,configurationProfileHash. Lo snapshot annidato bindingObservation è una pura osservazione (iamMutations0); il contatore top-level misura le4modifiche dell'operazione.

Riportare solo JSON finale,Exit/DeliveryExit e percorsi. Non incollare Env,configuration-profile.json,inputs.json o log completi. **SeSTOP/ambiguo,conservare senza rilancio.** iamWritesReserved segnala dispatch possibile;iamWritesObserved solo effetti riconciliati. Riconciliare sempre questa operazione/stessi UUID e claim,non crearne un'altra per aggirare uno STOP.

## Dopo la ricevuta

Anche IAM corretto non prova richiesta installata/tokenbrowser/Gateway/jobaccess. Il prossimo lavoro è nuovo piano nativo di configurazione del SOLO Onboarding,stessa immagine/source9890b318.../c512c247...,con schema36/snapshot/jobFAILED5/peer/rete/mount e review HUMAN correnti. MCPd2454f3c.../a5218012... e Registry restano acquisiti. Nessun nuovo build/import,migrazione o vecchio APPLY riapprovato da questo comando.

Poi normale autenticazione browser SOLO UTENTE sul link nativo dello stesso asset/job;nessun agent THS o api-root generico404. Freshcard/permessi/owner/Gateway/scopes. Budget3tentativi/900s e successivo resume sono DUE decisioni HUMAN distinte STESSO job/sessione,cumulativi6–8;mai reset o altro budget dopo ambiguità. Ultimo FarmacieFAILED5 non osservato da questi controlli.

Asset9c502da5-b5d8-405e-b3f5-60eb31ecb513/job677480c8-3d10-44fd-9dad-f72ddeed20a4. Originale13903byte/SHAf670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311,parser/preview61righe→semantica/Ingestion/UDP/provenance,D5/D6/D7,dueclient/fault/ripresa. Riutilizzare M1/Teatri/typed/ASSETS/LATEST,nessuna terza acquisizione. M1/G4 acquisiti;M2/G5/G6/G7/E2E aperti;Supervisor dopo E2E completo. No nuovo upload/job/attivazioneimplicita/Registryrestart/reinstall/merge/releaseacceptance/subagenti/automazioni.

Mini-PET M2 1.2,piano/roadmap,audit e precedenti Teatri/Resolution/API/TTY riusati. PET originali non esposti negli allegati correnti:nessuna nuova pretesa di lettura integrale/conformità.


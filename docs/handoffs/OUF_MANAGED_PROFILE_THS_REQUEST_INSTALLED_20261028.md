# Aggiornamento: scheda live negata per ownership

HTTP403 ONB_FILE_OWNER_SCOPE_UNPROVEN, correlation e8c96213-6537-42c1-a726-311d6eb7898a, riferito dall'utente il 28 ottobre2026. [Osservazione e diagnosi del gate](../../evidence/managed-profile-ths-ownership-denial-20261028.json). Non è prova di scadenza del budget900s: ownership controllata prima di card/policy, nessun predicato temporale. Ultima prova FAILED5/zero budget; identità/tenant browser e ricevute persistenti vanno riconciliati in lettura. Non chiedere riaperture/login alla cieca, non rilanciare APPLY né concedere budget o cambiare ownership. Le richieste sotto di aprire la scheda sono superate; esito installazione e tutti i vincoli restano acquisiti.

# OUF — richiesta THS installata, prossimo passo scheda HUMAN dello stesso job — 28 ottobre 2026

## Esito acquisito, non rieseguire

L'allegato **Testo incollato(20261028-154443).txt** è stato letto integralmente:10691byte,SHA256 **6f850947efce0f4d3e067c7921e69ac6f6d7f4bd3184cdbf0562d73bdf7a35e9**,issued+15progress+risultato finale+footer. [Ricevuta strutturata](../../evidence/managed-profile-ths-request-update-target-20261028.json),[output integrale conservato](../../evidence/managed-profile-ths-request-update-target-20261028.log). I timestamp nanosecondo sono conservati come interi esatti. Nessuna nuova lettura indipendente del log VPS;non richiederlo nuovamente.

**THS_OWNER_REQUEST_UPDATE_INSTALLED_E2E_NOT_ACCEPTED**,complete=true,componentReadinessProven=true,scopePatchApplied=true,**Exit0/DeliveryExit0**. Il delta della richiesta OAuth è INSTALLATO sul SOLO Onboarding,nella stessa immagine. I tre scope preview/file.profile/quarantine.release sono aggiunti ai cinque precedenti. Lo scope **/etc/ouf/deploy-snapshots/managed-profile-ths-request-update-e22a443d-20261028-v1**,comando,review e authority sono **CONSUMATI**. NON riconsegnare,rieseguire o riapprovare l'APPLY. Anche tutti i predecessori IAM/publisher/capture/prepare/APPLY restano consumati.

- Review **0990401fb938c73c13bd6be090c04a5291bfe52aa06d9546cdaf7e13659a10b8**
- Authority **ce93c610fee96883a11fb806d283565340ffe6d1e6e629acf883eaabae0956ba**
- Frozen plan **040d5a43b8050007666e993886d575dcf95259d6d8d1ef712aba44f3422aced5**
- Execution inputs **e22a443d2617bf4db06b90ca272fd80e87fe3a05a9b4b6386b15cce51fea11e4**
- Conditional native plan **9c961982f1e521ca67e25de6d9437cbfc670821c874625d77b9a092da33b6900**
- Configuration profile **d0dbbd61b5a6486124e229e646ce63a96165dfc2433ae200f7fec92383d5140c**
- Canonical result SHA256 **1c452fa61251395b18c800ee0aceefa9cce09e068807b85729d0857ff9b547bf**
- Native binding **2c5295203d6f190e04f2add429a617be69b2a72dd264b45f241a80d1aac09d0b**
- Runtime binding **05f8dab7097dd4a42d010b609d88b9be634d26b302222c67169a68377dd853d1**

Source **9890b31868641e5be43c949a56f4ef69dd23bdfd**,native **sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3** invariati. Nuova generazione Onboarding PID **3462703**,startTicks **88998673**,mnt[4,4026532358],net[4,4026532422]. Un vecchio owner retained fermo;**12peer invariati**,compreso MCPsource d2454f3cb8cd410d284b9dc78349a170187aea1c/native sha256:a52180123104ac97e4979ad1b9b291654b076692da51708bb2a377301fef1220. Registry e worker intatti.

## Prove target, effetti e limiti

15stage completi e contatori monotoni:287EngineGET,7Enginewrite,7SQL READ ONLY,2processi backup,3readiness,8metadata/public-authority letture,1owner-overlay contenuto;0image load/import,quarantine,adminGET/PUT,service credential file. Tre firme installazione e chiavi esistenti aperte come da review. Zero nuove migrazioni,restore,grants,budget,resume,upload/job,acquisizioni o attivazioni. Controller OAuth/IAM/gateway requests0;normale bootstrap OAuth dell'owner può essere avvenuto,conteggio non osservato. mountSourceContentIdentityProven=false rimane una limitazione,non convertirla in prova.

Backup quiescente **735390byte**,dump e parsing verificati,nessun restore:
**/etc/ouf/deploy-snapshots/managed-profile-ths-request-update-e22a443d-20261028-v1/onboarding.dump**
SHA **5cdda140c580e2fe69df57366ac6725d302ec126854cef32799d2f0c10056a6f**.

Schema36 e storia migrazioni esatta. **Intero snapshot V36 invariato**:hash **e608428ca16b9e81406d0990a140e767256ec0bcd4803f9ccf4aa62fc943c28a**,operationalStateHash **db5d8d256acc687e1ae696a5ac5072e25ee9774b39e976050c39abfe6c539fa6**. noPendingProfileOrReadinessWork=true,retainedFailedJobUnchanged=true,zeroBudgetsAndEventsProven=true. **Farmacie FAILED/tentativi5** conservato;nessun budget,sessione di recupero o resume concesso.

Directory **/home/oufadmin/ouf-managed-profile-ths-request-update-delivery.KMVmMfPK**,deliveryLog bootstrap.log nella directory;runtimeLog **/usr/local/lib/ouf-managed-profile-ths-request-update-ab50b8b5a818713e/operator.log**. Non richiedere log di nuovo o esporre review/Env/dump/CSRF/token.

[Qualifica](../../evidence/managed-profile-ths-request-update-qualified-20261028.json) e [precedente handoff di preparazione](OUF_MANAGED_PROFILE_THS_REQUEST_UPDATE_20261028.md) restano prove storiche;il comando di quest'ultimo è consumato. Codice persistente e guard nativo sono installati/verificati nel percorso corrente. Readiness/manutenzione NON sono E2E applicativo;effectiveBrowserTokenScopesProven=false,applicationE2EProven=false,releaseAcceptance=false.

## Identità e Policy58

[Verifica connettore corrente](../../evidence/managed-profile-ths-request-update-connector-check-20261028.json):routing esplicito **ouf-admin**,link_6aafef96b4148191b767e9af7b756a07,profilo subject **b93d8cf6-cd14-4ee6-91d7-84cd76c4f500**. Lettura protetta authorization.proposal.read della stessa proposta owner-scoped **fb54d330-0ec2-400a-ae71-e4ac3cf45319** riuscita:revision1,PUBLISHED,finalPolicyRef **ouf-lab-authorization:58**. Contratto del tool:risultato del medesimo chiamante. La risposta non restituisce separatamente il subject JWT;non inventare introspezione o prove di sessione browser. Non usare giovanni-chatgpt o dedurre l'identità applicativa da SSH/IAMoufadmin.

Policy56 SERVICE strutturale e Policy58 ruolo exact-job già acquisiti;nessun grant temporaneo,nuova proposta/ruolo/descrittore da riproporre. La vecchia approvalPath della proposta è solo ricevuta storica,NON il prossimo link operativo. Prima di altre capabilities governate verificare account effettivo,nessuna scrittura di recupero via agente.

## Prossimo passo esatto: THS SOLO UTENTE, lettura scheda corrente

**Inviare sempre questo link all'utente;NON aprirlo con browser dell'agente:**

https://api.ouf-lab.it/trusted-human/managed-files/recovery/?asset=9c502da5-b5d8-405e-b3f5-60eb31ecb513&job=677480c8-3d10-44fd-9dad-f72ddeed20a4

Aprire nuovamente il collegamento completo,con account OUF **ouf-admin**. Per questo passo usare soltanto **Aggiorna stato** e riportare il testo visibile della scheda:stato,tentativi cumulativi,ultimo blocco ed eventuale sessione. Non richiedere backend wrapper/CSRF/token. Nessun upload/job nuovo e nessuna decisione budget/resume finché lo stato/review correnti non sono verificati.

Percorso verificato nel codice source9890b318...:
- PermissionThsSecurity.java protegge /trusted-human/managed-files/**,richiede sessione HUMAN OIDC,PKCE,registrationIdouf-ths e verifica server-side del token.
- Il login applicativo configurato è **/oauth2/authorization/ouf-ths**,non la root generica api.ouf-lab.it (404 atteso). Il collegamento nativo completo passa attraverso la catena e conserva la destinazione richiesta.
- ManagedProfileRecoveryThs.java seleziona la stessa coppia asset/job,API /trusted-human/managed-files/recovery/api/{assetId}/{jobId};la UI legge la scheda.
- profile-recovery.js usa requested state/review/version/generation/inputBindingHash;mostra Stato,Tentativi cumulativi,Ultimo blocco,sessione/history. Nessuna mutazione su Aggiorna stato. Budget e resume sono due pulsanti/POST distinti;pending command/sessione in sessionStorage conservati per riconciliazione.
- Un401/THS_SESSION_REQUIRED e un403 permanente hanno messaggi distinti;non assumere che il solo login conceda permessi. Se ancora negato,raccogliere il SOLO messaggio visibile/codice/correlationId e diagnosticare il gate reale. Nessun ritorno a root404,login ciechi o nuovo grant.

Il connettore verificato non prova questa sessione browser. Accesso live,ownership,Gateway,scope e permessi della scheda restano **NON PROVATI** finché l'utente legge la nuova scheda.

## Due decisioni HUMAN successive, stesso job

Solo dopo accesso/stato/review freschi:
1. Concessione nativa **3tentativi/900s**,nuova sessione sullo STESSO job. Tentativi cumulativi **6–8**,mai reset. Motivo/checkbox della review reali,nessuna approvazione simulata.
2. Dopo ricevuta/stato/sessione aggiornati,decisione HUMAN distinta **Avvia il recupero** sullo STESSO job/sessione. Il budget da solo non avvia il job.

Ambiguità:conservare e riconciliare lo STESSO comando/sessione,nessun secondo budget. Se pending è presente,usare la riconciliazione della richiesta precedente secondo codice,senza creare nuovi commandKey o cambiare job. Mai nuova acquisizione per aggirare blocchi.

Asset **9c502da5-b5d8-405e-b3f5-60eb31ecb513**,job **677480c8-3d10-44fd-9dad-f72ddeed20a4**. Poi provare originale/hash/parser/preview:Farmacie13903byte,UTF8BOM/semicolon,61righe/10colonne,SHA **f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311**;proseguire semantica/Ingestion/UDP/provenance,D5–D7,dueclient,fault/ripresa. Riutilizzare Teatri/M1/typed/ASSETS/LATEST e tutto il lavoro GioNob,nessuna terza acquisizione.

[Mini-PET M2 1.2](../OUF_M2_MINIPET_v1_0_20261026.md),[piano](../../releases/csv-m2-plan-20261026.json),[roadmap](../OUF_M2_ROADMAP_20261026.md),[industrializzazione](../OUF_MANAGED_PROFILE_THS_INDUSTRIALIZATION_20261028.md). M1/G4 acquisiti;M2/G5/G6/G7/61righe→UDP/D5–D7/dueclient/E2E aperti. Supervisor dopo E2E completo. Nessun reset/nuovo upload/job/terza acquisizione/attivazione implicita/Registry restart o reinstall/merge/release acceptance/subagenti/automazioni. PET originali non esposti negli allegati correnti:nessuna nuova pretesa di lettura/conformità integrale.


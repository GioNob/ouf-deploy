# SUPERSEDED — lettura riuscita e consumata

Il read documentato qui è acquisito integralmente e NON va rilanciato. Seguire il [nuovo handoff della correzione IAM](OUF_MANAGED_PROFILE_THS_IAM_CORRECTION_20261028.md), qualificata ma non eseguita sul target. Le istruzioni sottostanti sono storiche.

# CURRENT — lettura IAM riuscita/CONSUMATA; correzione minima in preparazione

28 ottobre 2026, Europe/Rome. [Ricevuta integrale](../../evidence/managed-profile-ths-iam-binding-read-target-20261028.json): complete/Exit0/DeliveryExit0,identità amministrativa protetta verificata,1auth/14GET IAM/5GET Engine/2metadata/135305byte. Status THS_IAM_BINDINGS_OBSERVED_CONFIGURATION_PROFILE_BLOCKED è lettura riuscita,non STOP e non profilo pronto. Scope/comando managed-profile-ths-iam-binding-read-5dfd7b7a-20261028-v1 CONSUMATI:non rilanciare/riconsegnare. Nessun token/password nuovo conservato o modifica IAM/runtime/grant/budget/resume.

Client ouf-authorization-ths UUIDa53bc77e-1b21-4a54-8f1a-b236fadb759a:14DEFAULT/6OPTIONAL,69definizioni,baselineHashba556e9fce5fb31de5f53af0bf6d3fe7a77e8e09d9048529d8283eaaa6afabc2. Previewe369f8fd... e file.profile226b20cd... esistono,inclusione token=true,nessuna restrizione ruolo,ma binding NONE. Quarantine.release NON definito. Profilo Env non compilato. Policy58 resta PUBLISHED,nessuna nuova proposta/grant/login browser richiesto.

NEXT preparare/qualificare UNA correzione nuova con review concreta esplicita:creare il solo scope OAuth mancante (OIDC,include in token scope=true,nessun RealmDefault),aggiungere3link OPTIONAL allo stesso client,preservare i20link precedenti e altre definizioni/configurazioni. OPTIONAL lega l'uso alla richiesta esplicita della THS;non modifica iDEFAULT esistenti. Fresh snapshot deve uguagliare baseline prima effetti;claim/receipt fsync prima guard e riconciliazione stessa operazione senza POST/PUT ripetuti. Se autorizzato dall'utente nel terminale,un nuovo accesso amministrativo finito distinto dal readconsumato,nessun refresh o vecchia finestra/budget riaperta. Nuovo comando NON ancora consegnato.

Codice persistente e guard nativo sono acquisiti in sorgente/CI59test+Keycloak reale,non correzione installata o E2E. Dopo IAM verificato,compilare profilo Env solo privato condizionale;runtime APPLY ancora separato con review/fence correnti. THS esclusiva UTENTE;appouf-admin distinto da IAMoufadmin. Ultimo FarmacieFAILED5 non riletto,budget3/900 e resume DUE future decisioni HUMAN distinte stesso job/sessione,cumulativi6–8. M1/G4 acquisiti;M2/G5/G6/G7/E2E,61righe→UDP,D5–D7/dueclient aperti;Supervisor dopoE2E. No reset/nuovi upload/job/terzaacquisizione/Registryrestart/reinstall/attivazioneimplicita/merge/releaseacceptance/subagenti/automazioni. Header seguenti STORICI.

# OUF — controllo IAM e contratto persistente della recovery THS — 28 ottobre 2026

## Punto corrente e predecessori consumati

[Ultima ricevuta integrale](../../evidence/managed-profile-ths-client-selection-target-20261028.json): **MANAGED_PROFILE_THS_CLIENT_SELECTED_IAM_BINDING_NOT_OBSERVED**,complete/Exit0/DeliveryExit0. Inputs **5dfd7b7a903c07f546c42ba1915bf6f8fd1430ab91addc4879988cd4c1727892**,3metadata/5GET/1config/695761byte. Client effettivo **ouf-authorization-ths**,registrationouf-ths,providerouf,issuerhttps://auth.ouf-lab.it/realms/ouf,authorization_code. OverlaySHA6d546047448495746d7eaad6d83e7942fa2950f137d4a240a3aef9309f7f39be;file/mount/processo provati invariati. Log e directory in ricevuta; risultato letto integralmente in chat, log host non riletto indipendentemente. Non chiedere il log di nuovo.

La lettura precedente fdc61884... aveva già provato cinque scope richiesti e i tre requisiti recovery omessi: preview,file.profile,quarantine.release. Tutti i comandi di selezione/capture/APPLY/publisher/login/review/authority precedenti sono **CONSUMATI**:non riconsegnare/rilanciare/riapprovare. Nessuna correzione Env applicata, IAM binding o browser token osservato. Policy58 e ruolo del solo job restano PUBLISHED; nessun nuovo grant/proposta.

## Industrializzazione concreta e limiti

[Contratto e percorso riusabile](../OUF_MANAGED_PROFILE_THS_INDUSTRIALIZATION_20261028.md). Helper pure persistenti risolvono client effettivo, verificano definizioni/UUID/binding default/optional/inclusione token/restrizioni ruolo e compilano un profilo di configurazione additivo sulla stessa immagine. Ogni scope e proprietà estranea resta esatto; prova mancante blocca la compilazione. Due set di parametri d'installazione sono testati, non due client MCP reali.

**Collegamento nel codice di produzione:** tools/source_revision_update/configuration.py:verify, già estratto e sigillato dai Context degli aggiornamenti nativi, ora nega un artefatto contenente ManagedProfileRecoveryThs.class se manca il contratto completo di richiesta THS nel JSON. Nessuna patch automatica in quel gate: delta nel profilo/review. Gli artefatti legacy senza quel componente mantengono il proprio contratto. Tre test eseguono le stesse definizioni del verifier su ZIP reali di contratto (class fixture, non E2E Java). Non è provato che ogni bootstrap indipendente usi questo entrypoint.

Il nuovo lettore prepara soltanto il profilo privato condizionale. Il successivo aggiornamento Onboarding deve ancora essere composto/qualificato con nuova review HUMAN, generazioni e fence schema36/job/snapshot/peer/rete/mount correnti. Nessuna nuova immagine, reinstallazione Registry o riavvio è richiesto da questa lettura. Stessa immagine Onboarding c512c247.../source9890b318...,MCPa5218012.../sourced2454f3c... installati,ultimo controlupdate acquisito. Readiness e CI non sono E2E.

Mini-PET M2 1.2,piano/roadmap/audit e precedenti Teatri/Resolution/API21ottobre sono fonti del residuo. PET originali non esposti negli allegati correnti: nessuna lettura integrale o nuova conformità dichiarata. Non rifare M1/typed/ASSETS/LATEST/motori già acquisiti.

## Nuova operazione qualificata, target NON eseguito

[Qualifica](../../evidence/managed-profile-ths-iam-binding-read-qualified-20261028.json).

- Source **831a6c2268b5e5dc1138a86bec7e2c81c70d9965**,scripts/read-managed-profile-ths-iam-bindings-20261028.py,51493byte,SHA **c9d0f9bb73b41e70593a90277f4d326463151845a1244af5bf089e54650371df**.
- Wrapper **b3038858a0c779d3ce3eb98fcb63f916f2bb350a**,SHA **770712e37a90336b5433610e0adebd005399ef42536176170f61b778c50455a8**.
- Qualifica **dc3fdc88b105e6b07f1fd1dd841a5fbb2d213a03**,run push40680109883/PR40680120010. Entrambi PASS: 59test/0skip,quattro log diretti letti. Job push122788377721/122788378353,PR122788416211/122788416426. Esiti e limiti nella qualifica.
- Reuse esatto delle funzioni terminal/access dal percorso API21ottobre3b205c44...,nessun vecchio main/token/cache/journal invocato. Engine/Capture/process pin già qualificati, nuova custodia che persiste solo hash di binding dei metadata IAM, senza ricopiarne Env.

Fixture con Docker/process-root/mount/setns/PTY e Keycloak26.2.5 reali; consenso e credenziali solo di fixture. Verifica identità protetta,16GET, configurazione IAM prima/dopo uguale,root400/private600,no nuovi segreti nei file,no replay. Consegna HTTPS immutable/nonroot/sudo/root400/checksumROOT,negativo nonTTY prima scope,STOP sintetico con prove conservate. Non è prova sul VPS o sul token browser.

Nuovo scope **/etc/ouf/deploy-snapshots/managed-profile-ths-iam-binding-read-5dfd7b7a-20261028-v1**; codice root **/usr/local/lib/ouf-managed-profile-ths-iam-bindings-c9d0f9bb73b41e70/read.py**. Specifico della coorte conservata,non default universale. Il nome IAM è un campo esplicito del profilo (/ouf-keycloak sul target),non un alias da adottare; fixture concorrenti hanno nomi distinti. Trasporto loopback/namespace/profile admin deriva dalla selezione d'installazione già qualificata21ottobre; non è un URL arbitrario dell'utente.

Legge soltanto inputs.json5dfd... e result.json della selezione già riuscita.5GET Engine:info,Onboarding/IAM prima e dopo; stesse immagini/configurazioni/PID/start/net/mnt/root/boot/socket/peer,stat file/mount già letto e sigilli storici correnti. Zero nuove letture del contenuto ownerconfig o file credenziale/token/chiave. Vecchie contabilità3/27/743005byte e3/5/1config/695761byte conservate,nessun vecchio file modificato.

## Consenso e identità amministrativa separati

Il plugin non espone questa lettura IAM amministrativa. Si applica la regola del progetto in [AGENTS.md](../../AGENTS.md): “If credentials or human consent are indispensable, prepare a separately explicit terminal/API step; never silently log in, refresh, reset budgets/windows, or replay claims.”

Il comando mostra la review concreta (client,issuer,namespace/generazioni,limiti/hash). L'utente deve inserire la riga **AUTORIZZO LETTURA IAM <hash mostrato>**, poi la password **IAM oufadmin**,nascosta,non sudo e mai in chat. È una NUOVA operazione amministrativa finita,non riapre finestre/login/budget vecchi. Account tecnico IAMoufadmin distinto dall'account applicativoouf-admin; THS e sue decisioni restano esclusivamente UTENTE.

Dopo un solo password grant (scopeopenid), il token appena restituito e IDtoken della stessa risposta risolvono il subject; una GET protetta deve provare id/username/enabled prima delle letture client. Questo usa provenienza del canale provider+lookup protetto,non verifica JWT locale indipendente o autorità HUMAN applicativa. Nessuna cacheCLI o refresh. Password/token restano memoria/pipe limitate e non finiscono in argv/Env/log/journal; refresh restituito scartato nel child.

Limiti: **600s totale;90s per consenso e password;210s massimi dopo consenso,ristretti a120s dopo password senza estensioni;2metadata/5EngineGET/1auth/16AdminGET normali,20massimi/24MiB**. Solo GET transitorie (trasporto,429,502,503,504):stesso stage/token/deadline,5/15s jitter20%,max3/stage e4reservation globali,Retry-After entro margine originale. Permanenti/ignoti/authambigua/expiry/drift:STOP,no retry/refresh/relogin. Claim fsync prima dispatch,counter monotoni e reinitnegata; scope consumato ancheSTOP/crash.

Zero IAMwrite,Enginewrite,SQL,import,lifecycle,grant,budgetprofiling/resume,upload/job/fonte/acquisizioni. readOnly=false correttamente perché autentica; configurazione/policy sono sola lettura. Non confondere l'unica allowance amministrativa con i3tentativi di profiling.

I metadata IAM vengono salvati solo come hash; il profilo condizionale conserva Env Onboarding preesistente privato600 e può contenere credenziali d'installazione già presenti. Non dichiarare ogni file privato privo di segreti. Nessun nuovo materiale password/token amministrativo viene salvato o stampato.

## Unico comando, SSH interattivo oufadmin UNA volta

```bash
(
  set -euo pipefail
  umask 077
  ouf_ths_iam_launch=$(mktemp -d "$HOME/ouf-ths-iam-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/b3038858a0c779d3ce3eb98fcb63f916f2bb350a/releases/read-managed-profile-ths-iam-bindings-20261028.sh' \
    -o "$ouf_ths_iam_launch/run.sh"
  printf '%s  %s\n' '770712e37a90336b5433610e0adebd005399ef42536176170f61b778c50455a8' "$ouf_ths_iam_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_ths_iam_launch/run.sh"
  bash --noprofile --norc "$ouf_ths_iam_launch/run.sh"
)
```

Restituire solo JSON finale,Exit,DeliveryExit e percorsi dei log. Non incollare configuration-profile.json,Env,inputs.json o log completi. SeSTOP/risposta ambigua,conservare senza rilancio; una auth riservata non va reinterpretata come zero.

Possibili successi:
- **THS_IAM_BINDINGS_VERIFIED_CONFIGURATION_PROFILE_PREPARED_NOT_AUTHORIZED**:binding e idoneità senza restrizioni ruolo provati,profilo Env privato compilato,nessun APPLY/authority.
- **THS_IAM_BINDINGS_OBSERVED_CONFIGURATION_PROFILE_BLOCKED**:lettura completa ma mancano definizioni/binding/inclusione/idoneità. Preparare soltanto la correzione IAM minima sullo stesso client con nuova review concreta; niente altri client,scope globali/defaultRealm o ruoli/grant aggiunti implicitamente.

## Continuazione applicativa

Dopo binding e delta configurazione effettivamente installati/verificati: normale autenticazione browser dell'UTENTE sul link nativo dello stesso job,senza agent browser e senza api-root generico404. Solo allora freshcard/review. Budget **3tentativi/900s** e successivo resume sono DUE decisioni HUMAN distinte STESSO job/sessione,cumulativi **6–8**; mai reset/nuovo job/upload o altro budget per un esito ambiguo. Ultimo stato FarmacieFAILED5 non osservato da questi lettori.

Asset9c502da5-b5d8-405e-b3f5-60eb31ecb513/job677480c8-3d10-44fd-9dad-f72ddeed20a4. Originale13903byte/SHAf670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311,parser/preview61righe→semantica/Ingestion/UDP/provenance,D5/D6/D7,dueclient e fault/ripresa restano aperti. M1/G4 acquisiti;M2/G5/G6/G7/E2E aperti. Supervisor dopo E2E completo. No terzaacquisizione/Registryrestart/reinstall/attivazioneimplicita/merge/releaseacceptance/subagenti/automazioni.

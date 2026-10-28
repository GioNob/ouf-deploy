# CURRENT — lettura THS RIUSCITA/CONSUMATA; tre scope mancanti nella richiesta applicativa

28 ottobre 2026, Europe/Rome. [Ricevuta integrale](../../evidence/managed-profile-ths-scope-capture-target-20261028.json): MANAGED_PROFILE_THS_SCOPE_REQUEST_OBSERVED_NOT_AUTHORIZED, complete/Exit0/DeliveryExit0. InputsHash fdc618841f14eeb0c99ee3f61f0971affefff5f13d740d406db376d3daaa7bec, 3 metadata/27GET/743005byte, coorte13 e immagini owner/MCP invariate. Scope managed-profile-ths-scope-capture-policy58-20261028-v1 e comando CONSUMATI: NON rilanciare o riconsegnare.

Richiesta effettiva: openid, authorization.policy.admin, ouf.managed-source.file.upload, resolution.issue.read, resolution.match.approve. Mancano tutti e soli i tre requisiti recovery preview/file.profile/quarantine.release. Patch additiva privata condizionale pronta; before b739cf07... → after f439449c..., cinque scope e altre proprietà conservati. Non applicata: zero Enginewrite/IAM/OAuth/SQL/lifecycle/grant/budget/resume/upload/job/acquisizioni. ClientId nel JSON=null, non osservato da file: registrationId ouf-ths NON prova clientId. Binding IAM/token browser restano ignoti; nessun login o nuovo grant proposto. Policy58 resta acquisita.

NEXT preparare/qualificare lettura del client effettivo dal solo overlay owner già selezionato, custodia/processi correnti e successiva verifica IAM API sul client osservato. Riutilizzare Resolution/Teatri, stessa immagine, nuovo mandato concreto soltanto dopo prove. Nessun vecchio APPLY/login/authority riusato. THS esclusiva UTENTE. Ultimo jobFAILED5 non riletto; budget3/900 e resume futuri DUE decisioni HUMAN distinte stesso job/sessione, cumulativi6–8. M1/G4 acquisiti; M2/G5/G6/G7/E2E,61righe→UDP/D5–D7 aperti. Supervisor dopo E2E. No Registryrestart/reinstall, terza acquisizione, attivazione implicita, merge/releaseacceptance, subagenti/automazioni. Header seguenti STORICI.

## Follow-up corrente

La sezione precedente sostituisce tutti i NEXT storici sotto. Risultato letto integralmente in chat, log host non riletto indipendentemente; non richiederlo di nuovo. Consegna precedente esclusivamente storica, consumata.

---

# Richiesta OAuth della THS: lettura corrente qualificata — 28 ottobre 2026

## Punto corrente

La risposta nativa dell'utente è esattamente:

```json
{"error":"required scopes ouf.managed-source.preview not present"}
```

[Prova completa](../../evidence/managed-profile-ths-preview-scope-denial-20261028.json). È provata l'assenza di preview nel contesto negato. Non dimostra quale altro scope manchi, né se l'omissione dipenda dalla richiesta applicativa, dal binding IAM o dalla sessione già emessa. Non è stato introspezionato alcun token e non è stato chiesto un altro login.

Policy58 è già PUBLISHED e verificata per la stessa proposta fb54d330-0ec2-400a-ae71-e4ac3cf45319: 8 ruoli/12 assegnazioni/137 grant del subject, con i precedenti7+11/134 preservati e tre permessi limitati allo stesso asset/job. [Prova58](../../evidence/managed-profile-job-control-policy58-access-20261028.json). Nessun nuovo grant o proposta serve per correggere lo scope. Il precedente MCP INVALID_ARGUMENT resta distinto e non ritentato.

## Riuso e persistenza

I precedenti Teatri policy51/IAM READ e Resolution17ottobre sono stati letti integralmente. La correzione Resolution aggiungeva gli scope browser al solo SPRING_APPLICATION_JSON preservando tutte le altre proprietà e la stessa immagine; vedi releases/RESOLUTION_THS_CONFIGURATION_20261017.md e tools/resolution_ths_configuration/plan.py. Tutti quei comandi, login, scope, worker e authority restano consumati.

Il nuovo helper tools/managed_profile_ths_scopes/contract.py riusa quel pattern. Aggiunge solo i requisiti mancanti a spring.security.oauth2.client.registration.ouf-ths.scope; conserva scope preesistenti e altre proprietà/variabili. Nega proprietà duplicate, override ambigui, placeholder e selezioni dirette/JVM non riviste. ClientId è osservato solo se letterale nel JSON: non viene inventato dal registrationId. Nessun file montato di configurazione o credenziali viene letto.

Onboarding **a9c8310d284a118787fff63b700b964a2fe3027e**, draftPR53, versiona catalogue/managed-profile-ths-oauth-request-v1.json con il contratto preview/file.profile/quarantine.release. Tre nuove regressioni chiudono la corrispondenza ruolo/descriptor/scope, client/API e separazione dall'autorità; quattro test precedenti restano PASS. Push40664239712/job122734583264, log diretto letto. Delta solo catalogo/doc/test/workflow: nessun Java, migrazione, YAML o binario runtime cambiato. La dichiarazione non assegna scope IAM, non concede grant e non pubblica configurazione.

## Qualifica prima della consegna

[Qualifica dettagliata](../../evidence/managed-profile-ths-scope-capture-qualified-20261028.json).

- Codice **fa4b7f77a3f61b71c4dc76a959f8677830363056**, scripts/read-managed-profile-ths-scopes-20261028.py, 24111 byte, SHA256 **61930d7a0f19661205cecfcc6036f6ff266f3ce63460e7f4025dbcf108557924**.
- Wrapper **006e729bf20e83be7725d3c42b4b4bbfcb6df659**, SHA256 **b6afaba5cba7379761b982ce7f9f63bd9d0e000cf8328a57bee3aa6a32fc4d99**.
- Qualifica **bde4a04111e20d61533b29b42ddd843bc8116259**: push40663903278 e PR40663912726 PASS. 22 test/0skip, socket Unix reale/root SO_PEERCRED, custodia, coorte13/27GET, deriva di generazione negata e no replay. Job push122733459853/PR122733491918.
- Consegna reale pinned HTTPS/nonroot/sudo/root0400/checksum ROOT, main senzaTTY prima del contesto/Engine, STOP sintetico con private0600 conservati e rilancio negato: job push122733459590/PR122733491727 PASS. Log diretti ispezionati.

I metadata Engine della fixture sono sintetici; protocollo Unix, file, custodia, verifiche e persistenza sono reali. La CI non prova il risultato target, il token browser, il binding IAM o l'E2E. Capture/Engine/private/process_pin/stable_binding provengono dalle definizioni già qualificate in tools/managed_csv_recovery/retained_inputs.py; Logger dal precedente lettore. Nessun vecchio main viene eseguito. Il contratto puro incorporato coincide AST con il modulo riusabile testato.

## Nuova lettura target, ancora non eseguita

Nuovo scope fisso:
`/etc/ouf/deploy-snapshots/managed-profile-ths-scope-capture-policy58-20261028-v1`.

Codice protetto:
`/usr/local/lib/ouf-managed-profile-ths-scope-capture-61930d7a0f196612/read.py`.

SSH interattivo come oufadmin; sudo, Python-I-S-B root e SUDO_UID verificati. Nessun login OAuth e nessun APPROVO. Codice root0400/dir0700; input/output con Env completo solo privati0600. L'output pubblico espone esclusivamente scope/clientId selezionati e hash, mai l'intero Env.

Legge tre metadata da `/etc/ouf/deploy-snapshots/managed-csv-control-update-900b09c6d29a20fd-v1`: review.json, result.json, recovery.json. Review42db62a1d9d8f0423b88c86b4d56c50f39d9b0cd96ae6a2c11797583df3f830e; authority9ae7b608a7836e83d93df74d07612b121040854608bdf47cdd820a9d676f5bd1 e frozenPlan06054f1cb3fe0045c3fdc3ca1cfa595444b90fd20d3ee589cae71e9ad3225dc5 sono soltanto provenienza. Richiede successo/readiness, journal COMPLETE con tutti gli stage APPLIED e nessuna quarantena. Non legge chiavi, non firma e non riusa quell'autorità.

Ricava i due ID installati e gli undici peer, vietando collisioni o nuove adozioni. Massimo27GET Engine: info più due letture per13. Engine29.8.1, socket/root SO_PEERCRED, pin PID1/Engine/processi/boot e sigilli correnti verificati. Richiede gli stessi nativeBindingHash onboarding1765524a.../MCPd5750f01... e immagini c512c247.../a5218012... provati dall'update riuscito. Nomi, PID o configurazioni cambiati causano STOP, non adozione arbitraria.

Limiti: **90secondi,3metadata,27GET,2MiB/risposta,24MiB cumulativi**. Zero Enginewrite, SQL, fileconfig/credenziali/chiavi, IAM/OAuth, import, lifecycle, grant, budget/resume, nuovi job/upload/fonte/acquisizioni. Nessun processo di comando viene avviato dal lettore. Se manca l'override JSON esplicito o vi sono override ambigui: STOP senza fallback a file segreti.

Atteso **MANAGED_PROFILE_THS_SCOPE_REQUEST_OBSERVED_NOT_AUTHORIZED**, complete=true, Exit0/DeliveryExit0, inputsHash e scopeInspection:
requestedScopes, missingRequestScopes, conditionalConfigurationPatchPrepared. I tre scope sono il contratto richiesto, non l'asserzione che manchino tutti.

L'eventuale Env modificato resta una proposta privata condizionale. executionEntryQualified/targetApplyAuthorized/runtimeAuthorityIssued sono false; binding IAM e token browser non verificati, nessuna configurazione applicata o processo riavviato. Se tutti gli scope sono già richiesti non riscrive nulla.

## Unico comando, come oufadmin UNA volta

```bash
(
  set -euo pipefail
  umask 077
  ouf_ths_scope_launch=$(mktemp -d "$HOME/ouf-ths-scope-launch.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 32768 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/006e729bf20e83be7725d3c42b4b4bbfcb6df659/releases/read-managed-profile-ths-scopes-20261028.sh' \
    -o "$ouf_ths_scope_launch/run.sh"
  printf '%s  %s\n' 'b6afaba5cba7379761b982ce7f9f63bd9d0e000cf8328a57bee3aa6a32fc4d99' "$ouf_ths_scope_launch/run.sh" | sha256sum --check -
  chmod 0400 "$ouf_ths_scope_launch/run.sh"
  bash --noprofile --norc "$ouf_ths_scope_launch/run.sh"
)
```

Il plugin OUF non espone l'Engine o la configurazione OAuth necessaria. Questo passaggio dell'operatore serve a leggere i metadata locali conservando la custodia; non autorizza un nuovo APPLY. Riportare solo JSON finale, Exit, DeliveryExit e percorsi dei log. Non inviare inputs.json, Env o log completi. STOP o risposta ambigua consumano il nuovo scope: conservare prove e non rilanciare.

## Dopo il risultato

Se la richiesta effettiva omette requisiti necessari, verificare prima il clientId e i binding IAM effettivi per quegli scope. Preparare poi solo il delta Onboarding sulla stessa immagine, riusando Resolution e i controlli nativi Teatri/V36, con nuova review HUMAN concreta prima degli effetti. Non modificare ouf-chatgpt, workload o device per riparare la THS. Una nuova autenticazione normale del browser segue una correzione verificata, conservando il ritorno allo stesso job.

Se gli scope sono già richiesti, non produrre una patch arbitraria: diagnosticare binding/emissione/sessione con autorità corrente. Nessun successo di token si deduce dalla CI o dalla sola configurazione.

THS esclusiva UTENTE. Dopo accesso/card/review correnti, budget3tentativi/900s e successivo resume sono DUE decisioni HUMAN distinte sullo STESSO job677480c8-3d10-44fd-9dad-f72ddeed20a4/sessione, asset9c502da5-b5d8-405e-b3f5-60eb31ecb513, cumulativi6–8; mai reset o secondo budget per un esito ambiguo.

Ultimo job FAILED5. Poi originale13903byte/SHAf670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311, parser/preview61righe→semantica/Ingestion/UDP/provenance e D5/D6/D7. Riusare typed/ASSETS/LATEST e TeatriM1. M1/G4 acquisiti; M2/G5/G6/G7/E2E/dueclient aperti. Supervisor dopo E2E completo. Nessun nuovo upload/job, terza acquisizione, attivazione implicita, Registryrestart/reinstall, merge/releaseacceptance, subagente o automazione. Tutti i predecessori APPLY/publisher/capture/login/review/authority sono consumati.

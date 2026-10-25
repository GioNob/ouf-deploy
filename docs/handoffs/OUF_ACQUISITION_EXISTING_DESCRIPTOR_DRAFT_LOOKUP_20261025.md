# Recupero governato dell'unico draft esistente — 25 ottobre 2026

## Stato target e limiti

Ultimo risultato target: RETAINED_DESCRIPTOR_PUBLICATION_STOP_OBSERVED/complete=true/Exit0, [ricevuta](../../evidence/acquisition-descriptor-publication-retained-stop-target-20261025.json).
Cinque registrazioni APPLIED; CREATE_DRAFT CLAIMED/hash027f626dce41cac0dc2d1dd9338bd2aeb20bc474a438e6e26a68d4214271b46b; UUID/revisione/raw response assenti; nessuna dispatch PUBLISH registrata. Non significa che il draft non esista sul server.

La review5a31ae519ef9ee4e14cf9258f91739ba27aa07a290f5f07b277cb8d3a44de911 era stata approvata ESATTAMENTE. Errore dell'assistente: client richiedeva revision>=1, owner V16 crea revisionDEFAULT0; rispostaCREATE non conservata prima del guard. Publisher e reader retained CONSUMATI. Non rilanciarli, ripetere registrazioni/CREATE o inventare UUID. [Handoff precedente e prove](OUF_ACQUISITION_DESCRIPTOR_DRAFT_ZERO_STOP_20261025.md).

## Sorgenti owner effettivamente consultate

Onboarding deployed V35 source1b1222ceaa5af85a25c20857e7c8c1b548b12dc1: AuthorizationAdminApi.java, AuthorizationAdminService.java e migrationV15/V16/V26. Main84828f74 non è il deployed V35 e non è una base di rollout autorizzata. Nessun deploy/restart/migrazione è previsto.

L'API admin offre GET ACTIVE e GET draft per UUID, ma non ricerca/lista dei draft. GET richiede principal trusted HUMAN con authorization.policy.admin oppure superadmin protetto; GET draft applica isolamento tenant. V16 crea revision0, V26 aggiunge tenant_id derivato dall'audit CREATE_DRAFT. L'audit policy_ref può contenere decisionRef o superadmin:protected, quindi NON va scambiato con base_active_ref48.

## Lettura nativa esatta; nessuna pubblicazione

Codicepinned 59fabcd9ca7545d876018c4e7d623774f846c0d5, scripts/lookup-existing-descriptor-draft-20261025.py, SHA256 e2c61cb91291307a5b403ca2132b23ef927a8645a7356441ca963c610a565ec9.
Consegna 7c8b152524c5b0c9d1d018e99a0ded3e0cc29f3e, releases/lookup-existing-descriptor-draft-20261025.sh, SHA256 dde584912687df443beb17484324c0c7eacf3789672acad2ecc86998ddf59aba.

Nuovo contesto fisso ESCLUSIVO /etc/ouf/deploy-snapshots/acquisition-existing-draft-lookup-5a31ae519ef9ee4e-v1, root0700, file600. Codice root0400/dir0700, hash verificato da root; fchmod sul FD prima fsync, anche con umask077. Esecuzione ROOT via sudo: non chiedere all'operatore di leggere un file root0400. Copia esclusiva, nessuna modifica di vecchi codici, review, state, log o ACL.

Legge solo originali review/state per candidato e contatori, più il profilo fisico già osservato:
- /etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6/current-onboarding-database-snapshot-v1/snapshot-inputs.json
- SHA256000bf9de27a5a89d6132c2e594650282818957d322baa7b9166762fd0ac0eb0c
- schema ouf.current-onboarding-database-private-snapshot.v1.

Quel profilo è trasporto fisico e prova storica, NON nuova autorità e NON invoca il precedente reader/SQL/scope. Conserva il limite noto allCurrentConfigurationPrecedenceResolved=false: non prova da solo la configurazione applicativa attuale. Il nuovo reader verifica socket/dev/inode/custodia, Dockerbinary esatto, generazione PostgreSQL prima/dopo, database/OID/porta/ruolo e policyACTIVE completa uguale all'owner vivo. Il successivo GET del SOLO UUID individuato verifica che quel draft esista nell'owner realmente raggiunto e nel tenant corretto. Nessun uso del vecchio CID Onboarding ormai sostituito.

Login nuovo con client ouf-human-admin, scope openid authorization.policy.admin, account ouf-admin/subb93d8cf6-cd14-4ee6-91d7-84cd76c4f500/tenantouf-lab/actorHUMAN. Riusa SOLTANTO definizioni pure Transport/login del reader pubblico root0444/hash062b1e201904b9fd7a10efcad371de17d4c0fbc3411710c310186aa7381c5cad, non vecchio main/scope/login/token. Bearer solo in memoria, nessun refresh/filetoken/credenziale IAM. IAM normale finito:600s/1metadataGET/121POSTmassimi; contatori separati conservati.

Prima della query, GET ACTIVE governato verifica realmente JWT e permesso admin; dopo la query lo ripete e richiede identità completa invariata con ACTIVE48/responsehash5de0.../policyhash6209... . In caso di revoca/denial, STOP con prove, niente GET/SQL alternativo.

UN SOLO containerexec e UN SOLO psql session, durabilmente riservati PRIMA di dispatch, via Docker/socket/programmi/database/Unixsocket del profilo fisico. Nessun parsing di configurazioni credenziali, nessuna chiave di firma. Ambiente pulito, Dockerconfig vuota nuova, PGPASSFILE=/dev/null/PGSERVICEFILE=/dev/null, no passwordprompt, SQL trasmesso via STDIN senza grant/token in argv. BEGIN REPEATABLE READ READ ONLY; timeout statement5s/lock1s/idle5s, SET LOCAL ROLE del runtimeRole retained, SELECT fisso e ROLLBACK. Il warning libpq ESATTO su /dev/null è ammesso; altri stderr/SQLerror restano STOP. Nessun SQL mutante, selector/query libero o retry di SQL.

La query seleziona al massimo DUE righe, con creator/tenant/base48 esatti e uguaglianza JSONB del candidato COMPLETO già approvato/hash027f..., più audit CREATE_DRAFT HUMAN corrispondente. Nessun filtro che nasconda un diverso stato/revisione: questi vengono osservati e poi validati, mai corretti. Zero o due risultati: STOP, nessuna scelta/CREATE. Uno: receipt privata con UUID salvata PRIMA dei guard e GET HTTP governato del SOLO UUID, con policy completa esatta, DRAFT/revision0/ETag\"0\" e auditunico. Anche risposte native fallite sono trattenute private prima dei guard.

Contatori originali 6administrativeWrites/6ownerGets/0previewPosts/346780bytes incorporati, mai azzerati. Nuovi ownerGET3stage, fino8tentativi per soli errori transitori espliciti con 5/15/60/300/900 e jitter<=20%, Retry-After, finestra90s; massimo cumulativo30GET, entro160originali,32MiBcumulativi. Nessun retry su403/errore permanente/sconosciuto o SQL/Engine. Due EngineGET, un SQL/execnuovo soltanto di lettura; nessuna nuova autorità di lifecycle/apply/pubblicazione o nuovo grant/budget fonte. La finestra read dopo login è90s; niente attese in transazione.

Risultato atteso EXISTING_DESCRIPTOR_DRAFT_OWNER_CONFIRMED_NO_PUBLICATION/complete=true/Exit0/DeliveryExit0, UUID/revision0, continuationAuthorized=false/runtimeAuthorityIssued=false/appE2Efalse. Questa lettura NON pubblica, non registra, non crea draft, non fa preview e NON richiede APPROVO. Se STOP, conserva tutto e NON rilanciare/rimuovere/cambiare child.

## Qualifica CI

La qualifica puntuale finale e le limitazioni sono in [evidence/acquisition-existing-descriptor-draft-lookup-qualified-20261025.json](../../evidence/acquisition-existing-descriptor-draft-lookup-qualified-20261025.json).
Dati IAM/owner/storia/permessi/UUID di CI sono SINTETICI. Docker/PostgreSQL17, DDL V15/V16/V26, trasporto Unix/exec/psql/STDIN, transaction-read-only/SET ROLE e filesystem root/nonroot sono REALI. Nessuna approvazione production simulata. CI non osserva il draft VPS o la pubblicazione49.

## Unico comando VPS: come oufadmin, una volta

Serve la password sudo nel terminale, poi il normale login IAM nel browser con ouf-admin. Inserire il codice device SOLO nel browser; non pubblicare codice o token in chat. Nessun APPROVO in questo passo.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_lookup_bootstrap=$(mktemp -d "$HOME/ouf-existing-draft-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/7c8b152524c5b0c9d1d018e99a0ded3e0cc29f3e/releases/lookup-existing-descriptor-draft-20261025.sh" \
    -o "$ouf_lookup_bootstrap/run.sh"
  printf '%s  %s\n' 'dde584912687df443beb17484324c0c7eacf3789672acad2ecc86998ddf59aba' "$ouf_lookup_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_lookup_bootstrap/run.sh"
  /usr/bin/bash "$ouf_lookup_bootstrap/run.sh"
)
```

Restituire solo JSON finale, Exit/DeliveryExit e percorsi log, non review/state/risposteprivate o operator.log integrale (può contenere codice device).

## Dopo UUID confermato

Preparare esecutore RESIDUO che non contenga alcuna rotta REGISTER/CREATE. Incorporare tutti i contatori storici+lookup e rileggere ACTIVE/capabilityregistration e SOLO quel draft. Nuova review concreta privata con UUID/revision0/candidato completo e preview cinque aggiunte/zero grantchange/106grantpreservati. L'eventuale pubblicazione SOLO dopo APPROVO hash FRESCO su riga isolata nel TTY, mai simulato o riusato. Riservare l'unica pubblicazione residua prima del dispatch, persistere status/ETag/body PRIVATI prima parsing/guard, confermare ACTIVE49 e106grant invariati. STOP/CLAIMED/perdita risposta non autorizzano retry.

Poi scope/grant HUMAN temporaneo per le DUE acquisizioni ESISTENTI e quattro letture governate: Ingestion+UDP per ciascuna. Nessuna terza acquisizione, attivazione, reset o modifica Registryworker. Installazione READ VPS positiva resta distinta dalla prova dati E2E. Tecnico8/8, funzionale4/6, E2E/G4/F5/F6 OPEN; correlare contratto/CSV/publication/ACK/watermark/13identità/propertyprovenance e preservare8Cinema prima Supervisor. Nessun merge/release acceptance.

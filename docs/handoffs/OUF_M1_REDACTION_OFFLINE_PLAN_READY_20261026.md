# M1 — cattura consumata, immagini esatte già scaricate; prima preparazione privata del piano

## Punto corrente

La ricevuta VPS dell’owner conferma ACQUISITION_REDACTION_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED, complete=true, Exit=0/DeliveryExit=0. [Ricevuta](../../evidence/acquisition-redaction-inputs-target-20261026.json). InputsHash: 9bbe7298c2eff0be51bf943919c9db0044413256b08efe620a503f79aef4d7d2.
Contesto /etc/ouf/deploy-snapshots/acquisition-redaction-update-inputs-v1: CONSUMATO, non ripetere.
Quattro file conservati e dieci Engine GET; MCP corrente corrispondente, sei originali/READ invariati. Zero dati applicativi, import, scritture container, SQL, OAuth, credenziali file, signing key o autorità runtime. Configurazioni private non lette dalla chat.
Log /home/oufadmin/ouf-redaction-inputs-delivery.2Qolb5ul/bootstrap.log.

Questa continuazione ha effettuato ZERO acquisition READ. L’ultima osservazione applicativa resta quella del [precedente handoff owner](OUF_POST_OAUTH_OWNER_REDACTION_20261026.md): binding run/pubblicazione/CSV e ACK prefix/watermark positivi, dettagli Ingestion e UDP REDACTED; causa effettiva non ancora nota.
La policy51 aveva scadenza 2026-10-26T14:14:26Z (15:14:26 Europe/Rome) ed è scaduta al presente checkpoint. Nessun rinnovo/proposta/nuovo grant automatico. La preparazione offline seguente non usa tale autorità.

## Immagini selezionate e trasporto consumato

I candidati restano Ingestion PR47/7d85bfe0d1423bcb13e115f06c92d8a0baa1ebf7 e UDP PR48/125510cf9d970aff7db66a0a8f27eb98b50bb6de. Aggiungono solo categorie diagnostiche minimizzate; nessuna modifica ai guard ALLOW, dati/cursor negati, query, schema, worker o grant. Prove PG17/HTTP e skip dichiarati nel [handoff precedente](OUF_M1_REDACTION_DIAGNOSTICS_READY_20261026.md). Le immagini nuove NON sono installate.

La prima selezione di ZIP delle PR era errata: workflow head_sha corrispondeva al candidato, ma source-commit.txt riportava il merge commit della PR. Il guard EXACT_CI_SOURCE_REQUIRED l’ha respinta senza essere indebolito. Quei file restano conservati e il loro trasporto è consumato.
Caso precedente db8577ab3082fbc2308ae0a6d33eb55fffc85e3020f99a8623cf69b165d849aa, run40333672069/job121609598041, directory /home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-acquisition-redaction-transport-db8577ab3082fbc2.

Il caso corretto 5ab4bafadb29cdd51b8ddaa776ea9aaf4fdc410de675c746ad789f249273c64f seleziona gli artefatti PUSH dei commit esatti, intento distinto e nuovi byte:
- Ingestion push40330310435, artifact12653103275, 140874962 byte, ZIP SHA256 f3a42897aaf29fe93ecbb091072c1966881d8e2c8d83416c0debb8d841d4de63.
- UDP push40330617797, artifact12654597311, 122385628 byte, ZIP SHA256 ce5b44eb696a71e0be1ec862597c81443a234e684915a19a59269578b0bb2003.

Trasporto corretto già ESEGUITO sull’existing runner: run40336259618/job121618723161, ricevuta 2026-10-26T14:06:13Z, complete=true. Directory:
 /home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-acquisition-redaction-transport-5ab4bafadb29cdd5
Due GitHub API GET nuovi, quattro cumulativi includendo la selezione respinta. File0400/dir0700/UID1000. Zero sudo/root staging/Engine/SQL/OUF OAuth/chiavi/credenziali/import/runtime; runner non reinstallato o riavviato. Anche questo trasporto è CONSUMATO: non rieseguire workflow o riscaricare gli ZIP sul target.

## Preparazione qualificata, ancora NON eseguita sul VPS

Source closure pinned f5bfd6f0d79cb4dd192913081c71a7a3abfd331e:
- scripts/prepare-acquisition-redaction-image-plan-20261026.py SHA256 16133fe2870bdb8c4757f8b22e010f29c69fadb80190e7db4504e3f2764cd38f.
- Tre helper puri plan_helper/retained_mac/image_custody; nessun vecchio entrypoint consumato invocato.
- Caso pubblico e qualification.json con identità native indipendenti per classic/containerd; manifest SHA nel wrapper e [prova strutturata](../../evidence/acquisition-redaction-offline-plan-qualified-20261026.json).

La preparazione legge soltanto inputs.json e result.json della cattura positiva e i DUE ZIP già presenti. Copia e verifica sei file sotto root0400, verifica ZIP/membri/checksum/commit/configurazione, audit degli archivi/layer, deriva archivi nativi tagless deterministici senza rebuild/relabel e li confronta con la qualifica indipendente. Crea il piano esatto della sola sostituzione futura delle due READ.
Nuovo contesto FISSO: /etc/ouf/deploy-snapshots/acquisition-redaction-image-plan-9bbe7298c2eff0be-v1.
Massimo300s, due private metadata read, due ZIP, due archivi nativi; minimo3GiB liberi. Nessun Engine/namespace/HTTPapp/SQL/OAuth/credenziale/chiave/import/lifecycle. Non dimostra generazioni runtime correnti, policy o label. executionEntryQualified=false e nessuna autorità runtime.

Env, Cmd, parametri JVM conservati, mount dati RO/rootfs RO/HostConfig esatto, Memory=0 compreso. Nessun nuovo limite inventato, route, MCP o worker. Il piano distingue Config.MacAddress legacy realmente presente da endpoint-only: assente/null/stringa vuota sono profili espliciti ed esatti; nessuna normalizzazione generica. Un controller futuro dovrà verificare il profilo dopo stop/detach, senza scambiare la normale assenza del metadata legacy per drift. Regola permanente: [MAC invariants](../OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md). Controller completo e ciclo di sostituzione NON ancora qualificati.

CI nativa positiva sui byte corretti: source8eac9ad661c1c3686f5ec70bcf50f8bc907de763, push40336259669/job121618538580(containerd),121618539313(classic); PR40336269673/job121618575547(containerd),121618576228(classic). Sette test di piano PASS/0skip e reali import/inspect/create non avviato Docker29.8.1 nei daemon isolati hosted; identità e archivi coincidono fra push/PR. Nessuna app nuova avviata, nessun dato target.
Due esecuzioni precedenti40335388909/40335396337 mostravano successo metadata ma i log contenevano EXACT_CI_SOURCE_REQUIRED: qualifica RESPINTA; corretto pipefail prima delle prove selezionate. Non sono PASS.
Consegna root: source905bcb8438418af95a9566e991de0f212abd8145, push40338268100/job121625600339 e PR40338282203/job121625643017 PASS. Log diretti letti: sei file root0400, negazione lettura nonroot, copier esatto, entrypoint sigillato positivo con cattura sintetica e ZIP pubblici esatti, confronto identità indipendente, input originali invariati e nessuna modifica agli scope consumati/parziali. bash-n PASS. Intero curl/sudo wrapper non eseguito come shell in CI: i suoi confini root e entrypoint sono stati eseguiti realmente..
La prima prova delivery40337203149/job121621855721 è fallita nel fixture: modificava i globals ma non i keyword-default già legati alle radici reali; corretta solo redirezione delle radici sintetiche nel test, source/wrapper invariati. Nessuna esecuzione target di quella prova.
La ripetizione nativa PR40338282130/classic121625642224 si è fermata nel trasporto hosted, prima delle prove native; non selezionata come PASS, nessun effetto target. Le prove native valide sopra restano riferite ai byte immutati.

## Unico prossimo comando, prima esecuzione da oufadmin sul VPS

Wrapper delivery905bcb8438418af95a9566e991de0f212abd8145, SHA256 89cc15c8a24ade001c69a6cc884ac4a446923752a8a84fd4b47c4d2d76242618.
Non richiede login IAM o APPROVO. Solo sudo se richiesto. Non installa le immagini.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_redaction_plan_bootstrap=$(mktemp -d "$HOME/ouf-redaction-plan-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/905bcb8438418af95a9566e991de0f212abd8145/releases/prepare-acquisition-redaction-image-plan-20261026.sh" \
    -o "$ouf_redaction_plan_bootstrap/run.sh"
  printf '%s  %s\n' '89cc15c8a24ade001c69a6cc884ac4a446923752a8a84fd4b47c4d2d76242618' "$ouf_redaction_plan_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_redaction_plan_bootstrap/run.sh"
  /usr/bin/bash "$ouf_redaction_plan_bootstrap/run.sh"
)
```

Esito atteso: ACQUISITION_REDACTION_IMAGES_AND_PLAN_PREPARED_NOT_AUTHORIZED, complete=true, Exit0/DeliveryExit0.
Log /home/oufadmin/ouf-redaction-plan-delivery.XXXXXXXX/bootstrap.log; ProtectedCode /usr/local/lib/ouf-acquisition-redaction-image-plan-16133fe2870bdb8c/prepare.py. Restituire solo JSON pubblico, Exit e percorsi log/directory. Nessun inputs/native-plan/config privato.
STOP o interruzione: conservare directory, claim e log; NON rilanciare, non cancellare o sovrascrivere scope parziali/consumati.

## Dopo la ricevuta

Qualificare il controller completo della SOLA sostituzione delle due READ e custodia/TTY/ciclo reale/guard legacy ed endpoint-only/ambiguità/quarantena con budget finiti. Prima di runtime: verifiche correnti, review privata concreta e APPROVO hash fresco realmente inserito dall’owner nel terminale. Non simulare approvazione e non invocare vecchie APPLY.
MCP9a corrente, originali ingestion/UDP, Postgres, Gateway e Registry devono restare invariati. Nessuna nuova acquisizione, attivazione, contatore/budget reset, grant cieco, reinstallazione, riavvio Registry, merge o release acceptance.
Solo dopo installazione positiva e nuovo mandato READ valido si potranno interrogare i due owner e distinguere il motivo live della redazione. Policy51 non è più autorità valida; non aprire automaticamente finestre o nuovi grant.
Le sole due acquisizioni esistenti sono bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f, source teatri-csv-6609b245, account ouf-admin. Il link corrente conservato è link_6aafef96b4148191b767e9af7b756a07. Prima prova governata solo runbb2; primo diniego STOP, nessun retry/seconda run cieca.
G0–G3 PASS; G4/M1/F5/F6 aperti. Tecnico8/8, funzionale4/6. WP5/6 parziali, G5/G6 non chiusi, G7/M2 non accettato. Supervisor dopo E2E.
Baseline miniPET1.1 invariata: M1 18–30h (centrale24), M2 40–70h (centrale55), HUMAN separato. Consuntivo storico21–26 incompleto: nessuna percentuale o residuo orario dedotto dal solo subtotal misurato. L’intervallo tecnico della continuazione viene registrato nel timeline, senza inventare ore HUMAN o attese storiche.

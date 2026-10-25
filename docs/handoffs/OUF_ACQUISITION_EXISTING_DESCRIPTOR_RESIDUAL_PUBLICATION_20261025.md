# Sola pubblicazione residua del draft confermato — 25 ottobre 2026

## Target provato e scope consumati

[Lookup VPS](../../evidence/acquisition-existing-descriptor-draft-lookup-target-20261025.json): EXISTING_DESCRIPTOR_DRAFT_OWNER_CONFIRMED_NO_PUBLICATION/complete=true/Exit0/DeliveryExit0.
UUID **cb75ddb0-bd19-48fb-847f-1c47aff3207a**, revision0/DRAFT/baseouf-lab-authorization:48/ETag"0", candidato completo hash027f626dce41cac0dc2d1dd9338bd2aeb20bc474a438e6e26a68d4214271b46b e106grant confermati dall'owner. Contatori6administrativeWrites/9ownerGets/0previewPosts/537123bytes, lookup2EngineGET/1SQL/1exec. IAM lookup1GET/10POST/13166bytes. Nessuna nuova registrazione/CREATE/preview/pubblicazione/authority.

Log /home/oufadmin/ouf-existing-draft-lookup-delivery.49373j4a/operator.log ebootstrap.log.
Scope /etc/ouf/deploy-snapshots/acquisition-existing-draft-lookup-5a31ae519ef9ee4e-v1 CONSUMATO; publisher originale e lettore retained pure CONSUMATI.
NON ripetere lookup/SQL/registrazioni/CREATE, riusare login/token/approvazione5a31, azzerare o cambiare scope per aggirare STOP.
[Handoff precedente](OUF_ACQUISITION_EXISTING_DESCRIPTOR_DRAFT_LOOKUP_20261025.md) e [incidente revision0/receipt](OUF_ACQUISITION_DESCRIPTOR_DRAFT_ZERO_STOP_20261025.md).

## Esattamente cosa fa il nuovo esecutore

Runtime **d70cf9cbe816f41f76d08858084bd393ece45c69**, scripts/publish-existing-descriptor-draft-20261025.py, SHA256 **14477872585ad75bf96da5bb13ed6ee4381911d81ccb0ec76d7166f3ec744932**.
Delivery **24f2abbd08c5987cd47fce1d952e0549c493a584**, releases/publish-existing-descriptor-draft-20261025.sh, SHA256 **6842bbe509f105021bd4be6a24553230d41054db7e83e372c0c91a753b2f73ef**.
Nuovo contesto root esclusivo /etc/ouf/deploy-snapshots/acquisition-existing-draft-publish-cb75ddb0-v1, root0700/file600; codice root0400/dir0700 con fchmod sullo stesso FD prima fsync e checksum da ROOT, esecuzioneROOT via sudo.

Legge soltanto review/state originali come prove, più result/state/owner-draft-response del lookup root già completato. Digest esatto della receipt lookup **8f69ddc401c1da775bfb1d3a76c4ff275b1918aaa353910171e1adf99e10843a**.
Preserva anche i contatori IAM storici disponibili negli originali e quelli lookup; nuovo login separato, senza refresh/reset. Originali non modificati né eseguiti.
Nuovo normale device login ouf-admin, clientouf-human-admin/scopeopenid authorization.policy.admin; bearer solo in memoria. Non riusa token del lookup.
Carica solo definizioni Transport/login del reader pubblico root0444/hash062b1e201904b9fd7a10efcad371de17d4c0fbc3411710c310186aa7381c5cad, mai il suo main/scope. Il messaggio login viene adattato per dire correttamente che la pubblicazione seguirà solo una review nuova.

Trasporto chiuso: SOLE GET ACTIVE/capabilitycatalog/SOLOUUIDconfermato, due POST preview dello stesso UUID/rev0, UN POST publish dello stesso UUID/rev0. Nessun body di mutazione, rotta REGISTER/CREATE/PUT/DELETE/simulate, SQL, Engine, filecredenziale, firma, worker, acquisizione o nuova attivazione fonte.
Preflight: ACTIVE48 identico a responsehash5de0.../contenthash6209..., tutte106grants esatte, aggiunte SOLO5descriptor; sei registrazioni READ/HUMAN esatte, fullcataloguehash, draftfull/ETag0. Prima preview OWNER autenticata HUMAN, delta5aggiunte/0rimozioni/0grantchange. La preview registra auditowner ma non cambia policy/draft; conta0→1 nello stesso massimo2 originario.

Poi review PRIVATA concreta nuova con nonce, UUID/rev0, intero candidato, previewowner, hashcatalogo, limiti/contatori cumulativi, scadenza effettiva e hash codice. Espone chiaramente i5ID e owner/scope/actor, nessun dato grant segreto.
**L'operatore inserisce SOLO la riga APPROVO e hash FRESCO mostrata, senza suffissi o frase.** Solo veroTTY; nessun flag di autoapprovazione/decisione in chat. La review è riletta/verificata prima degli invii approvati.

Dopo APPROVO: nuove GET ACTIVE/catalogo/draft, seconda preview identica alla prima, ulteriori ACTIVE/draft/ETag0 immediatamente prima della claim. Owner applica in transazione permesso corrente, tenant, base, ETag/revision e preservazione dei grant esterni. Unico PUBLISH_DRAFT CLAIMED+counter6→7 fsync PRIMA di invio. Status/ETag/body PRIVATI conservati anche per HTTPError PRIMA di parsing e guard; risposta persa/ambigua resta CLAIMED e non autorizza retry.
Atteso ACKPUBLISHED/revision1/ETag"1", poi ACTIVE49 con tutti106grant ecapability esatte. publishedAt ACTIVE viene assegnato dall'owner e può differire dal timestamp candidato nel draft; non è relabel/rebuild o sostituzione del candidato.
Solo dopo readback APPLIED. Non confondere policyHash transport/CanonicalHash owner con il digest del JSONreview: gli hash restano distinti.

Contatori iniziali incorporati6writes/9GET/0preview/537123bytes; massimi originali7writes/160GET/2preview/32MiB. Nessun nuovo budget fonte o azzeramento. Solo GET transitori espliciti retry8maxstage,5/15/60/300/900+jitter<=20%/Retry-After dentro scadenza; permanenti/unknown/POST/CLAIMED non ripetuti. Review+execution900s massimi, totale1800s incluso login; IAM600s/1metadataGET/121POSTmax, tokenexp−15s può ridurre finestra. Deadline monotonic e SIGALRM reale limitano anche I/O bloccato; scadenza stampata Europe/Rome. Nessuna attesa in DBtransaction.

## Qualifica e confini

[Qualifica puntuale](../../evidence/acquisition-existing-descriptor-residual-publication-qualified-20261025.json).
Finale push40240974039 e PR40240978367:16protocol+5rootcustody+3ownerJava/PG17 ciascuno,0skip, log diretti letti.
Jobpush121312457757/121312457646 ePR121312470986/121312470979.
Codice OWNER deployed1b1222ceaa5af85a25c20857e7c8c1b548b12dc1 invariato, installSDK suo e test Java21 con PostgreSQL17/migrazioni native, MockMvc attraversato dal client Python reale via HTTPbridge CI. Test successo, review rifiutata, owner commit con risposta persa: una sola pubblicazione,0REGISTER/CREATE nel residuo,2preview salvo rifiuto, revision0→1 e106grant inclusa storia altrotenant preservati.
Principal trusted e decisioneTTY/storia in CI sono SINTETICI; IAM/JWTproduction e Gatewaylive NON provati da questi test. RuntimeSynchronizer esterno mocked in CI, refresh/cache consumers live non dimostrati. Non è risultato VPS o E2E.
Rootcustody reale: fileoperatore600/root600 letti senza cambiare originali, due storieIAM conservate, digest/counter/symlink/modewrong negati, rootumask077/copia0400/dir0700/hash/esecuzioneisolata e negoNONroot reale, copia/replaynegati. RootUIDmapping locale limita chown: quel test è qualificato in UbuntuCI privilegiata, non sostituito con skip.

Baseline originale allegata consultata (nessuna ripubblicazione dell'archivio): SHA256e63df67e8817eec38a9d4b3eb736b020f693b932f3360dc02f4555330f2201ce. Matrix1.7§1/§4/§7; AuthorizationPET1.5§16–18 e§36.6–36.7; SourceOnboarding/THSPET1.6§27.1–27.3. Ownerboundary, snapshot atomico, controllo versione e distinzione IAM-HUMAN/Agent preservati nel perimetro riparazione. ReviewTTY sotto mandato owner è controllo di questa riparazione; non dichiarare completata la conformità THS/ApprovalChallenge o release acceptance sulla sua base.

## Comando unico: come oufadmin UNA volta

Chiede sudo per copia/esecuzione protetta, poi login IAM nel browser con ouf-admin. Codice device SOLO nel browser. Dopo preflight vedrai review, scadenza e rigaAPPROVO: incolla SOLO quella riga nel terminale. La vecchia5a31 NON è valida per questa operazione.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_residual_bootstrap=$(mktemp -d "$HOME/ouf-existing-draft-publish-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/24f2abbd08c5987cd47fce1d952e0549c493a584/releases/publish-existing-descriptor-draft-20261025.sh" \
    -o "$ouf_residual_bootstrap/run.sh"
  printf '%s  %s\n' '6842bbe509f105021bd4be6a24553230d41054db7e83e372c0c91a753b2f73ef' "$ouf_residual_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_residual_bootstrap/run.sh"
  /usr/bin/bash "$ouf_residual_bootstrap/run.sh"
)
```

Atteso **EXISTING_ACQUISITION_DESCRIPTORS_PUBLISHED_GRANTS_UNCHANGED**, complete=true, Exit0/DeliveryExit0; counts7writes/2preview e106grantpreservati. Nessuna nuovaREADgrant o accettazioneE2E implicita. Se STOP o rispostaambigua conserva tutto e NON rilanciare.
Restituire solo JSONfinale/Exit/DeliveryExit/percorsilog; non review/state/receiptprivate o operator.log integrale con devicecode.

## Dopo pubblicazione provata

Verificare capability/scope effettivi per ouf-admin sul canaleMCP e nuove ROLES/GRANTS correnti. Riprendere piano governato delle DUE run ESISTENTI teatri-csv-6609b245:
- bb2e2af4-9c0a-49ea-8ad9-a947987c1472
- a3208f2f-ebfd-415d-bddc-79ab05dea78f.

Nessun replay della proposal rifiutata/scaduta. Nuova proposal concreta temporanea ristretta ai6READ/run, che preservi2ruoli/admin34permission/2assegnazioni/grantestranei; decisione esclusivamenteHUMAN/THS, successiva proposal.read dello stessoID. Pubblicare descrittori NON concede permessoalleletture né scopeOAuth.
Poi quattro letture Ingestion+UDP per le due run, correlare contratti/CSV/publication/ACK/watermark/13identità/propertyprovenance, chiarire11–19property/unione20 e preservare8Cinema. Nessuna terzaacquisizione, attivazione, reset, Registryrestart/reinstall.
Tecnico8/8funzionale4/6; E2E/G4/F5/F6 OPEN. Supervisor dopoE2E. Nessun merge o release acceptance.

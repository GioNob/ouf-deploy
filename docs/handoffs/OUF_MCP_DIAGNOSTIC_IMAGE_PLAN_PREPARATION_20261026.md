# OUF — deposito immagine diagnostica MCP e piano privato, 26 ottobre 2026

## Stato esatto

VPS cattura riuscita: MCP_DIAGNOSTIC_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED/complete=true/Exit0/DeliveryExit0.
InputsHash **fb4b7c9ae832e779192f1ff6e032e49c696752e182a57b8e9464f5a76000b3e4**;
9EngineGET/5metadataread/65041byte,4originali invariati e3installati stessa generazione,zero effetti.
Receipt [acquisition-mcp-denial-inputs-captured-target-20261026.json](../../evidence/acquisition-mcp-denial-inputs-captured-target-20261026.json).
Log dichiarato /home/oufadmin/ouf-mcp-inputs-delivery.Rsmep8r0/bootstrap.log, non letto dall’assistente.
Scope cattura mcp-denial-update-inputs-9a374dd07745f059-v1 CONSUMATO: NON rilanciare.
Non ripetere vecchia preparazione native5fa62, APPLY/recovery, pubblicazioni49/50 o acquisizioni.
[Handoff precedente integrale](OUF_MCP_DENIAL_DIAGNOSTICS_AND_READONLY_CAPTURE_20261026.md), suoi riferimenti e prove restano vincolanti.

MCP candidato source9a374dd07745f059de3ad39757c68f02db6d29c3/[PR79 draft](https://github.com/GioNob/ouf-mcp-server/pull/79) NON distribuito.
Include diagnostics bounded SOLO sulle due acquisitionREAD e ripristino schemaHUMAN CAPABILITIES diPR78.
Deployed resta bd60ccd. Non cambia permessi/cache/admission/Gateway/owner; causa live DENY/OAuthscopes/bundlelocale NON osservata.
Due READ distinte runbb2... già negate; nessun retry. Runa320... non letta.

Grant12READ policy50 erano validi solo fino26ottobre2026 **09:24:50CET/08:24:50Z**: finestra ora TERMINATA.
Non è stato creato rinnovo/proposta nuova, reset o estensione. Policy49/50 e grant originari restano prove storiche.
La preparazione FILE sotto non usa grantOUF e non autorizza chiamate acquisition. Dopo futura installazione,
le READ governate richiederanno contesto/mandatoHUMAN corrente: non usare la vecchia finestra.

## Nuova preparazione distinta: immagine più piano, SENZA runtime

Una sola prima esecuzione di nuovo scope FISSO:
**/etc/ouf/deploy-snapshots/mcp-denial-image-plan-fb4b7c9ae832e779-v1**.
Non è un child riaperto dello scopeconsumato. Intento nuovo: depositare la SOLA immagine MCP qualificata
e compilare proposta privata dalla cattura già ricevuta, senza importarla/eseguirla.
Il controller NON apre il socketEngine e NON fa GETEngine; nessuna revalidazione live affermata.
Zero containerwrite/import/stop/start/detach/rename/restart,namespacejoin,credenzialeOUF/chiavifirma,
OAuth/IAM/SQL/Gateway/Registry/acquisizione/attivazione/grant. Niente APPROVO o loginOUF.
Il normale gh già usato sul VPS scarica un solo artifactGitHub esatto; credenzialiGitHub non stampate né estratte dallo script.
Non cambiare account o autenticazione se fallisce; STOP e prove conservate.

Runtime **a82727760244183c1733b8d7619909a2821839ac**:
scripts/prepare-mcp-denial-image-plan-20261026.py
SHA256 **96cb2f55d3000d5408265f09a2bd615d902964398e97ba631a72b84a14379059**.
Delivery **39394ecef13f10e6431c53d689e3d8a9a7954084**:
releases/prepare-mcp-denial-image-plan-20261026.sh
SHA256 **20473f93d856b9a883661d86712d268866c3be3cef3901263b7a25a3f0722f60**.
Codice e3helper puri copiati ROOT400/dir700 in /usr/local/lib/ouf-mcp-denial-image-plan-96cb2f55d3000d54;
fchmodFD prima fsync, verifica hash ROOT, nessun tentativo di lettura400 da utente normale.
Helper della stessa revisione runtime:
- plan_helper.py SHA09b892a89f7cd7fa31fbc891822445ed09554e9362e397bb9b12b98316e1d8dd;
- retained_mac.py SHAcb5dbbee4a80ce71860dfe5d32362a662d98898c58fd82009e69c5eb6ac1f7ce;
- image_custody.py SHA5d0fc0edb1ebd9386326eadbbee08f2cf0a9fd1e122940c0661b5ac5e3655ed8.

Sono usate SOLO funzioni pure mcp_replacement/stablebinding/environment/MAC/archive.
Nessuna vecchia entrypoint/controller o sue procedure vengono importati/eseguiti, nessuna funzioneGateway o preparazione storica chiamata.
plan_helper contiene anche funzioni storiche non utilizzate: non chiamarle in una continuazione.
La consegna/closure è monouso anche se STOP o interruzione: non cambiarepath, riscrivereclaim o rilanciare.

Legge esattamente inputs.json (rawSHAfb4...) e result.json del nuovo capture, ROOT/no symlink/nlink1/mode400o600,
max6MiB ciascuno, claim durevole PRIMA open, duplicatekeys rifiutate e frameFD/path prima/dopo.
Non rilegge vecchi5file né credenziali. Seals e vecchi byte invariati.
Contatori installazione306GET/22writes/3loads/83ownerConfig/2quarantena/8health/9adminGET/2PUT/3fileadmin
e cattura9GET/5file/65041byte conservati distintamente nel piano. Nuovi contatori questa preparazione:
2metadataread/1ZIPread/1nativearchive;0EngineGET/0write/0import. Nessun reset di budgetstorico.

Artifact GitHub12633545900/run40284011851/source9a374dd0, ZIP9617218byte
SHA6c31a1b5698942ddbb47b96ec1b49860c690c44aac8106beb1ca4b1ed7bba56a.
Sei member esatti, tutti SHA256SUMS verificati; image.tar.gz SHA19fd036f973e52734d209d20671240f8973cd55d7183968ce605254b94cbd5bb,
capabilities.json SHAf2a6f20ff15969c068b87cbd15cf8485e5680f63123d60e90b58c7a09b7b37ae.
Platformlinux/amd64/4layer/configCIffc78..., User10005:10005, entrypoint/usr/local/bin/ouf-mcp/Cmdserver.
Non vengono rebuild/relabel o emesse nuove firme. ZIP<=9617218/metadata2MiB/expandedtar64MiB,
headroom256MiB e120scontroller; downloadGh120s e singoli codiciCurl60s. Tutti file nuovi ROOT400, scope700;
bootstraplog privato utente600, conservato, nessun outputConfig/Env.

Piano primario autenticamente compilato e scritto PRIMA di imagecustody binding: hash della receipt di staging reale
e frozenplan reale, non hash fittizi o del modelloCI. Nativeplan successivo vincola byte e IDderivati.
Engineprofilo SOLO29.8.1 e classic overlay2 o containerd-snapshotter osservati nella cattura:
- classic: nativeID=configID sha256:ffc78ca5e7fc1a1941cd4c4347d43e061df97d06c9fca44df0e8a5c47b5b839d;
  taglessarchiveSHA a7fd7391aca2d63207339c5cac689b221ea4759d25dc7a0ed112fdad41eba0fb;
- containerd: nativeID sha256:9a1af5be94ff3dda4084b829e824482c5cf863525375c6f104a3fe89517e781e;
  taglessarchiveSHA dafe0b0be9bf78717061923b1d1fe9feab2f01b81fd1e432a8b7a35a7677bcc3.
Nessuna equivalenza arbitraria config/native e nessun import effettuato qui.

Proposta SOLOMCP conserva nomi/Env/mount/HostConfig/networkaliases/endpointMAC e6altri componenti;
vecchioMCP trattenuto fermo con nome distinto,1manager, nessun rollback automatico. La policyMAC è quella comune STRETTA,
non ignore diConfig: presente/stringa/coerente→ASSENTE SOLO dopo stessoCID/STOP/DETACH provati nel FUTURO executor.
Qui si compila il piano, non avviene alcuna transizione. FeatureCAPABILITIES, possibile bootstrapOAuth normale MCP
e possibile aggiornamento suo catalogomanifest dichiarati nel piano; nessuna migrazione o grant.
runtimeAuthorityIssued=false/targetUpdateAuthorized=false/executionEntryQualified=false.

## Qualifica reale e limiti

[Prova](../../evidence/mcp-denial-image-plan-qualified-20261026.json).
Consegna finale push **40292394526**, jobscontainerd121470284503/classic121470285022;
PR **40292401379**, jobsclassic121470307487/containerd121470307758:
log diretti letti, **8testplanner+6MACnegative+2ciclilegacy+nativeimage+rootcustody PERbackend,0skip**.
Esatto artifact autenticato da metadataGitHub run/source/conclusionsuccess/digestpublisher, scaricato e verificato.
Vero Docker29.8.1 classic/containerd importa/inspecta l’immagine candidata e crea container NONavviato per configurazioneUID/Entrypoint/Cmd.
Questo NON prova bootstrap/readiness MCP, OAuth, integrazione owner, E2E, THS o acceptance.
CicloMAC completo usa workloadBusyboxCI, asserisce legacyConfigpresente in ENTRAMBIprofili eprova preservazione dopo stop/detach/rename/replacement.
Rootcustody esegue l’ESATTO copierPython embedded nel wrapper, prova file400/dir700/nonrootdenial,
stage positivo con artifactreale, scopeconsumato rifiutato e wronginputhash rifiutato primaZIP.
Metadata della cattura per i test sono SINTETICI; nessun hashCI passato per il pianoVPS, nessuna approvazioneproduction simulata.
Il wrappercurl/gh completo NON è stato eseguito sulVPS dall’assistente; attesa primaesecuzione sotto.

## Comando NUOVO — prima esecuzione di SOLO deposito immagine e piano

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_plan_bootstrap=$(mktemp -d "$HOME/ouf-mcp-image-plan-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/39394ecef13f10e6431c53d689e3d8a9a7954084/releases/prepare-mcp-denial-image-plan-20261026.sh" \
    -o "$ouf_plan_bootstrap/run.sh"
  printf '%s  %s\n' '20473f93d856b9a883661d86712d268866c3be3cef3901263b7a25a3f0722f60' "$ouf_plan_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_plan_bootstrap/run.sh"
  /usr/bin/bash "$ouf_plan_bootstrap/run.sh"
)
```

Atteso **MCP_DIAGNOSTIC_IMAGE_AND_PLAN_PREPARED_NOT_AUTHORIZED**,complete=true,Exit0/DeliveryExit0,
inputsHash/frozenPlanHash/nativePlanHash/nativeImageId/contextPath/counts.
Restituire SOLO JSONfinale,Exit,DeliveryExit,percorsilog. Non incollare inputs/nativeplan/Env/config o logcompleti.
STOP/interruzione: conserva tutto e NON rilanciare. Nessun APPROVO va inserito in questo passo.

## Dopo receipt positiva — ancora nessuna APPLY pronta

Compilare/qualificare esecutore NUOVO SOLOMCP con piano appena compilato e sorgenti chiuse;
revalidare con budget finito i7CID/generazioni/Engine/boot/mount/config/network prima della review e prima degli effetti.
Leggere integralmente docs/OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md e seguire i suoi precedenti:
sharedretained_mac/legacygate completo già qualificato come PREREQUISITO, non prova del nuovo executor da scrivere.
Nuova review concreta privata con hash FRESCO e rigaAPPROVO canonicaVISIBILE/editabile+Invio nel terminale REALE;
usare tools/human_terminal_line_review.py qualificato, sudo diretto SENZA pipeline e logginginterno600 per l’APPROVAZIONE interattiva.
La pipeline in QUESTA preparazione non legge inputHUMAN: non copiarla al futuro controllerinterattivo.
Solo dopo approvazione chiaviinstallazione esistenti/verificaattuale di issuer/attestor/notBefore/expiresAt/finestra900+30,
nuove firme e authority chiusa; mai riutilizzo oldauthority6147... o nuove chiavi di comodo.
Fencing/journalclaim prima effetti, rawreceipt privata prima guard, rispostaambiguaCLAIMED senza retry/replay;
watchdog finito solo candidatoMCPproprio non ancora provato, nessun restart/rollback vecchio o Registry.
Nessuna modifica originalworker/2READ/Gateway/Registry, niente migrazioni/budget/attivazioni/acquisizioni/grant.
La preparazione qui NON qualifica né autorizza questi futuri effetti: **nessuna consegna APPLY nuova esiste**.

Solo dopo update provato, futura diagnosi bounded delle READ con HUMANmandato corrente;
non ripetere per inerzia le due negazioni e non usare i grant50 scaduti. Due run ESISTENTI,
bb2e2af4-9c0a-49ea-8ad9-a947987c1472 e a3208f2f-ebfd-415d-bddc-79ab05dea78f, sourceteatri-csv-6609b245.
Chiuderecontratti/ACK/watermark/intake/materialization/propertyprovenance/13identitàTeatri/unione20IRI e preservazione8Cinema nei limiti delle baseline.
E2E/G4/F5/F6 OPEN,tecnico8/8funzionale4/6, Supervisor solo dopoE2E; nessun merge/releaseacceptance o terzaacquisizione.

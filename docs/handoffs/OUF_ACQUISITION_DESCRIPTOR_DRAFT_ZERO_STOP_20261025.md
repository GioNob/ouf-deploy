# STOP pubblicazione: draftrevision0 e receipt da riconciliare — 25 ottobre2026

## Risultato VPS acquisito

L'operatore ha inserito ESATTAMENTE la review5a31ae519ef9ee4e14cf9258f91739ba27aa07a290f5f07b277cb8d3a44de911, con106grant preservati e5registrazioni. Poi STOP_RECONCILE/EXACT_OWNER_DRAFT_REQUIRED/Exit2/DeliveryExit2. **Non è errore dell'operatore.** [Evidenza](../../evidence/acquisition-descriptor-publication-stopped-target-20261025.json), senza codiceIAM o token del terminale.

Scope /home/oufadmin/ouf-acquisition-descriptor-publication-20261025 CONSUMATO; codicepinned3f0b407/hash1cbb..., delivery4ccff5b/hash810fac... e log /home/oufadmin/ouf-descriptor-publication-delivery.6WD1Ui9l/operator.log ebootstrap.log, bootstrap3KAvHaVh. NON rilanciare il [vecchio comando](OUF_ACQUISITION_DESCRIPTOR_HUMAN_PUBLICATION_20261025.md), non creare altro draft, ripetere registrazioni, rimuovere scope, cambiare directory per aggirare il blocco o riusare login/approvazione/token.

Lettura owner governata effettuata DOPO lo STOP: authorization.permissions.read/GRANTS conouf-admin, subjectesatto, limit100. ACTIVEouf-lab-authorization:48/hashsha256:6209fe7a832a4b92fcd543304a5480edb85f6f66dfe8476245075509e2c7f46b,82grantdelsubject/nextAfterNULL. Non è stata osservata pubblicazione49; grantconfigurati non sono ALLOWeffettivo.

## Errore concreto e limiti della conoscenza

Fonteprimaria Onboarding tree84828f74ac586bae09a78f0fb197b75b1a3d98d1: V16__authorization_admin_lifecycle.sql definisce revisionbigintNOTNULLDEFAULT0. AuthorizationAdminService.create non imposta revision; get restituisce lozero e l'APIaccettaETagzero. Il client richiedeva>=1 e la sua fixturepartivaerroneamente1. Questa è una lacuna di codice/qualifica dell'assistente. Correzione FUTURA>=0; revisionnegative ancora vietate, tutte le condizioni base/candidate/grants/ETag/preview invariate.

Il guard è chiamato su creazione/readback/pubblicazione: la fase precisa va riconciliata dai metadati, non inventata dal reasonCode. Il flusso pinned colloca registrazione/readback e salvataggioAPPLIED prima di ogni guarddraft. La vecchia versione salva UUID/revision neljournal SOLO DOPO il primo guard e NON persiste la rispostaCREATEprima del controllo. Quindi la receipt/UUID può NON essere disponibile sulclient. Non affermare risposta trattenuta se non esiste e non ricreare draft per compensarla.

La patchFUTURA persiste le risposte create/publish PRIVATE(status/ETag/bodylimitato) prima di parsing e guard. Non viene consegnata come esecutore o usata per riaprire la claimconsumata. I log/provevecchi restano intatti.

## SOLO lettura locale qualificata

Scriptpinned **3f9064f0ba7433155e536d0fd28f0f32bbbf451d**, SHA256 **d453c5319a141fa41d606b80fcaa982330e6510358e25909a5794aeb46836abc**.
File scripts/read-descriptor-publication-stop-20261025.py.
[Qualifica](../../evidence/acquisition-descriptor-publication-retained-stop-qualified-20261025.json).

Eseguito comeoperatore, senza sudo e senza login. Legge ESCLUSIVAMENTE:
1. codicepubblico stoppedcontroller /usr/local/lib/ouf-acquisition-descriptor-publication-1cbb40dd80d9e258/publish.py, root0444/nlink1/hash1cbb esatto;
2. review.json privata600, digest5a31 esatto, candidate49/106grant/hashpreservati;
3. state.json privata600, APPROVOretained/stateSTOP/budgetResetfalse/effectkeys e readstagesfinitiesatti.

Massimo3file/6MiBreview+128KiBstate+64KiBcode/60s, stableFD/nonlink/owner/modecontrollati. NON esegue codice/funzioni del vecchio publisher, non legge operator.log con codiceIAM, né token/credenziali/chiavi. Audit REALE nega network/socket,process/exec,enumerazione,oldfilewrites,chmod/chown/ACL/rename/delete sugli originali. Nessun SQL o ownerAPI; stato corrente non letto daquestohelper.

Crea soltanto child FISSO /home/oufadmin/ouf-acquisition-descriptor-publication-20261025/retained-draft-read-v1, claim/result600 e fsyncdir/parent. Gli originali review/state/log restano invariati. STOP/interruzione consuma ilchild, non rimuoverlo/rilanciarlo o scegliernealtro.

Output minimizzato: conteggi/stadi/APPLIED-CLAIMED, hashcandidato e tipicampi (nonvalori grant), SOLOeventuale draftUUID/revisionretained, createDispatchClaimed/publishDispatchRecorded/ownerResponseFilePresent. continuationAuthorized=false SEMPRE: non autorizza né esegue alcuna pubblicazione.

## Qualifica reale

Sorgente3f9064f0ba7433155e536d0fd28f0f32bbbf451d: push40228181751 ePR40228185226,3jobpuntualiPASS/logdirettiletti:
- 7testretained-read e21testpublisherfuturo/0skip: UUIDpresente/assente senza inventarlo,0revisioneaccettata, negativevietate, review/hash/custodia/symlink/unknownstage negati, rispostaCREATE salvata prima delguarde private, grantdata non proiettati, risposta perdutaCLAIMED/no retry. Jobpush121274013295/PR121274025283.
- Audit REALE come nonroot consourceRoot0444 e storiaSINTETICA: no rete/process/writes/chmod sugli originali, metadataletturefinite, fixedchild e replaynegato. Jobpush121274013075/PR121274025505.
- PostgreSQL17 REALE: eseguita la definizione policy_draft della V16owner, INSERT senza revision comecreateowner, rispostaJSON conDEFAULT0 accettata dal validator corretto. Jobpush121274013220/PR121274025463.

Owner/storia/decisioniCI sono SINTETICI; filesystem/audit/nonroot e DBdefault reali. Non è una prova del draftVPS, dell'APIproduction o di autorità per proseguire. La qualifica vecchiadelivery PR40228185354 è fallita perché testcopier confrontava SHAimmutabile con HEADfuturo; workflow corretto a riscaricare il pinned3f0b, non è nuova consegna o permesso di replay.

## Comando unico, sola lettura retained

Come oufadmin, UNA volta:

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_stop_read=$(mktemp -d "$HOME/ouf-publication-stop-read.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/3f9064f0ba7433155e536d0fd28f0f32bbbf451d/scripts/read-descriptor-publication-stop-20261025.py" \
    -o "$ouf_stop_read/read.py"
  printf '%s  %s\n' 'd453c5319a141fa41d606b80fcaa982330e6510358e25909a5794aeb46836abc' "$ouf_stop_read/read.py" | sha256sum -c -
  chmod 0400 "$ouf_stop_read/read.py"
  set +e
  /usr/bin/python3 -I -S -B "$ouf_stop_read/read.py" 2>&1 | tee "$ouf_stop_read/operator.log"
  ouf_stop_status=("${PIPESTATUS[@]}")
  set -e
  printf 'Exit=%s\nReadLog=%s\n' "${ouf_stop_status[0]}" "$ouf_stop_read/operator.log"
  if [[ ${ouf_stop_status[1]} != 0 ]]; then exit 2; fi
  exit "${ouf_stop_status[0]}"
)
```

Non richiede login IAM o APPROVO. Pubblica solo il JSONfinale, Exit e ReadLog, non review.json/state.json o vecchiooperator.log. Atteso RETAINED_DESCRIPTOR_PUBLICATION_STOP_OBSERVED/complete=true/continuationAuthorized=false/Exit0. Se STOP conserva tutto e NON rilanciare.

Risultato di questa lettura target ANCORA NON RICEVUTO a questo checkpoint.

## Dopo la lettura

- Se draftUUID èretained: lettura governata owner del SOLOdraftesistente e candidate/base/hash/ETag/zeroRevision completi prima di una eventuale continuazione RESIDUA, con contatori e approvazione nuova concreta se èscaduta. Mai REGISTER o CREATEripetuti.
- Se draftUUID/receipt manca: occorre un lookup OWNERgovernato e delimitato allo stesso creator/tenant/base/candidate già approvato, prima di qualunque altro effetto. Non inventareUUID, usare SQLbypass, nuove acquisizioni o altro draft sostitutivo. Non affermare che lookup/proiezione sia già disponibile senza verificarlo.
- Prima di riprendere: ownerstatuscurrent/registrazioni/previews e riservapublishresidua; appE2Emaiimplicita, nessun rilancio automatico/rollback o nuovo budget fonte.
- OAuthscope/grant temporaneo2run/4READ restano aperti e separati. Nessuna terza acquisizione/attivazione, reset contatori, Registryrestart/reinstall, merge o releaseacceptance. InstallazioneREADVPS positiva/Registryintatto, E2E/G4/F5/F6OPEN tecnico8/8funzionale4/6, Supervisor dopoE2E.

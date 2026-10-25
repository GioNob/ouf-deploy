# OUF — continuazione della review non approvata e riconciliata

## Ultimo risultato VPS reale

`UNAPPROVED_ACQUISITION_REVIEW_RECONCILED_NO_AUTHORITY`, complete=true, Exit0/DeliveryExit0.46letture metadata, zero nuove richieste Engine/admin/SQL/OAuth, zero credenziali/chiavi/attivazioni/grant. OriginalAuthorityAndJournalAbsent=true; retainedClaimsProveNoRuntimeEffectsDispatched=true. currentRuntimeStateObserved=false e continuationAuthorized=false. Non presentare questa ricevuta come installazione.

Review originaria `4cdc8631745c00589e89c4763b34f57451032be714d168447df998dbbd1da328`; nativeInputs `5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591`. Hash canonico ricostruito dai campi esatti della ricevuta, da verificare sul suo file protetto nel controller: `4ba97a80d257743d05b0423328e34cc699358056b829e70142e1347f7599c158`. Non è un hash del file direttamente letto dall’agente sul VPS.

Raw result e log: `evidence/acquisition-unapproved-review-reconciled-target-20261025.json`; `/home/oufadmin/ouf-acquisition-unapproved-read.Kcq0jQFj/operator.log`; delivery `/home/oufadmin/ouf-unapproved-read-delivery.v9qiMRfa/bootstrap.log`. Nessun timestamp di esecuzione VPS fornito.

I conteggi preflight VERIFICATI sono9EngineGET/1adminGET/5ownerConfig/1fileadmin; zero writes/import/readiness/PUT/quarantena. Il primo APPLY e il lettore offline sono entrambi CONSUMATI: non rilanciare nessuno dei due. Sono conservati anche i precedenti scope nativi/preparatori, con rispettivi contatori distinti. Il primo STOP è causato dal prompt ambiguo dell’assistente, non da un errore da attribuire all’operatore.

## Continuazione concreta

Sorgenti al commit `a21f5bda87ee7ed2e499338d842cd207ba956b3c`; nuovo ingresso `scripts/continue-acquisition-unapproved-review-20261025.py`. Wrapper `releases/continue-acquisition-read-native-20261025.sh`, SHA256 `ef035a77a93e26e4f24f2e53123eac412457772329b7f8f0cb8a81a2e16fedde`.17sorgenti, manifest canonico `dc2af88dfe0f1db2d54a0c3ed1a84a868f1b3b8e7ae5b1d6531d3aa27ec233b0`; nuova copia root0400/dir0700 `/etc/ouf/deploy-snapshots/acquisition-read-continuation-code-dc2af88dfe0f1db2`, no-follow/fstat/hash/fsync e log conservati. Nessuna modifica ai vecchi16sorgenti root installati.

Unico nuovo child logico `terminal-continuation-v1` SOTTO la root originale `acquisition-read-apply-5fa62...`. Cambiare hash/launcher non riapre questo child o alcuno scope vecchio. Non usare il vecchio Context.__init__, bootstrap operativo, planner o reader. Il nuovo ingresso riusa definizioni qualificate e compone il proprio contesto senza rieseguire le entry precedenti.

Prima della review: verifica receipt/review/closure originarie e assenza di stato post-review originale, input nativi, socket/peerroot/coorte5/config/generazioni/risorse/identità Engine, archivi esatti e policy pubblica esistente. Tutti i conteggi partono dai9/1/5/1 retained e ogni nuova preflight li incrementa. Nessuna apertura del file admin o richiesta APISIX prima del consenso. Le82rotte nel documento pre-consenso sono dichiaratamente la snapshot congelata, non una nuova lettura admin.

La review privata nuova dichiara UNA lettura aggiuntiva dello STESSO file admin esistente, solo dopo APPROVO e firme, limite cumulativo2 inclusa quella già consumata. Tutti gli ALTRI massimi rimangono quelli originari:500EngineGET/22writes(inclusi6negativi)/3load/128healthGET/32adminGET/2adminPUT/64ownerConfig/3quarantineStops. Non è reset o refund del vecchio budget, e non concede budget fonte, IAM grant, attivazione o acquisizione. Il mandato deve essere accettato dal vero operatore sul terminale prima di questa ulteriore lettura.

Il parser resta esatto; la riga da digitare è separata da ogni spiegazione. L’agente non può precompilarla, simularla o usare il vecchio hash. Dopo decisione: nuova verifica coorte/policy, firme installer esistenti e900s+30negativa/180avvio. Watchdog pronto prima degli stage. Il PRIMO stage firmato e claimed è LOAD_EXISTING_ADMIN_KEY; solo lì si riserva ed esegue l’ulteriore lettura. Subito dopo verifica fresca delle82rotte, prima di QUALUNQUE mutazione. Drift, policy scaduta, revoca o ambiguità impongono STOP, mai fallback a snapshot positiva.

Poi gli stessi23stage di installazione già definiti:3import esatti,2READ isolati/readiness, solo vecchioMCP disableRestart/stop/detach/rename, un nuovoMCP/readiness,2rotte additive preservando82, restart policy e verifica finale/attestazione. Breve indisponibilità MCP dichiarata; Ingestion/UDP/Postgres/Gateway originali invariati, workerRegistry escluso. Normale bootstrap OAuth/manifest persistence del SOLO MCP sostitutivo può avvenire sotto mandato esistente. Nessun SQL repair, migrazione, fonte attivata o terza acquisizione.

## Watchdog e limiti della qualificazione

Il fallimento CI precedente LIVE_BOUND_NEGATIVE_WATCHDOG_REQUIRED resta conservato. Riprodotta deterministicamente una race del vecchio private_read: atomic replace può scollegare l’FD tra open e fstat, causando RECOVERY_FILE_CUSTODY_REQUIRED e uscita del monitor. Il vecchio job non aveva il dettaglio del figlio: la sua causa esatta non è retroattivamente provata.

Nuovo published_snapshot: massimo8tentativi di SOLA lettura; un FD scollegato NON viene accettato. Si ritenta esclusivamente se al path esiste una diversa istanza regolare pienamente custodied, poi viene restituita soltanto una snapshot completa valida. Hardlink, custodia errata, drift, file alterato e casi ignoti restano negati; esaurimento contesa blocca. Nessun lock CAS condiviso nelle attese, nessun retry degli effetti. Il watchdog scrive ora un reasonCode sicuro su errore.

Fix98d7c0a: protocollo13PASS/0skip su push40204373361/job121202047139 e PR40204377394/job121202060179; nativeclassic/containerd2PASS ciascuno su tutti4job121202047308/121202047405/121202060201/121202060078. Log diretti letti; reali filesystem/root/Ed25519/Docker/APISIX con owner/chiavi/dati sintetici.

CI finale a21f5bda: push40205143142/job121204362394(protocollo16PASS),121204362340(classic2+2PASS),121204362217(containerd2+2PASS); PR40205146169/job121204371162(protocollo16PASS),121204371275(classic2+2PASS),121204371296(containerd2+2PASS). Zero skip, log diretti letti in tutti6job. Qualifica finale e pin: `evidence/acquisition-reconciled-continuation-qualified-20261025.json`. Il fixture della continuazione verifica il vero Context e l’intero operator, con decisione HUMAN sintetica esplicitamente confinata al CI; parser PTY reale qualificato separatamente. Prova chiave non aperta prima del mandato, conteggi iniziali incorporati/cumulativo2,24stage,3import/3container/82+2rotte/attestazione, vecchio scope invariato e SIGKILL/quarantena dei soli candidati propri. Issuer/configurazioni private produzione e intero bootstrap download/sudo del wrapper non sono provati dalla CI. Wrapper bash-n/static review e17SHA/AST verificati separatamente. I16test protocollo locali usano fixture bootID dichiarata perché /proc/sys/kernel/random/boot_id non è disponibile nello scratch; non sono prova del boot reale.

## Esito da raccogliere

Atteso dopo consenso ed esecuzione completa: `ACQUISITION_READ_PATH_INSTALLED_E2E_NOT_ACCEPTED`, complete=true, reviewHash/authorityHash, contatori cumulativi e attestazione, Exit0/DeliveryExit0. Nessun risultato di questa continuazione sul VPS ancora ricevuto. Non dichiarare che il child o la nuova copia root esistano già.

Raccogliere SOLO JSON pubblici e Exit/Directory/Log più DeliveryExit/DeliveryDirectory/DeliveryLog. Mai review privata, Env, file configurazione, chiavi o token. STOP/CLAIMED/errore conserva prove/journal/contatori/candidati e consuma il child: NON rilanciare, rimuovere o cambiare scope.

Dopo installazione provata: ROLES ouf-admin (solo link_id/viewROLES), preservare2ruoli/34permission e2assegnazioni; nuova decisione HUMAN per6READ ristrette a tenant/source/2run/detail/label. Policy48 scaduta non autorizza letture. Ispezionare le DUE acquisizioni esistenti per bundle/CSV, ACK/watermark,13ID/20proprietà/materializzazione/provenance e8Cinema preservati ai limiti delle baseline valori disponibili. E2E/G4/F5/F6 OPEN, tecnico8/8/funzionale4/6, Supervisor dopo; nessun merge/release acceptance o Registry restart/reinstall/reset.

## Comando completo di prima invocazione della continuazione

Consegna immutabile 738f6252e977fbd7c99d83489c3d2f83e11c581f, sorgenti a21f5bda invariati. Eseguire UNA volta. Quando compare la riga isolata APPROVO con il nuovo hash, digitare esclusivamente quella riga dopo aver letto la review; non usare il vecchio hash e non aggiungere testo. La nuova lettura credenziale e i relativi limiti sono espliciti nella review. In STOP conservare e non rilanciare.

```bash
bash <<'SH'
set -euo pipefail
umask 077
d=$(mktemp -d "$HOME/ouf-continuation-delivery.XXXXXXXX")
set +e
(
  set -euo pipefail
  curl --fail --location --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 60 --retry 0 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/738f6252e977fbd7c99d83489c3d2f83e11c581f/releases/continue-acquisition-read-native-20261025.sh' \
    --output "$d/run.sh"
  printf '%s  %s\n' \
    'ef035a77a93e26e4f24f2e53123eac412457772329b7f8f0cb8a81a2e16fedde' \
    "$d/run.sh" | sha256sum --check -
  bash "$d/run.sh"
) 2>&1 | tee "$d/bootstrap.log"
rc=${PIPESTATUS[0]}
set -e
printf 'DeliveryExit=%s\nDeliveryDirectory=%s\nDeliveryLog=%s\n' \
  "$rc" "$d" "$d/bootstrap.log"
exit "$rc"
SH
```

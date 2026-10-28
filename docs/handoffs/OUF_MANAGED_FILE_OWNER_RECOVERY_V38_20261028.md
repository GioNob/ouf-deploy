# OUF — ownership legacy esplicita e persistente — 28 ottobre 2026

## Checkpoint corrente

La [lettura target](../../evidence/managed-file-ownership-read-target-20261028.json), [output integrale riportato](../../evidence/managed-file-ownership-read-target-20261028.log), è RIUSCITA e CONSUMATA: complete/Exit0/DeliveryExit0, 3metadata/5GET/UNA SQL READ ONLY,573839byte. Hash canonico risultato **1c0cff56d38d831bb0b0ea90674d754f2331601b771b7b347f2249977c7f7ad1**. Nessuna scrittura, budget, resume o nuova acquisizione. Directory `/home/oufadmin/ouf-managed-file-ownership-delivery.BngQ0kG4`; log root `/usr/local/lib/ouf-managed-file-ownership-read-14ccad386c764663/operator.log`. Non chiedere nuovamente log, non riconsegnare/rilanciare quel reader.

Farmacie **9c502da5-b5d8-405e-b3f5-60eb31ecb513**,13903byte,hash **sha256:f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311**: uploader coincide con subject atteso **b93d8cf6-cd14-4ee6-91d7-84cd76c4f500**, ma zero uploadreceipt e nessuna review tenant. Teatri **6609b245-86ed-4315-8ce0-73f2a8555bf3**,4404byte,hash **sha256:08b20658b2b4eadf34d25cd93eead2945096b353ae33b797cf3c41df5319c9e9**, ha invece la review tenant/subject esatta. La differenza del predicato ownership è provata. Non inferire il tenant dal superadmin. Identità/tenant browser NON osservati.

Stesso job **677480c8-3d10-44fd-9dad-f72ddeed20a4**, FAILED/tentativi5/version0/generation0; un solo job, nessuna recoverySession, zero sessioni/eventi. Il codice ONB_FILE_OWNER_SCOPE_UNPROVEN non contiene una scadenza: i900secondi non spiegano quel403.

Produzione resta schema36,Onboarding source **9890b31868641e5be43c949a56f4ef69dd23bdfd**,native **sha256:c512c24787304dc0ee40d2b5b1559d458ddf1d5a65a068775ef173c47ba849a3**. Ultimo APPLY THS riuscito e consumato: review **0990401fb938c73c13bd6be090c04a5291bfe52aa06d9546cdaf7e13659a10b8**,authority **ce93c610fee96883a11fb806d283565340ffe6d1e6e629acf883eaabae0956ba**,root `/etc/ouf/deploy-snapshots/managed-profile-ths-request-update-e22a443d-20261028-v1`,binding **2c5295203d6f190e04f2add429a617be69b2a72dd264b45f241a80d1aac09d0b**,PID3462703/start88998673. MCPd2454f3c/a5218012 e gli altri12peer invariati; Registryworker intatto. [Ricevuta APPLY](../../evidence/managed-profile-ths-request-update-target-20261028.json). Tutti i predecessori, IAM/publisher/capture/review/authority sono consumati. Policy56 SERVICE e Policy58 exact-job restano acquisite.

## Codice persistente qualificato, non installato

[PR53](https://github.com/GioNob/ouf-source-onboarding/pull/53), source **9d19fad3dd750dd5b9e77253d3e7e82029c1aca7**. [Qualifica completa e limiti](../../evidence/managed-file-owner-recovery-v38-qualified-20261028.json).

- V37 registra il tenant dal principal verificato nello stesso commit dell'asset; tenant/uploader immutabili, retry identico riconciliato, nessun backfill storico.
- V38 crea una tabella append-only di riconciliazione ownership, inizialmente vuota. Nessuna ownership viene concessa dall'installazione.
- La scheda offre una decisione HUMAN precedente a budget/resume: mostra tenant/subject della sessione fresca,hash/dimensione e stato/review correnti. Richiede uploader originario, due capability exact-job già previste, conferma esplicita e motivazione. Nessun tenant/subject scelto dal body e nessun superadmin bypass.
- Solo legacy CSV FAILED senza altra provenienza, sorgente, sessioni o budget e con un solo job è ammissibile. Review/input/version/generation vengono ricontrollati sotto lock; altra provenienza o deriva nega senza effetti.
- La decisione crea soltanto la ricevuta ownership. Asset/job/quarantena/tentativi/budget/eventi restano invariati. Stesso comando e intento restituiscono la stessa decisionRef anche dopo restart/risposta persa; intento/tenant diverso confligge.
- La ricevuta non può essere sovrascritta da una prova legacy contraddittoria. ASSETS e recovery usano lo stesso predicato; il binding sorgente nativo richiede ownership tenant sotto lock.
- Browser conserva il comando prima del dispatch. Se storage indisponibile/corrotto non invia nuove decisioni; risposta ambigua si riconcilia con stesso comando, mai retry automatico o nuovo budget.
- Le route Gateway già pubblicate coprono GET/POST del suffisso ownership e le scope esistenti. Nessuna route, IAM, ruolo, descriptor o grant nuovo richiesto da questo disegno.

CI sorgente:365test applicativi/0fail/0error/0skip,13casi owner runtime,3policy reali,upgrade37→38 e upgrade storico36→37 separati;9test browser reali Playwright,10test SDK. Build nonroot,scansione HIGH/CRITICAL/UNKNOWN inclusi unfixed e bootPASS. RunPR **40732932645**,job **122973771424**; runpush **40732921041**,job **122973734387**. Artifact immaginePR **12836316286**,ZIP213064533byte,SHA riportato CI **7719c1045753fe38bbdc498adb8f540c61bad411c25969badf71ec4d3ec5d91b**. ZIP non ancora scaricato/importato; nessun native imageId candidato dichiarato verificato. Build Docker locale CI5140811b non equivale all'identità archivio nativo da preparare.

## Prossimo passo: NUOVA sola lettura corrente

Builder `tools/build_managed_file_owner_inputs.py`, controller `tools/managed_file_owner_inputs/capture.py`, script `scripts/capture-managed-file-owner-inputs-20261028.py`. Source **35527fe8b4245f21681f588cb3c50673993448b9**,SHA **f5fe26b895ca600df89dee1abf26146131b78345838609066445ad5074de3faa**. Wrapper **940779c786a1cab74bfffca346a83211b062461c**,SHA **2433025d5762cba0eff9470d7657d716a17b0940f8e90ab5fa5f72d34eb761db**. Qualifica consegna **7432f0a31238997e76a0e5936ff2a777ef7e45a6**.

Nuovo root esclusivo **/etc/ouf/deploy-snapshots/managed-file-owner-recovery-inputs-1c0cff56-20261028-v1**.4metadata:3successo THS già concluso e1risultato ownership già acquisito.27GET Engine sulla medesima coorte13,solo metadati e pin processi/root/socket/boot.90s/24MiB. **Zero SQL**,contenuto fileconfig/credenziali/chiavi,IAM/OAuth,import/lifecycle/grant/budget/resume/job/upload/acquisizioni. Config/Env nelle risposte Engine possono contenere dati sensibili: custoditi soltanto root0600,mai nell'output pubblico. Nessuna authority o piano eseguibile.

Contabilità lineage da lettura ownership consumata: conserva573839byte/3metadata/5GET/1SQL; aggiunge4metadata/27GET/0SQL/byte monotoni. Cumulativi7metadata/32GET/1SQL,non contabilità dell'intero progetto. FAILED5 è etichettato osservazione conservata: questa cattura non verifica nuovamente stato DB/job/budget. Qualifica Docker29.8.1 con13container reali,pin reali,peerroot,4metadata/27GET,privati0600 e no-replay. Predecessore simulato in CI,nessuna prova target o E2E.

Come **oufadmin** sul VPS,in TTY; nessun login IAM o APPROVO. Usare soltanto se la qualifica collegata riporta `currentDeliveryUsable=true`:

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_owner_inputs_bootstrap=$(mktemp -d "$HOME/ouf-owner-inputs-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 16384 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/940779c786a1cab74bfffca346a83211b062461c/releases/capture-managed-file-owner-inputs-20261028.sh' \
    -o "$ouf_owner_inputs_bootstrap/run.sh"
  printf '%s  %s\n' '2433025d5762cba0eff9470d7657d716a17b0940f8e90ab5fa5f72d34eb761db' "$ouf_owner_inputs_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_owner_inputs_bootstrap/run.sh"
  /usr/bin/bash "$ouf_owner_inputs_bootstrap/run.sh"
)
```

Riportare solo JSON finale/Exit/Directory/Log/DeliveryExit/DeliveryDirectory/DeliveryLog. STOP o esito ambiguo conserva e consuma: non rilanciare,non eliminare root/codice/log. Consegna root0400 `/usr/local/lib/ouf-managed-file-owner-inputs-f5fe26b895ca600d/read.py`;logroot0600 nella stessa directory. Non inviare metadata privati o credenziali.

## Dopo la cattura, ancora da eseguire

Preparare lo ZIP CI esatto e il piano condizionale di aggiornamento SOLO Onboarding,36→38,backup/fence/snapshot e12peer invariati,conservando FAILED5/asset/job/quarantena e zero ricevute ownership/budget/eventi. Nessun APPLY ancora preparato/autorizzato/installato da questo checkpoint. Nuova concreta review HUMAN/firma separata; mai riciclare authority precedenti.

Solo dopo installazione/verifica inviare il link THS **all'utente**, senza aprirlo come agente:
https://api.ouf-lab.it/trusted-human/managed-files/recovery/?asset=9c502da5-b5d8-405e-b3f5-60eb31ecb513&job=677480c8-3d10-44fd-9dad-f72ddeed20a4

Tre decisioni HUMAN distinte: **ownership legacy** con identità/tenant effettivi; poi **budget3/900** con stato/review freschi; poi **resume dello stesso job/sessione**, cumulativi6–8,mai reset. Ambiguità:stesso comando/sessione senza altro budget. Poi originale/hash/parser/preview,Farmacie61righe→UDP,provenance,D5–D7 e dueclient reali,riusando Teatri/M1/typed/ASSETS/LATEST.

M1/G4 acquisiti;M2/G5/G6/G7/E2E aperti. CI/manutenzione/readiness non sono E2E. Supervisor dopo E2E completo. No terzaacquisizione/nuovojob/upload/reset/replay/attivazioneimplicita/Registryrestart o reinstall/merge/release acceptance/subagenti/automazioni. [Piano M2](../../releases/csv-m2-plan-20261026.json),[roadmap](../OUF_M2_ROADMAP_20261026.md),[industrializzazione](../OUF_MANAGED_PROFILE_THS_INDUSTRIALIZATION_20261028.md). PET originali ancora non esposti nei file correnti: nessuna pretesa di lettura integrale.

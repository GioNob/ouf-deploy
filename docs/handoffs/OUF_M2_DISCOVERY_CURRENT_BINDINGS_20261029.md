# OUF — Discovery stabile: nuova lettura corrente pronta

29 ottobre 2026, Europe/Rome. [Requisito bloccante](../OUF_M2_DISCOVERY_STABLE_OPERATION_20261029.md), [qualifica](../../evidence/m2-discovery-current-bindings-qualified-20261029.json), [PR Deploy51](https://github.com/GioNob/ouf-deploy/pull/51). Target NON eseguito; capability esterne ancora NON operative nella connessione.

## Nuova azione circoscritta

Come oufadmin in SSH interattivo, eseguire UNA sola volta il comando sotto. Non richiede IAM/APPROVO. Eventuale password è soltanto sudo locale. Non eseguire come root o da una pipe/nonTTY.

Legge3metadata immutabili del successoV38 e27GET Engine sullo stesso insieme13container; verifica socket/peer/processi/boot e doppia osservazione.90s/24MiB. Nessuna SQL, OAuth/IAM, chiave, contenuto fileconfig/credenziale, import, lifecycle, grant, budget, resume o acquisizione. I metadata Engine possono già contenere valoriEnv preesistenti: rimangono privati root0600; l'output pubblico contiene solo un riepilogo minimizzato.

È un NUOVO scope di lettura, non replay dei reader/controller consumati. Usa le vecchie receipt soltanto come provenienza, mai come authority corrente. Se STOP, conservare tutte le prove e non rilanciare.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_m2_bindings_bootstrap=$(mktemp -d "$HOME/ouf-m2-bindings-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 15 --max-time 60 \
    --max-filesize 16384 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/09d2a2ba407f109fe8261ce61a6875b05d16a8d8/releases/read-m2-discovery-bindings-20261029.sh' \
    -o "$ouf_m2_bindings_bootstrap/run.sh"
  printf '%s  %s\n' \
    'eaca415a403169f97d22ce4df6f3f2873e3acd160e2e085d523a1d58d656207c' \
    "$ouf_m2_bindings_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_m2_bindings_bootstrap/run.sh"
  /usr/bin/bash "$ouf_m2_bindings_bootstrap/run.sh"
)
```

Restituire il JSON finale e i footer Exit/Directory/Log/DeliveryExit/DeliveryDirectory/DeliveryLog. Non inviare inputs.json, risposte Engine complete, Env, fileconfig, chiavi o token.

## Pin e qualifica

Sorgente `8af878eca402bfe4598edb77ab0de239c575f506`, SHA256 `788772e96f1e956e5439e2148b80bb825fda700e0a3a05a2021109b71823f215`. Wrapper `09d2a2ba407f109fe8261ce61a6875b05d16a8d8`, SHA256 `eaca415a403169f97d22ce4df6f3f2873e3acd160e2e085d523a1d58d656207c`. Codice protetto `/usr/local/lib/ouf-m2-discovery-bindings-788772e96f1e956e/read.py`; nuovo scope `/etc/ouf/deploy-snapshots/m2-discovery-current-bindings-0601fdfa-20261029-v1`.

Qualifica `7131ea456379b361ef6cb3bc87e57c6030e511c3`:13test locali/CI PASS, Docker29.8.1 reale con13container isolati, socketUnix/rootpeer/pin processi reali, storia predecessore sintetica. Metadata3/GET27, positive bindings e vecchi file invariati, drift peer e replay negati. Consegna reale HTTPS/nonroot/sudo/root0400/checksumroot, nonTTY prima scope, codice negato a nonroot, STOPscope preservato. Tutti4job push/PR SUCCESS;4log finali e il log intermedio di guard letti. Nessuna prova target o discoveryOntoPiA in queste fixture.

## Dopo il risultato

Il riepilogo mostra dichiarazioni, hash/binding, immagini/generazioni e policy restart osservate; non prova impostazioniSpring effettive, readiness, provider raggiungibile, custody credenziali o ammissioneDB. Non inferire ACTIVE dal solo Envfalse/true. Il risultato determina i successivi delta/prove correnti e la review della manutenzione strettamente necessaria.

Il requisito stabile è vincolante: configurazione persistente e capability pubblicate per utenti autorizzati, recupero durabile dopo interruzioni/riavvii, budget finiti e stato veritiero, queryOntoPiA reale viaMCP/Gateway/Registry. Nessun workaround/manualimport/ontologia locale sostitutiva. Nessuna attivazione/restart/reinstall/nuovo budget o vecchia authority autorizzati dalla sola cattura.

Farmacie stessa identità asset/job/profilo preservata,61righe/10colonne già profilate; chiave ministerialeSTRING e tutti10campiOPEN confermati. Nessun nuovo profiling/upload/resume/acquisizione. M1/G4 acquisiti;M2/G5/G6/G7, semantica pubblicata/D5–D7/dueclient/E2E restano aperti. No merge/releaseacceptance/subagenti/automazioni.

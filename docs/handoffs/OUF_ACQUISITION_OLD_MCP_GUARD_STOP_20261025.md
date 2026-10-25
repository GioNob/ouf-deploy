# OUF — continuazione fermata sul guard del vecchio MCP

## Nuovo risultato reale del VPS

La prima invocazione della continuazione è stata eseguita. APPROVO esatto accettato; review `7fcbce1f43fd99b4add8db9913b3dc2fe215836f16eecd8e8191f9e344e54aa9`, authority `496dda9a7057f67c4ffb10e6ae4606d101479c905cad6a731907eaf4010d56a4`. La nuova lettura admin è avvenuta DOPO il mandato, cumulativo2, come proposto. Il problema di prompt precedente non si è ripetuto.

Esito `STOP_RECONCILE / OLD_MCP_CONFIG_GENERATION_REQUIRED`, complete=false, Exit2/DeliveryExit2, nel guard prima della claim RENAME_OLD_MCP. Fonte: allegato operatore Testo incollato(4).txt; ricevute JSON/progress normalizzati e hash dell’allegato in `evidence/acquisition-continuation-old-mcp-guard-stop-target-20261025.json`. Non pubblicare tutto il terminale o l’archivio PET. Timestamp VPS non fornito.

Log operatore `/home/oufadmin/ouf-acquisition-continuation.z1OkfMYu/operator.log`; delivery `/home/oufadmin/ouf-continuation-delivery.6iRiaI7q/bootstrap.log`.

Il progress attraversa LOAD_EXISTING_ADMIN_KEY, verifica baseline,3import,2CREATE/2START READ, verifica readiness2READ, disableRestart/STOP/DETACH del SOLO vecchioMCP. Quindi progressRENAME e guard fallito. Il codice ordinato colloca13stage APPLIED prima di quel punto e nessuna claim rename o creazione MCP/routePUT successiva; il journal effettivo verrà letto dal diagnostico, non dedotto come stato corrente. Il vecchioMCP è stato fermato/scollegato nella sequenza. Non riavviarlo, ricrearlo o ricollegarlo automaticamente. I2READ erano pronti prima dello STOP; la negativa può averli fermati, ma il suo esito non è nell’output ricevuto. Non dichiarare né candidati correntemente running né cleanup provato.

Ultimi contatori pubblici PRIMA del guard:119EngineGET/10writes/3imageLoad/2readinessGET/2adminGET/0adminPUT/40ownerConfig/2fileadmin/0quarantine. NON sono contatori finali: guard e negativa possono averli incrementati. Restano i massimi cumulativi500/22/3/128/32/2/64/2/3. Niente refund/reset o ulteriore lettura chiave.

Scope `acquisition-read-apply-5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591/terminal-continuation-v1` CONSUMATO. Codice17file/rootdc2af88d e tutti i vecchi scope/evidenze conservati. NON rilanciare il wrapper738f625, vecchi Context/operator/reader, oldMCP restart/rollback o una negativa scaduta.

## Differenza da osservare, senza ipotesi come fatti

Il guard OLD_MCP_CONFIG_GENERATION_REQUIRED raggruppa4uguaglianze: ImageID, hashConfig completo, hashmounts ordinati, State.StartedAt. Il messaggio non identifica quale diverga. La precedente preservazione MAC rende plausibile un delta di metadata dopo DETACH, ma non è ancora una causa target osservata e non autorizza normalizzazioni o guardie allentate.

Il prossimo passo è esclusivamente il lettore `scripts/read-acquisition-old-mcp-guard-20261025.py`, sorgente pinned `3de2eff5506917519e3837f36ae05dffa9af1d36`, SHA256 `34a0567d5774e0610e8a3afa87dfcbc1097a22b7027dd80451b607b5fc72744d`. Wrapper `releases/read-acquisition-old-mcp-guard-20261025.sh`, SHA256 `c74dc9a4035838ea340068ec5f70d53bf1712d2d4416a866684628f5b1579999`.

È un lettore OFFLINE: manifest17sorgenti installati/review/authority esatte, journal retained due volte stabili, inputc40 e catturaMCP storica vincolati, sole risposte Engine GIÀ conservate da questo scope e marker pubblici della negativa. Nessun nuovo Engine/APISIX/SQL/OAuth/proc/namespace/config attiva/credenziale/chiave; nessuna importazione/esecuzione di moduli operativi vecchi. Nessuna nuova approvazione runtime richiesta.

Crea solo il nuovo figlio esclusivo `retained-old-mcp-guard-v1` sotto lo scope fermato, con claim, prova privata di hash/comparazione e risultato0400; i file retained originari non vengono riscritti. Limiti30s/640letture metadata/64MiB, inventario≤1024entry e≤522risposte Engine. Se lo snapshot journal o i file cambiano, STOP senza retry/consumo extra runtime. Fsync, no-follow/fstat/hash, custodia root e no hardlink/symlink. Non usa stdout o log grezzi del watchdog come diagnostica.

Seleziona per seriale l’ultima risposta HTTP200 dell’esatto CID vecchioMCP, confronta i4componenti e riproduce il guard contro la cattura originaria autenticata. Per Config mostra solo nomi noti/tipi/presenza/default-like; nomi sconosciuti SHA256. JSONboolean e numero restano distinti. MacAddress, se effettivamente diverso, espone solo classificazioni/uguaglianza al precedente endpoint, MAI l’indirizzo. Env/labels/argv e valori privati esclusi. Nessuna normalizzazione della cattura originaria.

Proietta i conteggi FINALI registrati e gli stage effettivamente APPLIED, assenza di claim rename/newMCP, stato/candidati fermati provati nel journal di quarantena e presenza dei marker. Quarantena assente/parziale viene riportata come tale; non diventa successo cleanup dal solo complete del lettore. `currentRuntimeStateObserved=false` e `continuationAuthorized=false` rimangono espliciti: sono prove retained, non una nuova inspect del runtime.

## Qualificazione e prossimo recupero

CI push40206682028/job121208999476 e PR40206685845/job121209010852:14PASS/0skip ciascuno, log diretti letti. Filesystem root/FD/hash/stat reali, metadata/storia Docker/journal SINTETICI; nessun Engine/server target accessibile dal fixture.14PASS locali con il solo percorso temporaneo spostato nello scratch (guardie non alterate). Copre4componenti separati/redazione/nomi sconosciuti/JSONtipizzato, ultima risposta, parent immutato/no replay, authority/source/hash drift, hardlink/symlink/custodia, counter reset negato, claim extra negata e journal che cambia. Il caso MAC è un fixture di classificazione, NON prova della causa VPS. Wrapper bash-n/static review; non eseguito integralmente download/sudo inCI.

Atteso dal VPS `RETAINED_OLD_MCP_GUARD_DIFFERENCE_OBSERVED`, complete=true/Exit0, con soli JSON pubblici e Exit/Directory/Log più DeliveryExit/DeliveryDirectory/DeliveryLog. Se STOP, conservare il nuovo child/log e non rilanciare. Nessun risultato di questo lettore ancora ricevuto.

Dopo i campi effettivamente osservati: correggere solo quel delta, qualificare una continuazione del prefisso già APPLIED e della negativa reale, preservando3import/2create/STOP/DETACH/storico/contatori. Non ripetere effetti completati, non attribuire nuova autorità a firme scadute o a questa lettura offline. Eventuali riavvii dei SOLI candidati propri, nuovi limiti cumulativi indispensabili e lettura chiave devono essere concreti, dichiarati e approvati nel terminale prima degli effetti. Nessun nuovo comando mutante è attualmente consegnato.

502/403: precedenti prove VPS positive conservate, nessuna nuova richiesta originale eseguita. E2E/G4/F5/F6 OPEN, tecnico8/8/funzionale4/6; Supervisor dopo E2E. Niente terza acquisizione, fonte attivata, reset budget, Registry reinstall/restart, merge o releaseAcceptance. Non usare OUF MCP per letture protette/grant prima che la sostituzione/path sia provata; policy48 scaduta, ouf-admin resta l’account selezionato.

## Comando completo del lettore offline

Consegna immutabile ea93c93156e29577538b02b68f6fdbeb8d85f757; eseguire UNA volta. Nessun APPROVO richiesto. Attendere SOLO JSON pubblico e righe finali Exit/Directory/Log e DeliveryExit/DeliveryDirectory/DeliveryLog. STOP vieta rilancio. Questo comando non ripara o riavvia i servizi.

```bash
bash <<'SH'
set -euo pipefail
umask 077
d=$(mktemp -d "$HOME/ouf-old-mcp-guard-delivery.XXXXXXXX")
set +e
(
  set -euo pipefail
  curl --fail --location --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 60 --retry 0 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/ea93c93156e29577538b02b68f6fdbeb8d85f757/releases/read-acquisition-old-mcp-guard-20261025.sh' \
    --output "$d/run.sh"
  printf '%s  %s\n' \
    'c74dc9a4035838ea340068ec5f70d53bf1712d2d4416a866684628f5b1579999' \
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

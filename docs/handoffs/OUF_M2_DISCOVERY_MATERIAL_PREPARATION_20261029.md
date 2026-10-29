# Successore corretto disponibile

Il vecchio tentativo e il vecchio comando sotto restano CONSUMATI. [Unico NUOVO comando corrente, legato allo STOP esatto](OUF_M2_DISCOVERY_MATERIAL_ROLES_20261029.md). Non rieseguire il precedente.

# Stato corrente — STOP consumato, comando ritirato

Il comando riportato sotto è STORICO e NON va rieseguito. Esito operatore STOP_RECONCILE/INSTALLATION_ROLES_OUTSIDE_REVIEWED_COHORT dopo tre metadata, zero Engine o letture credenziali/copie. [Ricevuta](../../evidence/m2-discovery-material-preparation-target-stop-20261029.json). Correzione in corso con selezione per containerId e invarianti complete; nuovo successore da qualificare e collegare allo STOP esatto, preservando ogni scope consumato.

# Preparazione privata discovery — unico passaggio operatore corrente

29 ottobre 2026. La preparazione è qualificata in sorgente e **non è stata eseguita sul VPS**. [Evidenza completa](../../evidence/m2-discovery-material-preparation-qualified-20261029.json).

Serve l'accesso SSH interattivo di `oufadmin`: il connettore OUF disponibile in questa chat non espone un esecutore amministrativo del filesystem VPS. Non si richiede una nuova autorizzazione generale. L'attività prepara gli input infrastrutturali del percorso governato; le operazioni applicative e OntoPiA restano obbligatoriamente via MCP/Gateway/Registry.

La custodia precedente `eed64887cfcf18dc4be6de32c954b67649adf72ff384c3296d4bfe21ba1188c5` è riuscita e CONSUMATA. Anche gli scope f759/14e42 precedenti restano consumati: non rilanciarli, cancellarli o ricrearli.

## Cosa esegue

Un nuovo scope fisso `/etc/ouf/deploy-snapshots/m2-discovery-material-preparation-eed64887-20261029-v1`, massimo90secondi/16MiB:

- Legge tre record privati esatti, controllati per hash, metadati root0600, boot e generazioni; non riapre gli scope di provenienza.
- Ricontrolla tutti tredici peer con27 GET Engine al massimo, socket/peer Unix root e pin kernel prima/dopo. Non legge log applicativi.
- Verifica un file credenziale, due copie della chiave applicativa discovery e un certificato pubblico. Confronta le chiavi con i riferimenti APISIX esistenti per evitare collisioni di scopo.
- Prepara due NUOVE copie root:10001/0440 e una copia pubblica root:root/0600, tutte nel nuovo contesto root0700. Rilegge i tre output. Conserva intatti i file storici.
- Salva il piano e il nuovo inventario solo in `prepared-inputs.private.json` root0600. La chat riceve solo risultato minimizzato, impronte e contatori.

Nessun nuovo login, OAuth/IAM, grant/budget, SQL, firma, chiave, import immagine, modifica applicativa, lifecycle container, upload/job/resume/acquisizione. Il controllo del certificato è SOLO dell'involucro pubblico: non prova CA/validità corrente/trust/TLS e non crea ancora il truststore combinato IAM+provider. Le copie non provano validità della credenziale né ammissione runtime.

## Eseguire una sola volta

Aprire la normale sessione SSH come `oufadmin`, con terminale interattivo. Eseguire questo blocco esatto. L'eventuale password sudo resta nel terminale; nessun segreto o input privato va copiato nella chat.

```bash
(
set -euo pipefail
umask 077
ouf_material_bootstrap=$(mktemp -d "$HOME/ouf-m2-material-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/369ccc5cdb972dd7e361659f1f3d9cd47c59fe22/releases/prepare-m2-discovery-material-20261029.sh' \
  -o "$ouf_material_bootstrap/run.sh" &&
printf '%s  %s\n' '7e25e9e150f3452dd0e6c994ae0d38cb3db803cfb2c0dae59b2baa75d787c0bd' "$ouf_material_bootstrap/run.sh" | sha256sum -c - &&
chmod 0400 "$ouf_material_bootstrap/run.sh" &&
bash "$ouf_material_bootstrap/run.sh"
)
```

Il launcher scarica il capsule dal commit `6f2cc38a07a2b56542959716967e183f59217713`, verifica SHA256 `7f1c64c3f20f7c31ee76799c3aad28bd4e8d6fcb7dbe688f1a02726cf6dd603b`, lo protegge root0400 e avvia Python -I/-B/-S con ambiente vuoto. Sia lo scope esistente sia un precedente operator.log impediscono un nuovo avvio. Non sovrascrivere il log per sbloccare l'operazione.

Restituire SOLO JSON pubblico e footer OperatorExit/OperatorLog/DeliveryExit/DeliveryDirectory/DeliveryLog. Non allegare `prepared-inputs.private.json`, credenziali o chiavi.

## Esito e rientro

Il solo successo atteso è `PRIVATE_MATERIAL_COPIES_PREPARED_NOT_ADMITTED`, complete=true,13peer/27GET,2copie private/1certificato/3riletture e un nuovo preparedInputsHash. Gli exit devono essere0. I valori runtimeAuthorityIssued, targetApplyAuthorized, stableCapabilitiesOperationalProven, applicationE2EProven e releaseAcceptance restano false.

Anche uno STOP consuma il nuovo scope. Conservare contesto, copie parziali e log. **NON rilanciare**, cancellare o ricreare; prima va letto e riconciliato l'esito. I file storici e il contesto riuscito precedente non vengono modificati.

Dopo il successo, proseguire dalla nuova impronta privata con la preparazione coordinata: trust IAM+provider e ammissioni correnti, integrazione esecutiva completa a tredici fasi/worker distinto, fencing/backup/DB/cohort, review/HUMAN e authority native finite al momento corretto. Non acquisire token o aprire finestre prima che l'intero percorso sia pronto. Le capability discovery non sono ancora esposte; nessuna ricerca OntoPiA sostitutiva via web/Turtle o ontologia inventata.

## Qualifica

Sorgente produttiva01641bd4, capsule6f2cc38a, consegna369ccc5c; ultima sorgenteae11054d.127testPASS/0skip per push40860072911/job123400765696 e PR40860080014/job123400789917, log letti. Include8test con file/copie POSIX effettivi e5test del capsule esatto.

Docker29.8.1 reale,13container usa-e-getta,27GET/peer Unix root/pin kernel,2copie private/1pubblica/riletture e fonti/peer invariati: push40859066955/job123397346293 e PR40859078235/job123397384148 PASS, log letti. Peer fermo e replay rifiutati. Provenienza e input privati sintetici, nessuna esecuzione target.

Consegna HTTPS/nonroot/sudo/root0400 e checksum: push40859857287/job123400042223+123400042904 e PR40859864249/job123400067637+123400067010 PASS, quattro log letti. Caso metadata target assenti: il capsule produttivo byte-esatto si ferma prima di leggere credenziali. Caso log preesistente: nessuno scope/avvio, codice e log invariati. La prova positiva è quella nativa separata, non questo fixture negativo.

M1/G4 acquisiti. M2/G5–G7/D5–D7, otto criteri di stabilità ed E2E restano OPEN. Stesso Farmacie asset/job/profilo già SUCCEEDED e decisioni confermate, nessuna ripetizione. Nessun merge, acceptance, subagente o automazione.

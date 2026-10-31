# STORICO — riconciliazione RIUSCITA/CONSUMATA: NON eseguire il comando sottostante

[Esito target](../../evidence/m2-provider-reconciliation-target-20261029.json). Provider fermo; ID/immagine uguali, hash combinato configurazione/rete diverso in entrambe le API.13pincohort coincidono e store pubblico preservato. Il launcher corrente è ritirato; non riaprire lo scope. Nessun nuovo comando pronto: preparare correzione e review coordinate senza inferire autorità di restart o deriva statica dal solo hash.

# Riconciliazione provider in sola lettura

29 ottobre2026. Consegna qualificata; nuovo scope **NON ESEGUITO sul VPS**.

Il precedente trust/context si è fermato su `CURRENT_RETAINED_PROVIDER_IDENTITY_CHANGED`, dopo aver preparato e riletto il PKCS12 pubblico e prima delle OCI. Quello scope resta FALLITO/CONSUMATO; store, risposte Engine e log vanno conservati. Il successo materiali68daa9 resta valido e consumato.

[Esito target precedente](../../evidence/m2-discovery-trust-context-target-stop-20261029.json). [Qualifica di questa lettura](../../evidence/m2-provider-reconciliation-qualified-20261029.json).

## Scopo

Il messaggio precedente raggruppa confronto identità e stato Running/Paused/Restarting. Questa lettura separa i controlli: confronta **tutti** i campi dell'identità originale (containerId, immagine, hash completo Config/HostConfig/Mounts/reti), lo snapshot1.44 già salvato e le due rappresentazioni correnti1.44/API negoziata dal medesimo Engine root. Non elimina campi e non cerca container per nome.

La prova Docker29.8.1 usa API negoziata1.56: nel provider di fixture l'identità coincide in entrambe le versioni, nonostante differenze della risposta completa. Questo **non dimostra** un difetto API sul VPS. La fixture rileva invece una reale modifica RestartPolicy, un provider fermo e un vecchio processo core assente, senza concedere ammissione. Il risultato sul VPS deve ancora stabilire quale controllo fallisce.

Il PKCS12 già preparato viene soltanto verificato e riletto: nessun nuovo store, CA, file credenziali/chiavi o OCI. I vecchi processi core assenti o sostituiti sono fatti d'incidente, non prova di cohort corrente. Root/Engine/boot restano legati al record esatto; le osservazioni devono rimanere stabili durante la lettura. Nessun match conferisce permesso di ripresa, avvio o installazione.

## Unico comando corrente

Serve SSH interattivo sul VPS come `oufadmin`: il connettore OUF non espone un executor per questi file protetti e per il socket Unix locale. Il flusso applicativo rimane ChatGPT→MCP→Gateway→Registry→OntoPiA.

Eseguire **una sola volta**:

```bash
(
set -Eeuo pipefail
umask 077
[[ "$(id -un)" = oufadmin && -t 0 && -t 1 ]] || { printf '%s\n' 'OUFADMIN_INTERACTIVE_SSH_REQUIRED' >&2; exit 1; }
ouf_bootstrap=$(mktemp -d "$HOME/ouf-m2-provider-reconcile-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 16384 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/4dcbdc900855f401c897f99d77fae68fb8816066/releases/prepare-m2-provider-reconciliation-20261029.sh' \
  -o "$ouf_bootstrap/run.sh"
printf '%s  %s\n' '36895e6d53ed008670937b03a6bc947bb45c2ca6441cca34a9c0b371c21cc5ce' "$ouf_bootstrap/run.sh" | sha256sum -c -
bash "$ouf_bootstrap/run.sh"
)
```

Eventuale sudo soltanto nel terminale. Restituire esclusivamente JSON finale e footer OperatorExit/OperatorLog/DeliveryExit/DeliveryDirectory/DeliveryLog. Nessun file privato o valore environment in chat.

## Vincoli e lettura dell'esito

Nuovo scope: `/etc/ouf/deploy-snapshots/m2-provider-reconciliation-960507a9-20261029-v1`,45s/4MiB. Sei metadati esatti, una rilettura del solo store pubblico preservato e al massimo cinque GET locali/versione-provider esatto. Zero Engine writes, lifecycle/restart/firewall/IAM/OAuth/SQL, file credenziali/chiavi, nuove chiavi/firme, grant/budget, upload/job/resume o apply applicativo.

Prima della prima richiesta verifica il risultato STOP esatto `960507a9…`, il record materiali68daa9, la ricevuta dello store e la sua custodia root:10001/0440, il manifesto originale732a e il claim/response del terzo GET fallito. Le risposte complete rimangono root0600; l'output pubblico contiene controlli booleani, classificazione e hash.

Atteso: `READ_ONLY_PROVIDER_RECONCILIATION_COMPLETE`, complete=true, OperatorExit0/DeliveryExit0. Osservare `analysis.identityChecks`, `analysis.stateChecks`, `analysis.matchingCurrentApis` e `retainedCorePinStates`. Conservare `reconciliationHash`, `preservedTrustInputsHash`, `preservedPublicStoreSha256`.

Completa è soltanto la lettura. `providerAdmissionProven`, `currentFullCohortConfigurationProven`, `resumeAllowed`, authority/apply/E2E restano false. Anche un esito senza match o con provider fermo è una diagnosi, non una richiesta di restart.

Anche STOP consuma lo scope. Non rilanciare, cancellare, ricreare o sovrascrivere log. Nessun vecchio collector viene ripreso. Dopo il risultato preparare la correzione e la review native con le evidenze esatte, preservando store/storia e authority finite.13fasi/worker distinto/IAM/TLS/DB/stabilità/E2E restano aperti; niente token/finestra anticipati, bypass, merge o acceptance.

## Qualifica

Quattordici test per push/PR (dieci diagnosi/guard e quattro capsule), zero skip, log letti. Cinque moduli esatti, capsule SHA256 `a3dc3693cb08e2140cff764350529873c05ef52158b3e0440b3a904e2fe6b83f`,81813byte; wrapper SHA256 `36895e6d53ed008670937b03a6bc947bb45c2ca6441cca34a9c0b371c21cc5ce`. I capsule consumati trust/context5e93 e material-roles3f21 restano byte-esatti.

Prova nativa: tredici peer core e un provider, Unix peer root/pin kernel, CA/store e provenienza storica sintetici. Deriva configurativa reale e provider fermo non vengono autorizzati, store alterato e predecessore diverso sono rifiutati prima di Engine. Scope/log e store precedente restano preservati. Quattro job di consegna HTTPS/nonroot/sudo/root0400 provano rifiuto senza TTY, metadata assenti, log precedente e replay.139regressioni per push/PR superate. Nessuna di queste prove è ammissione o E2E target.

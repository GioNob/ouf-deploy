# STORICO — preparazione RIUSCITA/CONSUMATA: NON eseguire il comando sottostante

[Esito target](../../evidence/m2-stopped-provider-inputs-target-20261029.json):11metadata/661574byte,27GETcore+5contesto,13core/1OCIRegistry/0OCIprovider,contratto storico verificato e storepreservato. installationInputsHash1868b57c9fbbb3f05b6f8b2eedeb2f1afe14c0ad4cf15cc7f3e039bbedd6d083. Fonte JSON/footerutente,nessuna letturaindipendenteprivati/log. Launcher ritirato e scope CONSUMATO. Nessun nuovo comando pronto; completareammissionecoordinataprovider+workerdistinto e13fasi/TLS/IAM/DB/boot/rotazione dai nuoviinput. Nessunrestart/driverstorico/authorityimplicita;M2/stabilità/E2E OPEN.

# Provider fermo: input per la revisione coordinata

29 ottobre 2026, Europe/Rome. Preparazione qualificata, **nuovo scope NON ESEGUITO sul VPS**. [Qualifica](../../evidence/m2-stopped-provider-inputs-qualified-20261029.json).

## Punto acquisito

La [riconciliazione riuscita](../../evidence/m2-provider-reconciliation-target-20261029.json) è CONSUMATA. Il provider selezionato per ID/immagine è fermo in entrambe le API; tredici pin core coincidono e lo store pubblico è preservato. L'hash storico include la rete di runtime: la differenza non prova una deriva statica. Il test Docker reale dimostra che uno stop può modificare la rete lasciando Config/HostConfig/Mounts uguali; la causa specifica sul VPS resta non provata.

Il precedente collector live-peer deve continuare a rifiutare un provider fermo. La nuova preparazione ha un modello esplicito di **dipendenza fermata**, conserva i record originali come provenienza e non esegue il driver storico. Non riapre scope precedenti.

## Perché serve questa preparazione

Recupera in una sola lettura governata gli input mancanti alla revisione di installazione: driver e quattro contratti originali esatti; ricevuta pubblica e record privato della riconciliazione84184832; materiali68daa9; trustafbbe480 e store33418234; configurazione owner IAM0b72275 e il suo riferimento pubblico alla policy nativa. Riosserva configurazione completa/immagine/mount/rete/generazione dei tredici core e il contesto OCI/namespace del solo Registry operativo.

Il provider deve essere ancora esattamente nello snapshot fermo acquisito: non gli viene inventata una OCI o un namespace vivo. Il suo vecchio flag di start e il runtime autenticato storico non conferiscono autorità corrente. Il nuovo provider dovrà avere una fresca ammissione coordinata e un worker di lease distinto, prima di ATTEST_NEW_OCI_PEER del Registry. L'esecutore completo a tredici fasi è ancora da integrare.

## Unico comando corrente

Il connettore MCP OUF non espone esecuzione privilegiata sul filesystem VPS e sul socket Unix locale. Per questa preparazione infrastrutturale serve un terminale SSH interattivo come `oufadmin`. Il percorso applicativo resta ChatGPT → MCP OUF → Gateway → Registry → OntoPiA, senza aggiramenti.

Eseguire **una sola volta**:

```bash
(
set -Eeuo pipefail
umask 077
[[ "$(id -un)" = oufadmin && -t 0 && -t 1 ]] || { printf '%s\n' 'OUFADMIN_INTERACTIVE_SSH_REQUIRED' >&2; exit 1; }
ouf_bootstrap=$(mktemp -d "$HOME/ouf-m2-stopped-provider-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 16384 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/0c29421d39190f784f62c3928ac69c9c1138587d/releases/prepare-m2-stopped-provider-inputs-20261029.sh' \
  -o "$ouf_bootstrap/run.sh"
printf '%s  %s\n' '7b56c3eb8128085ce5704432ac87f2f6e3b89e9c06375517521fa9e8a2280a39' "$ouf_bootstrap/run.sh" | sha256sum -c -
bash "$ouf_bootstrap/run.sh"
)
```

La password sudo, se richiesta, va inserita soltanto nel terminale. Restituire esclusivamente il JSON finale e il footer OperatorExit/OperatorLog/DeliveryExit/DeliveryDirectory/DeliveryLog; nessun file privato o valore di configurazione in chat.

## Perimetro e risultato

Scope nuovo: `/etc/ouf/deploy-snapshots/m2-stopped-provider-inputs-84184832-20261029-v1`. Massimo90s/16MiB: undici metadati esatti,27GET core+5GET contesto, una rilettura del solo store pubblico preservato, una lettura OCI del Registry. Zero OCI del provider, file credenziali/chiavi/MAC, letture CA, nuovo store, IAM/OAuth/SQL, firme, nuove chiavi, import, lifecycle/restart/firewall, grant/budget, upload/job/resume/acquisizioni/apply.

Atteso: `STOPPED_PROVIDER_INSTALLATION_INPUTS_PREPARED_NOT_ADMITTED`, complete=true, OperatorExit0/DeliveryExit0 e `installationInputsHash`. Il record privato `installation-inputs.private.json` resta root0600. Input preparati non equivalgono a policy attesa compilata, peer ammesso, trust TLS/IAM/DB verificato o capability operativa.

Anche STOP consuma il nuovo scope. NON rilanciare/cancellare/ricreare o sovrascrivere log; conservare output e tutti gli scope precedenti. Il vecchio comando di riconciliazione è ritirato, così come i precedenti comandi consumati.

## Qualifica e limiti

PR54 ancora DRAFT, senza merge. Preparazionea1a24e9, capsulecc20f66, consegna0c29421. Capsule di sei moduli,97372byte, SHA256 `f312b973e0692495838c1e61ed9617bcd35099b5ee795f5a95dee7e52eeaad08`; wrapper2592byte, SHA256 `7b56c3eb8128085ce5704432ac87f2f6e3b89e9c06375517521fa9e8a2280a39`.

Otto test per push/PR senza skip, esportazione riproducibile e rifiuto di modulo aggiunto o sorgente alterata anche con hash payload ricomputato. Docker29.8.1 reale, tredici core più provider, pin kernel, OCI/namespace Registry reali; contratti/CA sintetici. Rifiutati record/store alterati prima di Engine, provider divenuto running prima di OCI, replay dello scope; file originali preservati. Quattro job HTTPS/nonroot/sudo/root0400 qualificano nonTTY, metadata assenti, log precedente e scope consumato.139regressioni PASS. Log citati letti; sorgenti/capsule precedentemente consumati byte-esatti. Le prove CI non sono prove VPS o accettazione E2E.

Dopo il risultato riprendere dagli input esatti: dipendenza provider con nuova ammissione e worker distinto; composizione completa tredici fasi, rete/TLS/IAM/DB/fencing/backup, boot/rotazione; pubblicazione governata delle capability; discovery OntoPiA reale; adozione HUMAN; percorso Farmacie fino a UDP, reimport/guasti/ripresa e due client reali. M1 e decisioni Farmacie restano acquisiti; M2/G5/G6/G7 e gli otto criteri di stabilità restano OPEN. Nessun token/finestra anticipati, vecchia authority, reset budget, bypass, merge, release acceptance, subagenti o automazioni.

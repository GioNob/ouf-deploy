# STORICO — scope FALLITO/CONSUMATO: NON eseguire il comando sottostante

Il target si è fermato su CURRENT_RETAINED_PROVIDER_IDENTITY_CHANGED dopo il PKCS12 pubblico e prima delle OCI; il materiale parziale e le risposte Engine restano preservati. [Esito](../../evidence/m2-discovery-trust-context-target-stop-20261029.json). Il launcher corrente è ritirato. Nessun nuovo comando è pronto; riconciliare il provider dai record già acquisiti, senza riaprire scope o azzerare budget.

# Preparazione trust pubblico e contesto nativo corrente

29 ottobre 2026. Stato: consegna qualificata, **NON eseguita sul VPS**. Il precedente scope materiali è RIUSCITO/CONSUMATO e resta in sola lettura. Non rilanciarlo.

Il passaggio prepara il PKCS12 pubblico IAM/provider con i certificati esatti, collega i record al preparato `68daa9c9…` e alla configurazione dell'owner IAM, e raccoglie il contesto Docker/OCI corrente per la revisione coordinata. Non concede ammissione IAM/TLS/DB né authority di installazione. L'esecutore completo a tredici fasi e il worker provider distinto restano aperti; discovery non è ancora esposta dal connettore.

[Qualifica e ricevute CI](../../evidence/m2-discovery-trust-context-preparation-qualified-20261029.json). Il pacchetto chiuso di nove moduli è riproducibile byte per byte: SHA256 `5e93e2248307b2cd33edf60485eabe085df1c535431f061d34eddbf413641519`, 102541 byte. Wrapper SHA256 `cd8d4ea2a791a834db75e4022b290a1d037fce3f5445cffabf434399f1da8da5`. Nessuna modifica dei precedenti moduli/capsule consumati.

La prova usa Docker29.8.1 reale, tredici peer e un provider aggiuntivo, peer Unix root/pin kernel, due configurazioni OCI e namespace verificati. Quattro test del capsule per push/PR, sedici test del trust incluso filesystem root e Java21, due issuer TLS isolati e rifiuto terza CA/MAC alterato. Quattro job di consegna HTTPS/nonroot/sudo/root0400 provano il rifiuto senza TTY e la conservazione di log/scope precedenti. Regressione139 PASS per push/PR. Tutti i log citati sono stati letti. CA e provenienza della fixture sono sintetiche: questi esiti non sono ammissione target o E2E.

## Ricevuta del comando precedente

Il footer `MATERIAL_ROLE_PREPARATION_SCOPE_CONSUMED_NO_REPLAY` con directory `ouf-m2-discovery-material-roles-delivery.qQDBrdmF` appartiene al precedente material-roles già riuscito e consumato. Non è un esito di questo trust-context. Il successo68daa9 resta conservato. Non riaprire alcuno scope e non usare il vecchio launcher. La ricevuta duplicata è registrata separatamente; non prova un'esecuzione trust-context.

## Unico comando corrente

Serve una sessione SSH interattiva sul VPS come `oufadmin`. Il connettore OUF non espone un esecutore remoto per questo filesystem; questo è il motivo dell'intervento operatore. Il flusso applicativo resta ChatGPT→MCP→Gateway→Registry→OntoPiA.

Eseguire **una sola volta**:

```bash
(
set -Eeuo pipefail
umask 077
[[ "$(id -un)" = oufadmin && -t 0 && -t 1 ]] || { printf '%s\n' 'OUFADMIN_INTERACTIVE_SSH_REQUIRED' >&2; exit 1; }
ouf_bootstrap=$(mktemp -d "$HOME/ouf-m2-trust-context-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 16384 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/7d3c9cc8cfc7f8385f3a697e08b1b94737a08d61/releases/prepare-m2-discovery-trust-context-20261029.sh' \
  -o "$ouf_bootstrap/run.sh"
printf '%s  %s\n' 'cd8d4ea2a791a834db75e4022b290a1d037fce3f5445cffabf434399f1da8da5' "$ouf_bootstrap/run.sh" | sha256sum -c -
bash "$ouf_bootstrap/run.sh"
)
```

L'eventuale password sudo si inserisce esclusivamente nel terminale. Restituire solo il JSON finale e le righe OperatorExit/OperatorLog/DeliveryExit/DeliveryDirectory/DeliveryLog; i file privati restano sul VPS.

## Ambito finito

Nuovo scope: `/etc/ouf/deploy-snapshots/m2-discovery-trust-context-68daa9c9-20261029-v1`. Deadline90s, massimo16MiB,32GET Engine (27 per i tredici peer originali,5 per info/provider esatto/rete),5metadati esatti,2CA pubbliche,2configurazioniOCI. Un nuovo `provider-trust.p12` root:10001/0440 con rilettura. Le configurazioni e risposte Engine possono includere environment privati e rimangono nei file root0600 del nuovo scope.

L'owner IAM è selezionato mediante review/configurazione con hash esatti, mai mediante ricerca di credenziali. Il provider è selezionato per containerId/immagine/configurazione sigillati nel manifesto materiali originale; si osservano pin e namespace correnti. Sono ammessi soltanto i due alias Docker /run/docker/netns e /var/run/docker/netns che risolvono allo stesso namespace protetto e combaciano con il processo corrente. L'OCI osservato rimane evidenza del presente, non policy attesa del sostituto.

Zero letture di file credenziali/chiavi applicative, login/IAM/OAuth/SQL, generazione chiavi, firme, import immagini, operazioni lifecycle/firewall, grant/budget, upload/job/resume/acquisizione o attivazione applicativa.

## Esito e ripresa

Atteso: `PUBLIC_TRUST_AND_NATIVE_CONTEXT_PREPARED_NOT_ADMITTED`, complete=true, scopeConsumed=true, OperatorExit0/DeliveryExit0. Conservare `publicTrustInputsHash` e `nativeContextHash`; il numero peer è13 o14 secondo l'appartenenza effettiva del provider al cohort originale. `targetApplyAuthorized`, ammissioneTLS/IAM e E2E restano false.

Anche STOP_RECONCILE consuma lo scope. Non rilanciare, cancellare, ricreare né sovrascrivere log o file parziali. Il codice conserva gli output già scritti e produce un reasonCode minimizzato. Dopo il risultato proseguire dalla nuova evidenza esatta con l'integrazione coordinata/worker distinto; nessuna finestra/token o firma anticipata, nessun riutilizzo di authority storica, reset budget, merge o acceptance.

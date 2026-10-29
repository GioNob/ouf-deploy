# M2 — Lettura del contratto runtime corrente del provider

29 ottobre 2026. Operazione di sola lettura, distinta dall’uso ordinario delle
capabilities. Il flusso di prodotto rimane CSV → lavorazione governata → oggetti
UDP; le capabilities UDP operano poi sugli oggetti caricati. Search non è una fase
di caricamento. M1/G4 conservati; M2 e accettazione E2E ancora OPEN.

## Perché serve l’intervento sul VPS

La fase iniziale del worker è ora composta e qualificata nativamente, ma richiede
un provider realmente ammesso nella generazione corrente. Input1868 conserva
cinque sorgenti storiche e l’inspect del provider fermo: non contiene la selezione
effettiva del named runtime nell’Engine corrente né i byte correnti di wrapper,
configurazione runtime, Broker e profili attestation/approval. I contratti v4/v6
esistenti non vanno presunti attivi o trasformati in una nuova authority.

Le capabilities MCP disponibili non eseguono comandi privilegiati e non leggono
questi file. Non è disponibile un executor SSH dell’agente. L’unico intervento
necessario all’owner è eseguire una volta il comando circoscritto sotto da SSH
interattivo come `oufadmin`, quindi riportare il JSON finale e i footer. Non serve
un login IAM/THS, un nuovo token o una finestra di autorizzazione runtime.
L’eventuale password sudo rimane nel terminale locale.

## Perimetro e limiti

- Legge soltanto result/input1868 esatti, con hash canonici già acquisiti.
  Il vecchio scope rimane consumato e immutato; non esegue il vecchio launcher.
- Quattro GET Engine complessive, su due soli endpoint: `/v1.44/info` e
  l’inspect del provider esatto. Socket/inode e peer root SO_PEERCRED devono
  corrispondere; il provider deve essere ancora fermo e con la stessa configurazione.
- Segue solo il named runtime effettivamente selezionato e un wrapper OUF di
  forma chiusa, senza eseguirlo. Legge configurazione e sorgente adapter; se
  presente la voce del provider, legge Broker e tre profili metadata esatti,
  con path deterministici e hash. Non segue binding di chiavi o credenziali.
- Ricontrolla la custodia di tutti i file e il contratto Engine/provider. Massimo
  18 letture metadata, 16MiB complessivi, 90 secondi di esecuzione; deadline
  anche sulle chiamate bloccanti. Nessun elenco/esplorazione di directory.
- La sola scrittura riguarda nuovo codice protetto e nuovi record audit.
  Nessuna modifica ai file applicativi esistenti, daemon-reload, container
  create/start/restart, signing, SQL, IAM/OAuth, grant, budget, upload o job.
- Stampa solo classificazioni note, schemi, hash, conteggi e booleani. Config,
  Env, indirizzi, credenziali e contenuti privati non vengono stampati. Il report
  è metadata e provenienza; non è ammissione del provider o readiness.

Nuovo scope monouso:
`/etc/ouf/deploy-snapshots/m2-provider-runtime-contract-1868-20261029-v1`.
Un errore/STOP conserva il tentativo e i risultati; **non rilanciare**. Anche un
log protetto di un tentativo precedente blocca l’esecuzione prima dello scope.

## Codice e qualifica

- Reader immutabile: commit `6ae7db0f157fb9fe84bdd01b2512445b7e0b184f`,
  SHA256 `ffa56e75f434893a7dc1f31e0a6078c2e3ec3a1f48cd019102e74a920334492b`.
- Launcher immutabile: commit `af3e33e0ff1864df538e01a232846346a723562a`,
  SHA256 `e5dfa9d2bcb5109158be6daa5d35017543c1e5baddf9903ccc3112a08794cc17`.
- 16 test PASS/0skip per push e PR, con file root privati e vero server HTTP
  Unix/SO_PEERCRED. Le risposte Engine e i profili applicativi sono sintetici:
  nessuna osservazione del target è inferita.
- Quattro job di delivery PASS: HTTPS effettivo, account nonroot/sudo, codice
  root0400/checksum root, rifiuto nonTTY prima del download/scope, file protetto
  non leggibile dall’account, fallimento preservato, replay e log preesistente
  negati. Sei log letti direttamente fra protocollo e delivery.
- [Evidenza completa](../../evidence/m2-provider-runtime-contract-qualified-20261029.json).

## Unico comando corrente

Da SSH interattivo come `oufadmin`, una sola volta:

```bash
(
  set -Eeuo pipefail
  umask 077
  task_delivery=$(mktemp -d "$HOME/ouf-m2-runtime-contract.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/af3e33e0ff1864df538e01a232846346a723562a/releases/read-m2-provider-runtime-contract-20261029.sh' \
    -o "$task_delivery/read.sh"
  printf '%s  %s\n' 'e5dfa9d2bcb5109158be6daa5d35017543c1e5baddf9903ccc3112a08794cc17' "$task_delivery/read.sh" | sha256sum -c -
  /usr/bin/bash "$task_delivery/read.sh"
)
```

Riportare **solo JSON finale e footer** `OperatorExit`, `OperatorLog`,
`DeliveryExit`, `DeliveryDirectory`, `DeliveryLog`; non inviare i file privati.

Dopo l’esito, vincolare il provider child e il suo scope parent ai fatti correnti,
comporre gate-only/ammissione/consumo e ripausa prima di Registry ATTEST. Poi
coorte13peer/TLS/IAM/DB/trust/fencing, boot/rotazione, pubblicazione capability e
prove OntoPiA/CSV→UDP; le capabilities UDP sugli oggetti caricati si qualificano
separatamente. Nessun vecchio mandato, authority, scope o budget viene riaperto.

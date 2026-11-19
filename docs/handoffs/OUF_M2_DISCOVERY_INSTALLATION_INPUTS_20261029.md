# OUF — Riferimenti dell'installazione discovery: lettura qualificata pronta

29 ottobre 2026, Europe/Rome. [PR52](https://github.com/GioNob/ouf-deploy/pull/52), [qualifica](../../evidence/m2-discovery-installation-inputs-qualified-20261029.json), [composizione applicativa](OUF_M2_DISCOVERY_CURRENT_BINDINGS_20261029.md). M1/G4 acquisiti; M2 e le otto condizioni di stabilità restano aperti.

## Perché serve questo passaggio

La cattura precedente è riuscita e consumata:13binding,27GET,zero effetti. Il profilo attuale dichiara provider/worker disabilitati e non contiene una prova dei riferimenti effettivi di provider, workload e mount necessari alla nuova review. Il pacchetto Registry è qualificato e verificato; MCP e Gateway sono composti e qualificati. La manutenzione persistente deve essere preparata con i riferimenti selezionati del target, senza scegliere identità o segreti storici e senza attivare il vecchio profilo file-only.

La nuova lettura usa soltanto due record esatti già conservati come provenienza, poi osserva due volte Registry,MCP,Gateway owner eAPISIX:9GET Engine. Altri9peer non vengono riosservati e nessuna nuova autorità è emessa. Produce riferimenti dichiarati nonsegreti, presenza delle superfici di override e impronte dei mount; i valoriEnv completi e i percorsi sorgente dei mount rimangono privati. Non legge contenuti di fileconfig,credenziali o chiavi. Non prova configurazione effettiva,custody,readiness,provider raggiungibile oDBadmission.

## Unica azione operatore

Come **oufadmin in SSH interattivo**, eseguire UNA volta il seguente comando. È il percorso di manutenzione già previsto; non richiede IAM oAPPROVO. Eventuale password è soltanto sudo locale. Non eseguire come root o in pipe/nonTTY.

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_m2_installation_bootstrap=$(mktemp -d "$HOME/ouf-m2-installation-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 15 --max-time 60 \
    --max-filesize 16384 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/c2035ca457e95f95d772b8e3660c241bfdec6e7b/releases/read-m2-discovery-installation-inputs-20261029.sh' \
    -o "$ouf_m2_installation_bootstrap/run.sh"
  printf '%s  %s\n' \
    'ec7775e982a705feb7a8ceaaa789397241d990eed36c7efefb26fde675dcb969' \
    "$ouf_m2_installation_bootstrap/run.sh" | sha256sum -c -
  chmod 0400 "$ouf_m2_installation_bootstrap/run.sh"
  /usr/bin/bash "$ouf_m2_installation_bootstrap/run.sh"
)
```

Restituire **solo il JSON finale e i footer Exit/Directory/Log/DeliveryExit/DeliveryDirectory/DeliveryLog**. Non inviare inputs.json,Engine completo,Env,configfile,chiavi ocredenziali.

Successo atteso: `M2_DISCOVERY_INSTALLATION_REFERENCES_CAPTURED_NOT_AUTHORIZED`, complete=true,4target,9GET e2metadata,Exit0/DeliveryExit0. In caso STOP conservare tutte le prove e non rilanciare. Nessun nuovo scope alternativo, replay oreset automatico.

## Pin e prove

Sorgente `41e4dda40899c85307a79dbc90c4385355bdc52d`, SHA256 `f9574bc696b34077e146f74810918625880a48d2108fc8038834eb23e45779ed`,23578byte. Wrapper `c2035ca457e95f95d772b8e3660c241bfdec6e7b`, SHA256 `ec7775e982a705feb7a8ceaaa789397241d990eed36c7efefb26fde675dcb969`. Qualifica `5f558b4c070f02f04f85d8031a705acda4a1d3ef`.

15test nuovi e13regressioni del reader precedente:28PASS/0skip. Docker29.8.1 reale su runner isolato,13container usa-e-getta e4selezionati per il nuovo reader, socket root/pin processi e namespace reali. Il predecessore è sintetico: non è una prova target oE2E.9GET/2metadata, vecchia cattura e binding positivi invariati, drift selezionato e replay negati; output privati0600 e segreti esclusi dal riepilogo pubblico.

Consegna reale HTTPS/nonroot/sudo, sorgente root0400 e checksum verificato root; rifiuto nonTTY prima dello scope, lettura sorgente negata a nonroot, STOPscope conservato. Nessun eseguibile gh otimeout richiesto. Tutti4job finali push/PR SUCCESS;4log letti direttamente. Nessun effetto IAM,SQL,container oapplicazione.

Nuovo scope `/etc/ouf/deploy-snapshots/m2-discovery-installation-inputs-14e42ac9-20261029-v1`, ancora NON eseguito. Codice protetto `/usr/local/lib/ouf-m2-discovery-installation-inputs-f9574bc696b34077/read.py`.90secondi/24MiB,2MiB per risposta; massimo3letturemetadata del primitive riusato, solo2nel percorso esatto.

## Dopo il risultato

Usare il nuovo inputsHash per vincolare il profilo persistente e la review coordinata, mantenendo separati dichiarazione, contenuti effettivi, custody, ammissione e autorità. Se un riferimento manca o non è risolvibile, correggere attraverso il relativo owner; nessun default inventato o credenziale scelta da un dossier storico.

Restano necessarie configurazione/provider/workload/TLS/rete/DB e nuova ammissione di generazione, review/authority finite quando richieste, backup/fencing/reconciliation, pubblicazione coordinata dei tre descrittori e route e degli scope/permessi stabili. Policy59 osservata: nessuna permission discovery nei9ruoli o138grant nominali letti; non è stata modificata. Nessun token o finestra da ottenere prima che il percorso sia pronto.

Poi UNA discovery Farmacie dal vero chatbot/MCP, con stessa idempotencyKey/requestId e provenienza/snapshot, adozione/pubblicazione governate, reboot/rotazione/fault e due client reali. Nessun webfetch/manualimport/Turtle o ontologia inventata sostitutivi.

Farmacie conserva asset9c502da5/job677480c8/profilof3061699 SUCCEEDED,61righe/10colonne,chiave ministeriale STRING e10campi OPEN. Non ripetere upload,profiling,budget,resume oacquisizione. M2/G5/G6/G7/D5–D7/E2E restano aperti. Nessun merge,release acceptance,subagente oautomazione. La vecchia cattura e tutti i predecessori restano consumati.

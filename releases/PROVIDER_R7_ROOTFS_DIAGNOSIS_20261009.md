> Lettura già eseguita con successo: snapshot cxgamg_7, ricevuta provider-r7-rootfs-target-20261009.json. Non ripeterla come preparazione separata. Stato corrente: [proposta R8](PROVIDER_R8_PREPARED_MOUNTPOINT_REVIEW_20261009.md). Il comando sottostante è storico.

# R7 — lettura delle differenze reali prima di qualsiasi recupero

R7 è consumato. La ricevuta riportata dall'operatore è conservata in `evidence/provider-r7-target-denial-20261009.json`; non è un'acquisizione indipendente dal VPS. Nessun esito di avvio riuscito è provato. I contatori storici sconosciuti di chiavi/lifecycle restano `null`.

| Ruolo | Evidenza concreta R7 | Limite della conclusione |
|---|---|---|
| southbound | `NODE_APPROVED_ROOTFS_DRIFT`, attestor `emit` linea 156: confronto con l'accettazione v1 fallito dopo l'osservazione | La vecchia eccezione non conserva il sigillo osservato né le voci diverse; non sappiamo ancora quali siano |
| adapter | `NODE_OBSERVATION_UNPROVEN`, lettura dello stato runc del peer, `run` linea 106 | Uscita non zero oppure output oltre limite; stderr e codice storico non conservati. Non prova un timeout né l'accettazione del suo rootfs |
| entrambi | `LOCAL_PRODUCER_DENIED` → `ADMISSION_PREPARATION_FAILED` → esito cohort non provato | Sono propagazioni degli errori precedenti, non cause aggiuntive |

Le directory mancanti di R6 non spiegano R7: il producer è stato eseguito. L'accettazione v1 riguarda il filesystem osservato durante export del container fermo; l'attestazione lo confronta dopo la preparazione runc. La fixture Docker precedente precreava la destinazione del bind e usava cwd `/`: non dimostrava l'equivalenza di queste fasi sul target. Nuove destinazioni/cwd, contenuti e metadati devono essere distinti attraverso il confronto. Il fallimento adapter potrebbe seguire la rimozione del peer southbound, ma l'ordine storico non è dimostrato.

Il lettore riusa l'immagine offline già presente, i file privati R7 e il sealer v1 effettivamente pubblicato; verifica i relativi hash. Registra guard vuoto, stato corrente dei due task, metadati containerd, generazioni shim e inventario runc. Confronta tutte le voci dell'immagine con il rootfs corrente: confronto v1 integrale e confronto diagnostico con la normalizzazione di immagine già documentata (solo contatori link delle directory e modalità della radice derivata dalla baseline). Nessuna normalizzazione cambia il sigillo accettato o concede autorità.

Se il rootfs non è montato, il lettore può eseguire un export del container fermo per mantenerne visibile il filesystem; il tar viene scartato senza estrazione. Al massimo un export per CID, nessun create/start/stop/delete/kill del container. Un eventuale arresto del client export riguarda soltanto quel subprocess di lettura. Nessuna lettura dei contenuti dei bind privati; i mount annidati sono rifiutati. Un nuovo snapshot privato conserva gli elenchi completi e la diagnosi; in console soltanto riepiloghi, percorsi interni all'immagine e metadati limitati. Guard, wrapper, accettazioni, input e journal preesistenti restano invariati. La lettura corrente non viene presentata come ricostruzione del sigillo storico perso.

PET consultati: Authorization v1.5 AUTH-05–12, nel contesto della Matrice v1.7. Nessun mandato, chiave, firma, broker operate, cleanup o nuova autorità di avvio. Nessuna installazione o ripetizione delle preparazioni già completate. La finestra di approvazione R7 non rende riutilizzabile il claim consumato.

Lettore: commit `4e57d2b8fb6f9ae081bca71650a43ee636fc31b5`, SHA256 `f496b2f20e1ac88c694ad16c0a3a3e529463297d8b10b565013903d6df3c55e4`. La verifica locale copre il caricamento delle sorgenti R7 reali, il sealer reale, l'intero flusso con risposte native simulate, differenze di contenuto/permessi, rifiuto di mount privati e gestione dell'export. Queste prove non sono osservazioni VPS. La consegna seguente usa l'eseguibile gh già presente fuori dal PATH e ricontrolla l'hash sotto root.

Eseguire il solo blocco seguente sul VPS. Riportare `OUF_R7_ROOTFS_READ_ONLY` e l'exit code; non incollare i file privati di confronto completi. Non ripetere i vecchi bootstrap R7.

```bash
(
  set -u
  set -o pipefail
  umask 077
  OUF_R7_READ_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [[ -x "$OUF_R7_READ_GH" ]] || { echo 'OUF_R7_ROOTFS_DELIVERY=EXISTING_GH_NOT_EXECUTABLE'; exit 1; }
  OUF_R7_READ_DIR="$(mktemp -d "$HOME/ouf-r7-rootfs-read.XXXXXXXX")" || exit 1
  "$OUF_R7_READ_GH" api 'repos/GioNob/ouf-deploy/contents/tools/semantic_target_review/read_r7_rootfs_differences.py?ref=4e57d2b8fb6f9ae081bca71650a43ee636fc31b5' --jq '.content' > "$OUF_R7_READ_DIR/read.b64" || { echo 'OUF_R7_ROOTFS_DELIVERY=DOWNLOAD_FAILED'; exit 1; }
  base64 --decode "$OUF_R7_READ_DIR/read.b64" > "$OUF_R7_READ_DIR/read.py" || exit 1
  printf '%s  %s\n' 'f496b2f20e1ac88c694ad16c0a3a3e529463297d8b10b565013903d6df3c55e4' "$OUF_R7_READ_DIR/read.py" | sha256sum -c - || exit 1
  sudo /usr/bin/python3.13 -I -B -c '
import hashlib, os, sys
p = sys.argv[1]
fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    raw = os.read(fd, 131073)
finally:
    os.close(fd)
if hashlib.sha256(raw).hexdigest() != "f496b2f20e1ac88c694ad16c0a3a3e529463297d8b10b565013903d6df3c55e4":
    raise SystemExit("OUF_R7_ROOTFS_DELIVERY=ROOT_HASH_MISMATCH")
sys.argv = [p]
exec(compile(raw, p, "exec"), {"__name__": "__main__", "__file__": p})
' "$OUF_R7_READ_DIR/read.py"
)
OUF_R7_ROOTFS_READ_EXIT=$?
printf 'OUF_R7_ROOTFS_READ_EXIT=%s\n' "$OUF_R7_ROOTFS_READ_EXIT"
```

Il prossimo recupero dipenderà dalle differenze osservate. Non è pronto alcun nuovo comando di avvio. Le accettazioni dei due CID non vengono sostituite da valori osservati o da fixture CI.

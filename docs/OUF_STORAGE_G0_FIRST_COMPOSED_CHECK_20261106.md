# Primo check composto delle quattro connessioni G0

La continuazione DB è riuscita secondo l'output operatore: tutte quattro le bozze sono presenti. È il momento del primo preflight del pacchetto esistente, non di un'altra preparazione o nuova qualifica di componente.

## Cosa eseguire

Il primo comando usa launch.py check del bundle9053aa38 già verificato e custodito. Verifica manifest, configurazioni S3/tre DB, rete, runtime/bucket,17ricevute, file locali delle credenziali e separazione dello scope. Legge le copie private già predisposte, non copia nuovi segreti e non contatta provider. Non scrive né consuma lo scope collect. Produce digest degli input/configurazioni, non dei contenuti delle credenziali.

Il secondo comando legge soltanto il JSON di pianificazione e la metadata lstat dei percorsi/antenati. Non segue symlink incontrati, non legge dati né directory di backup, non crea directory e non cambia permessi. Replica la sola condizione di ancestry usata dal collector root; non è ammissione della custodia o prova di capacità. Non viene eseguito statvfs, dato che questo passo risolve l'esistenza/custodia strutturale esatta e non ripete la scansione spazio già riuscita.

```bash
sudo /usr/bin/python3 -I -B -S \
  /var/lib/ouf-g0-network-preparation-20261106/package/launch.py check \
  /var/lib/ouf-g0-network-preparation-20261106/inputs/database-draft-continuation-20261106/package-input.review.json \
  --package-sha256 1e542f786ac1606cf72f273bc079eaa5b06b6bd22a210d615c10d13a9d9f8adf

sudo /usr/bin/python3 -I -B -S - <<'PY'
import json, os, stat
from pathlib import Path
p = Path("/var/lib/ouf-g0-network-preparation-20261106/inputs/database-draft-continuation-20261106/package-input.review.json")
try:
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not (stat.S_ISREG(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= 65536):
            raise ValueError()
        raw = os.read(fd, 65537)
        if len(raw) != s.st_size:
            raise ValueError()
    finally:
        os.close(fd)
    paths = json.loads(raw)["capacityPaths"]
    if set(paths) != {"source", "destination", "backup"}:
        raise ValueError()
    result = {}
    for purpose, value in paths.items():
        target = Path(value)
        if not target.is_absolute() or str(target) != value or ".." in target.parts:
            raise ValueError()
        compatible, reason = True, None
        for node in reversed([target, *target.parents]):
            try:
                info = node.lstat()
            except FileNotFoundError:
                reason = "PATH_NOT_PRESENT"
                break
            if not stat.S_ISDIR(info.st_mode):
                reason = "SYMLINK_OR_NOT_DIRECTORY"
                break
            if info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                compatible = False
        result[purpose] = {
            "exactDirectoryPresent": reason is None,
            "collectorAncestryCompatible": compatible and reason is None,
            "finding": reason or ("ANCESTRY_REVIEW_REQUIRED" if not compatible else None)
        }
    print(json.dumps({"schema": "ouf.storage-g0-capacity-path-precheck.v1",
        "paths": result, "filesModified": 0, "providerRequests": 0,
        "runtimeAuthorityIssued": False, "capacitySufficiencyProven": False,
        "g0Complete": False, "acceptanceCreditAdded": 0}, sort_keys=True))
except Exception:
    print(json.dumps({"status": "HELD", "reason": "LOCAL_PATH_PRECHECK_UNPROVEN",
        "filesModified": 0, "providerRequests": 0, "runtimeAuthorityIssued": False}))
PY
```

Restituire entrambi i JSON, senza altri file. Lo snippet è verificato sintatticamente; l'esecuzione target rimane operatore. Il collector e i test qualificati non sono stati modificati o rilanciati.

## Come leggere gli esiti

LOCAL_INPUTS_BOUND_EXTERNAL_ADMISSION_REQUIRED significa che il preflight locale ha vincolato i file validi. operatorInputsMissing è atteso per ACCESS,WRITERS,CAPACITY,CUSTODY,WINDOW e COLLECTION_DECISION_REFERENCE finché non esistono le relative evidenze/decisioni. Una lista mancante non deve essere colmata con dichiarazioni inventate. Il comando check può terminare0 pur con tali mancanze: non interpretarlo come ammissione operativa o accettazione.

PATH_NOT_PRESENT oppure ANCESTRY_REVIEW_REQUIRED individua un prerequisito concreto di collect. g0_host.capacity legge i tre percorsi dopo aver consumato il claim della raccolta: non lanciarla con un errore già noto. Non creare directory, cambiare owner, sostituire percorsi o attenuare il guard automaticamente. La preparazione delle aree può essere proposta concretamente dopo questa osservazione, senza toccare volumi o dati esistenti.

Il roster corrente e il join S3/DB sono risultati da ottenere con la raccolta ammessa, non dati da inventare per autorizzarla. I binding predisposti restano attesi, e il collector deve negare drift. La raccolta read-only non è cutover: niente stop writer, PUT/DELETE, endpoint switch o grant. Census operatore, profilo DB retained, custodia, capacità e finestra rimangono review specifiche; eventuali mancanze non diventano PASS perché il JSON è valido.

MiniPET39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Comandi senza raccolta provider o autorità runtime. L'istruzione di proseguire senza cercare backup esterno vale per la preparazione; non dispensa i criteri di accettazione o il passaggio governato.

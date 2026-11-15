"""Diagnostica in sola lettura dell'ultima epoca R3 dei due ruoli (sprint-01, start v7 HELD).

Uso (root, sola lettura):  sudo /usr/bin/python3.13 -I -B r3-epoch-diag.py [VERSIONE] [EPOCA]

Per ogni ruolo elenca i file della cartella dell'epoca (nome, tipo, modo, dimensione)
e, dai journal JSON, solo il campo `state` e i NOMI delle chiavi presenti, così si vede
fin dove è arrivato il preparer. Non stampa contenuti, hash di segreti o chiavi.
Nessuna scrittura, nessuna azione su container, nft o systemd.
"""
import json, os, stat, sys
from pathlib import Path

ROOT = Path("/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1")
JOURNALS = ("admission.json", "preexec.json", "deployment.json", "broker.json", "runtime.json",
            "epoch.json", "journal.json", "l2-binding.json", "runtime-cleanup.json")
SAFE_FIELDS = ("state", "failure", "namespaceOwned", "mode", "reason", "schema")


def emit(**kw):
    print(json.dumps(kw, sort_keys=True), flush=True)


def summary(path):
    try:
        value = json.loads(path.read_bytes())
    except Exception as exc:
        return {"parse": type(exc).__name__}
    if not isinstance(value, dict):
        return {"type": type(value).__name__}
    out = {"keys": sorted(value)}
    for k in SAFE_FIELDS:
        if k in value and (value[k] is None or isinstance(value[k], (str, bool, int))):
            out[k] = value[k]
    for k in ("driverHash", "containerGeneration", "namespaceInode"):
        if k in value:
            out[k + "Present"] = value[k] is not None
    return out


def main():
    if os.geteuid() != 0:
        print("eseguire con sudo", file=sys.stderr)
        return 2
    version = int(sys.argv[1]) if len(sys.argv) > 1 else 7
    epoch_arg = int(sys.argv[2]) if len(sys.argv) > 2 else None
    for role in ("adapter", "southbound"):
        cfg = json.loads((ROOT / "versions" / str(version) / "broker" / (role + ".json")).read_bytes())
        epochs = Path(cfg["registryRoot"]) / cfg["containerId"] / "epochs"
        epoch = epoch_arg or max(int(p.name) for p in epochs.iterdir() if p.name.isdigit())
        base = epochs / str(epoch)
        rows = []
        for path in sorted(base.rglob("*")):
            info = path.lstat()
            kind = "dir" if stat.S_ISDIR(info.st_mode) else "link" if stat.S_ISLNK(info.st_mode) else \
                "file" if stat.S_ISREG(info.st_mode) else "other"
            rows.append([str(path.relative_to(base)), kind, "%o" % stat.S_IMODE(info.st_mode),
                         info.st_size if kind == "file" else None])
        emit(role=role, epoch=epoch, step="files", files=rows)
        for path in sorted(base.rglob("*.json")):
            if path.name in JOURNALS or path.name.startswith("broker-denial"):
                emit(role=role, epoch=epoch, step="journal", file=str(path.relative_to(base)), **summary(path))
    emit(step="done", writes=0, containerLifecycleOperations=0, secretsPrinted=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

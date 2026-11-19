"""Diagnostica in sola lettura dell'ultima epoca R3 dei due ruoli (sprint-01, start v7 HELD).

Uso (root, sola lettura):  sudo /usr/bin/python3.13 -I -B r3-epoch-diag.py [VERSIONE] [EPOCA]

Per ogni ruolo elenca i file dell'epoca e i campi pubblici dei journal.
Per adapter.json include l'eventuale codice validato del diniego del driver.
Nessuna scrittura, nessuna azione su container, nft o systemd.
"""
import json, os, stat, sys
import runpy
from pathlib import Path

_common = runpy.run_path(str(Path(__file__).with_name('r3_common.py')))
adapter_journal = _common['adapter_journal']
driver_denial_fields = _common['driver_denial_fields']
fields = _common['fields']
read = _common['read']

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
    if len(sys.argv) > 3 or any(not arg.isascii() or not arg.isdecimal() or int(arg) < 1 for arg in sys.argv[1:]):
        print('argomenti non validi', file=sys.stderr)
        return 2
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
            if path == base / "adapter.json" and path.is_file() and not path.is_symlink():
                try:
                    value = adapter_journal(read(path), cfg["containerId"], epoch)
                    projection = fields(value, ("schema", "state", "failure")) | driver_denial_fields(value)
                except (ValueError, OSError) as exc:
                    projection = {"parse": type(exc).__name__}
                emit(role=role, epoch=epoch, step="journal", file="adapter.json", **projection)
            elif path.name in JOURNALS or path.name.startswith("broker-denial"):
                emit(role=role, epoch=epoch, step="journal", file=str(path.relative_to(base)), **summary(path))
    emit(step="done", writes=0, containerLifecycleOperations=0, secretsPrinted=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

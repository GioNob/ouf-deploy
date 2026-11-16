"""Diagnostica in sola lettura della guardia globale del lease R3 (start v8 HELD).

Uso:  sudo /usr/bin/python3.13 -I -B r3-guard-diag.py [VERSIONE]

Ripete i confronti di `validate_global_guard` (materialize_semantic_shared_faces.py)
tra i binding di rete firmati di ciascun ruolo e la configurazione kernel del
coordinatore usata dal template del preparer. Stampa solo nomi di interfacce,
nomi di tabelle, indirizzi IPv4 interni dei binding e hash. Nessuna scrittura.
"""
import hashlib, json, os, sys
from pathlib import Path

ROOT = Path("/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1/versions")


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def emit(**kw):
    print(json.dumps(kw, sort_keys=True), flush=True)


def main():
    if len(sys.argv) > 2 or any(not arg.isascii() or not arg.isdecimal() or int(arg) < 1 for arg in sys.argv[1:]):
        print('argomenti non validi', file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("eseguire con sudo", file=sys.stderr)
        return 2
    version = sys.argv[1] if len(sys.argv) > 1 else "8"
    for role in ("adapter", "southbound"):
        template = json.loads((ROOT / version / "documents" / role / "preparer-template.json").read_bytes())
        kernel = template["kernel"]
        emit(role=role, step="kernel", kernelKeys=sorted(kernel), tableName=kernel.get("tableName"),
             kernelSha256=sha(kernel), guardedInterfaces=kernel.get("guardedInterfaces"),
             existingInterfaces=kernel.get("existingInterfaces"),
             providerFlowSources=sorted({f.get("source") for f in kernel.get("providerFlows") or []}),
             staticFlowCount=len(kernel.get("staticFlows") or []))
        coordination = template.get("coordinationBinding")
        if isinstance(coordination, dict) and coordination.get("path"):
            try:
                owner = json.loads(Path(coordination["path"]).read_bytes())
                emit(role=role, step="coordinator", path=coordination["path"],
                     ownerKeys=sorted(owner) if isinstance(owner, dict) else type(owner).__name__,
                     ownerSha256=sha(owner), ownerKernelEqualsTemplate=(owner.get("kernel") == kernel)
                     if isinstance(owner, dict) else None)
            except Exception as exc:
                emit(role=role, step="coordinator", error=type(exc).__name__)
        transport = json.loads((ROOT / version / "documents" / role / "transport.json").read_bytes())
        for b in transport.get("networkBindings", []):
            guard = b.get("leaseGuard")
            row = dict(role=role, step="binding", bindingRef=b.get("bindingRef"), bridge=b.get("bridge"),
                       ipv4=b.get("ipv4"), leaseGuard=guard)
            if guard:
                row.update(guardHashMatchesKernel=guard.get("configurationHash") == sha(kernel),
                           guardTableMatches=guard.get("tableName") == kernel.get("tableName"),
                           bridgeGuarded=b.get("bridge") in (kernel.get("guardedInterfaces") or []),
                           bridgeInExisting=b.get("bridge") in (kernel.get("existingInterfaces") or []))
            emit(**row)
    emit(step="done", writes=0, secretsPrinted=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

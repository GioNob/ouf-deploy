"""Diagnostica in sola lettura del frame observer R3 (sprint-01, dopo lo start v5 HELD).

Uso (root, sola lettura):  sudo /usr/bin/python3.13 -I -B r3-frame-diag.py [VERSIONE] [EPOCA]

Ripete, fuori dal broker, i controlli STATICI che il frame observer installato fa
in `prepare` (custodia privata di policy e bundle, profilo OCI configurato,
custodia e hash delle sorgenti dei bind) e confronta l'insieme dei mount
effettivi di container Docker gia' in esecuzione con il loro OCI, come proxy
della vista dei mount che l'observer accetta. Stampa solo codici e metadati:
nessun contenuto di file, nessun segreto. Nessuna scrittura, nessuna azione su
container, nft o systemd.
"""
import hashlib, json, os, stat, subprocess, sys, time, types
from pathlib import Path

ROOT = Path("/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1/versions")
ROLES = ("southbound", "adapter")
OUT = []


def emit(**kw):
    OUT.append(kw)
    print(json.dumps(kw, sort_keys=True), flush=True)


def code(exc):
    return type(exc).__name__ + ":" + (str(exc.args[0]) if exc.args else "")


def sha_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def private_check(filename):
    """Same conditions as frame-observer main().private(), reporting the failing one."""
    filename = Path(filename)
    if not filename.is_absolute() or ".." in filename.parts:
        return "NOT_ABSOLUTE"
    for parent in filename.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            return "PARENT_CUSTODY:%s:uid=%d:mode=%o" % (parent, info.st_uid, stat.S_IMODE(info.st_mode))
    info = filename.parent.lstat()
    if info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        return "DIRECT_PARENT:gid=%d:mode=%o" % (info.st_gid, stat.S_IMODE(info.st_mode))
    info = filename.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 \
            or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 131072:
        return "FILE:reg=%s:uid=%d:gid=%d:nlink=%d:mode=%o:size=%d" % (
            stat.S_ISREG(info.st_mode), info.st_uid, info.st_gid, info.st_nlink,
            stat.S_IMODE(info.st_mode), info.st_size)
    return "OK"


def load_observer(source):
    ns = {"__name__": "ouf_frame_observer_diag", "__file__": str(source)}
    exec(compile(Path(source).read_bytes(), str(source), "exec"), ns)
    return ns, sys.modules["tools.observe_semantic_creation_frame"], sys.modules["tools.observe_semantic_mount_view"]


def role_checks(version, role, epoch_arg, cache):
    cfg_path = ROOT / str(version) / "broker" / (role + ".json")
    cfg = json.loads(cfg_path.read_bytes())
    cid = cfg["containerId"]
    frame = cfg["creationFrameObserverBinding"]
    emit(role=role, step="binding", containerId=cid[:12],
         python=sha_file(frame["python"]["path"]) == frame["python"]["sha256"],
         source=sha_file(frame["source"]["path"]) == frame["source"]["sha256"],
         configuration=sha_file(frame["configuration"]["path"]) == frame["configuration"]["sha256"])
    if "ns" not in cache:
        cache["ns"], cache["cf"], cache["mv"] = load_observer(frame["source"]["path"])
    ns, cf, mv = cache["ns"], cache["cf"], cache["mv"]
    epochs = Path(cfg["registryRoot"]) / cid / "epochs"
    epoch = epoch_arg or max(int(p.name) for p in epochs.iterdir() if p.name.isdigit())
    bundle_path = epochs / str(epoch) / "bundle" / "config.json"
    emit(role=role, step="private", epoch=epoch,
         configuration=private_check(frame["configuration"]["path"]),
         bundle=private_check(bundle_path) if bundle_path.exists() else "MISSING")
    policy = ns["decode"](Path(frame["configuration"]["path"]).read_bytes())
    emit(role=role, step="policy-keys", keys=sorted(policy), schema=policy.get("schema"))
    if not bundle_path.exists():
        return
    bundle = ns["decode"](bundle_path.read_bytes())
    started = time.monotonic()
    try:
        cf.configured_profile(
            bundle, policy["expectedOci"], policy["manifest"], policy["startup"], policy["approvedHooks"], ns["SCHEMA"])
        profile = "OK"
    except Exception as exc:
        profile = code(exc)
    emit(role=role, step="configured-profile", result=profile)
    sources = policy["sources"]
    try:
        cf.inputs(sources)
        exact = ns["canonical"]([{k: s[k] for k in ("source", "target", "readOnly")} for s in sources]) \
            == ns["canonical"](policy["manifest"]["mounts"])
        emit(role=role, step="source-inputs", result="OK", exactMountBinding=exact, count=len(sources))
    except Exception as exc:
        emit(role=role, step="source-inputs", result=code(exc))
    for slot, item in enumerate(sources):
        row = dict(role=role, step="source", slot=slot, target=item["target"])
        try:
            fd, info = mv.source_fd(item["source"], mv.Budget())
        except Exception as exc:
            row.update(custody=code(exc))
            try:
                st = os.lstat(item["source"])
                row.update(exists=True, nlink=st.st_nlink, reg=stat.S_ISREG(st.st_mode))
            except OSError as e:
                row.update(exists=False, errno=e.errno)
            emit(**row)
            continue
        try:
            row.update(custody="OK", uid=[info.st_uid, item["uid"]], gid=[info.st_gid, item["gid"]],
                       mode=["%o" % stat.S_IMODE(info.st_mode), "%o" % item["mode"]],
                       size=[info.st_size, item["maxBytes"]], nlink=info.st_nlink)
            try:
                cf.source_hash(item, fd, mv.attributes(info), mv.Budget())
                row.update(hash="OK")
            except Exception as exc:
                row.update(hash=code(exc))
        finally:
            os.close(fd)
        emit(**row)
    mounts = bundle.get("mounts") or []
    linux = bundle.get("linux", {})
    emit(role=role, step="oci-mounts", rootReadonly=bundle["root"].get("readonly", False),
         rootPath=bundle["root"]["path"],
         mounts=[[m["destination"], m.get("type"), ",".join(m.get("options") or [])] for m in mounts],
         masked=len(linux.get("maskedPaths") or []), readonly=len(linux.get("readonlyPaths") or []),
         staticSeconds=round(time.monotonic() - started, 3))
    try:
        mv.source_fd(bundle["root"]["path"], mv.Budget(), directory=True)
        emit(role=role, step="root-custody", result="OK")
    except Exception as exc:
        emit(role=role, step="root-custody", result=code(exc))


def proxy_checks(mv):
    """Mount view of running Docker containers vs their own OCI (observer's set rules)."""
    ids = subprocess.run(["/usr/bin/docker", "ps", "-q", "--no-trunc"], capture_output=True,
                         text=True, timeout=20).stdout.split()
    for cid in ids[:6]:
        meta = json.loads(subprocess.run(["/usr/bin/docker", "inspect", cid], capture_output=True,
                                         text=True, timeout=20).stdout)[0]
        pid, runtime = meta["State"]["Pid"], meta["HostConfig"].get("Runtime")
        bundle_path = Path("/run/containerd/io.containerd.runtime.v2.task/moby") / cid / "config.json"
        row = dict(step="proxy", name=meta["Name"].lstrip("/"), runtime=runtime)
        if not pid or not bundle_path.exists():
            row.update(result="NO_BUNDLE")
            emit(**row)
            continue
        bundle = json.loads(bundle_path.read_bytes())
        raw = Path("/proc/%d/mountinfo" % pid).read_bytes()
        try:
            rows = mv.mountinfo(raw)
        except Exception as exc:
            row.update(result="MOUNTINFO:" + code(exc), bytes=len(raw))
            emit(**row)
            continue
        targets = [r["target"] for r in rows]
        dup = sorted({t for t in targets if targets.count(t) > 1})
        mandatory = {m["destination"] for m in bundle.get("mounts") or []}
        linux = bundle.get("linux", {})
        allowed = mandatory | set(linux.get("maskedPaths") or []) | set(linux.get("readonlyPaths") or []) | {"/"}
        by = {r["target"]: r for r in rows}
        row.update(result="OK", mounts=len(rows), duplicates=dup,
                   unexplained=sorted(set(targets) - allowed), missing=sorted(mandatory - set(targets)),
                   rootRo=("ro" in by["/"]["options"]) if "/" in by else None,
                   ociRootRo=bundle.get("root", {}).get("readonly", False),
                   optionalOnBinds=sorted(r["target"] for r in rows
                                          if r["target"] in mandatory and r["optional"]))
        emit(**row)


def main():
    if os.geteuid() != 0:
        print("eseguire con sudo", file=sys.stderr)
        return 2
    version = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    epoch = int(sys.argv[2]) if len(sys.argv) > 2 else None
    cache = {}
    for role in ROLES:
        try:
            role_checks(version, role, epoch, cache)
        except Exception as exc:
            emit(role=role, step="aborted", error=code(exc))
    if "mv" in cache:
        try:
            proxy_checks(cache["mv"])
        except Exception as exc:
            emit(step="proxy-aborted", error=code(exc))
    emit(step="done", writes=0, containerLifecycleOperations=0, secretsPrinted=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

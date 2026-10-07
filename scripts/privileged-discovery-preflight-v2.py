#!/usr/bin/python3 -I
"""Fixed root read-only preflight for the selected OUF discovery deployment."""
import sys
sys.dont_write_bytecode = True
import hashlib, importlib.util, json, os, re, stat, subprocess, tempfile
from types import SimpleNamespace
from pathlib import Path
SNAPSHOTS=Path("/etc/ouf/deploy-snapshots")
PREFIXES=("semantic-provider-","semantic-runtime-","semantic-admission-","semantic-authority-")
RECEIPTS=("runtime-stage-receipt.json","stage-receipt.json","source-package-receipt.json","key-custody-receipt.json","trust-receipt.json")
FLAGS=("startAuthorized","runtimeRegistered","deploymentAuthorityProven","trustPolicyProvisioned","roleSigningAuthorized","infrastructureAuthorityComplete","runtimeFilesMounted","leaseLifecycleActivationReady","notReleaseAcceptance")
def safe_parents(path):
    for p in (path.parent,*path.parent.parents):
        s=p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o022:
            raise ValueError("UNSAFE_ANCESTOR")
def private_receipt_data(path):
    safe_parents(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or s.st_size>131072:
            raise ValueError("UNSAFE_RECEIPT")
        raw=os.read(fd,131073)
        if len(raw)!=s.st_size:raise ValueError("RECEIPT_DRIFT")
        def unique(items):
            d={}
            for k,v in items:
                if k in d:raise ValueError("DUPLICATE_KEY")
                d[k]=v
            return d
        v=json.loads(raw,object_pairs_hook=unique)
        if not isinstance(v,dict):raise ValueError("INVALID_RECEIPT")
        return raw,v
    finally:os.close(fd)
def read_receipt(path):
    raw,v=private_receipt_data(path)
    return {"receiptName":path.name,"sha256":hashlib.sha256(raw).hexdigest(),"flags":{k:v[k] for k in FLAGS if type(v.get(k)) is bool}}

def command(args,limit=2097152):
    with tempfile.TemporaryFile() as out:
        p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.DEVNULL,timeout=15,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
        out.seek(0);raw=out.read(limit+1)
    if p.returncode or len(raw)>limit:raise ValueError("READ_COMMAND_FAILED")
    return json.loads(raw)

# Reuse the original native read-only inventory from Gateway 1d75e404; never apply/reconcile.
def runtime_installer(args):
    path = args.stage_root.parent / 'source/scripts/transition_semantic_runtime_guard.py'
    if not args.stage_root.is_absolute() or '..' in args.stage_root.parts \
            or not re.fullmatch('[0-9a-f]{64}', args.installer_sha256):
        raise ValueError('explicit sealed source required')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe source ancestor')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 \
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 \
                or info.st_size > 131072:
            raise ValueError('unsafe source')
        raw = os.read(fd, 131073)
    finally:
        os.close(fd)
    if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != args.installer_sha256:
        raise ValueError('installer source drift')
    spec = importlib.util.spec_from_file_location('sealed_readiness_installer', path)
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def runtime_collect(args, installation):
    """Reuse the sealed installer's independent custody checks under its lock."""
    if os.geteuid() != 0 or not re.fullmatch('[0-9a-f]{40}', args.stage_source_commit):
        raise ValueError('root and explicit source required')
    stage_args = SimpleNamespace(stage_root=args.stage_root,
                                 stage_source_commit=args.stage_source_commit)
    def observe():
        prepared = installation.stage(stage_args)
        g, receipt, artifacts, conf, intent, roots, original, gu, unit, drop, _ = prepared
        journal = g.read(Path(conf['journalFile']))
        if journal.get('schema') != 'ouf.semantic-runtime-transition.v1' \
                or journal.get('state') != 'RUNTIME_EMPTY' \
                or journal.get('transactionId') != conf['transactionId'] \
                or journal.get('configurationHash') != receipt['configurationHash'] \
                or journal.get('stageReceiptHash') != g.digest(g.private(args.stage_root/'runtime-stage-receipt.json')) \
                or journal.get('startAuthorized') is not False:
            raise ValueError('incomplete or foreign journal')
        installation.independent(g, receipt, intent, roots, original, conf)
        tables = g.tables(conf)
        if g.footprint(tables) != conf['expectedFootprint'] or not g.sets_empty(tables) \
                or g.digest(g.encoded(g.stable(tables, True))) != journal.get('leaseStructureHash'):
            raise ValueError('runtime or lease structure drift')
        for path, name in ((unit, 'guard.service'), (drop, 'docker-drop-in.conf')):
            if g.private(path) != artifacts[name]:
                raise ValueError('installed artifact drift')
        installation.loaded(g, receipt, artifacts, original, gu, unit, drop)
        manifest = g.read(roots['manifest_root']/'stopped-manifest.json')
        kernel = conf['kernel']
        # Summaries deliberately omit endpoint URLs, credentials, env, mounts,
        # command lines and raw systemd/Docker/nft readbacks.
        result = {
            'schema': 'ouf.semantic-runtime-readiness.v1',
            'stageSourceCommit': args.stage_source_commit,
            'configurationHash': receipt['configurationHash'],
            'journalHash': g.digest(g.private(Path(conf['journalFile']))),
            'leaseStructureHash': journal['leaseStructureHash'],
            'runtimeState': 'RUNTIME_EMPTY', 'candidateCount': len(manifest['containers']),
            'candidatesNeverStarted': True, 'runtimeCustodyVerified': True,
            'staticPurposes': sorted({f['purpose'] for f in kernel['staticFlows']}),
            'staticFlowCount': len(kernel['staticFlows']),
            'providerFlowCount': len(kernel['providerFlows']),
            'providerSetsEmpty': True, 'guardProfile': 'EMPTY_ONLY',
            'guardedInterfaceCount': len(kernel['guardedInterfaces']),
            'excludedSharedInterfaceCount': len(kernel['existingInterfaces']),
            'startupReady': False, 'startAuthorized': False,
            'activeLeaseLifecycleReady': False,
            'unprovenGates': ['INFRASTRUCTURE_AUTHORITY', 'SHARED_FACE_SOURCE_ENFORCEMENT',
                'LIVE_NAMESPACE_ADDRESS_BINDING', 'PACKET_SPOOF_BYPASS_IPV6',
                'OIDC_PURPOSE_TLS_REVOCATION_ADMISSION', 'ACTIVE_LEASE_GUARD_COORDINATION',
                'REAL_REBOOT'],
            'readOnly': True, 'providerCalls': 0, 'dnsCalls': 0,
            'notReleaseAcceptance': True, 'noSecretsPrinted': True,
            'atomicSnapshotProven': False,
        }
        return result, g.digest(g.encoded({'receipt': receipt, 'conf': conf, 'intent': intent,
            'journal': journal, 'manifest': manifest, 'original': original}))

    # Read before acquiring the existing lock only to obtain its sealed path;
    # repeat every custody check twice under the lock and reject drift.
    prepared = installation.stage(stage_args)
    guard, conf = prepared[0], prepared[3]
    fd = guard.lock(Path(conf['lockFile']))
    try:
        first, seal = observe()
        if installation.stage(stage_args)[3]['lockFile'] != conf['lockFile']:
            raise ValueError('common lock drift')
        second, again = observe()
        if first != second or seal != again:
            raise ValueError('custody changed across reads')
        first['stableAcrossReads'] = True
        return first
    finally:
        os.close(fd)


def selected_runtime_readiness():
    stage=SNAPSHOTS/"semantic-runtime-transition-stage-20261003-160211"/"prepared"
    raw,receipt=private_receipt_data(stage/"runtime-stage-receipt.json")
    expected="ab4476f03d11f6325227b43b786be4a2e4d222b0ec8be29d4f119f354332402f"
    if hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError("SELECTED_RUNTIME_RECEIPT_DRIFT")
    args=SimpleNamespace(stage_root=stage,stage_source_commit=receipt["sourceCommit"],
        installer_sha256=receipt["sourceHashes"]["transition_semantic_runtime_guard.py"])
    return runtime_collect(args,runtime_installer(args))

def collect():
    report={"schema":"ouf.discovery.privileged-preflight.v2","privilegedReadAvailable":True,"readOnly":True,"keyFilesRead":False,"configurationWrites":0,"containerLifecycleOperations":0,"firewallWrites":0,"releaseApplied":False,"startAuthorized":False,"secretValuesPrinted":False,"receipts":[],"mounts":[]}
    for name in ("ouf-semantic","ouf-semantic-provider","ouf-semantic-southbound"):
        item=command(["/usr/bin/docker","inspect",name])[0]
        for m in item.get("Mounts",[]):
            row={"container":name,"destination":m["Destination"],"readOnly":not m["RW"]}
            try:
                s=os.lstat(m["Source"]);row.update(sourcePresent=True,uid=s.st_uid,gid=s.st_gid,mode=oct(stat.S_IMODE(s.st_mode)),symlink=stat.S_ISLNK(s.st_mode),regularFile=stat.S_ISREG(s.st_mode),directory=stat.S_ISDIR(s.st_mode))
            except OSError:row["sourcePresent"]=False
            report["mounts"].append(row)
    if SNAPSHOTS.is_dir() and not SNAPSHOTS.is_symlink():
        safe_parents(SNAPSHOTS/"unused")
        dirs=sorted(p for p in SNAPSHOTS.iterdir() if p.name.startswith(PREFIXES))
        if len(dirs)>256:raise ValueError("SNAPSHOT_INVENTORY_UNBOUNDED")
        for folder in dirs:
            if folder.is_symlink() or not folder.is_dir():continue
            for parent in (folder,folder/"prepared"):
                if parent.is_symlink() or not parent.is_dir():continue
                for name in RECEIPTS:
                    path=parent/name
                    if not path.exists() and not path.is_symlink():continue
                    try:row=read_receipt(path);row["snapshot"]=folder.name;report["receipts"].append(row)
                    except (OSError,ValueError):report["receipts"].append({"snapshot":folder.name,"receiptName":name,"readStatus":"UNSAFE_OR_UNAVAILABLE"})
    nft=command(["/usr/sbin/nft","--json","list","ruleset"])
    tables=[];sets=[]
    for item in nft.get("nftables",[]):
        t=item.get("table")
        if t and "semantic" in t.get("name",""):tables.append({"family":t.get("family"),"name":t.get("name")})
        s=item.get("set")
        if s and "semantic" in s.get("table",""):sets.append({"table":s.get("table"),"name":s.get("name"),"elementCount":len(s.get("elem",[]))})
    report["semanticTables"]=tables;report["semanticSets"]=sets
    try:
        report["runtimeReadiness"]=selected_runtime_readiness()
    except Exception:
        report["runtimeReadiness"]={"status":"BLOCKED","readOnly":True,"startAuthorized":False,"noRawOutput":True}
    report["custodyAcceptanceProven"]=False
    report["status"]="READ_ONLY_OBSERVATION"
    return report
def main():
    if os.geteuid()!=0 or len(sys.argv)!=1:
        print("OUF_DISCOVERY_PRIVILEGED_PREFLIGHT=BLOCKED ROOT_AND_NO_ARGUMENTS_REQUIRED")
        return 1
    try:
        print("OUF_DISCOVERY_PRIVILEGED_PREFLIGHT="+json.dumps(collect(),sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,subprocess.TimeoutExpired):
        print("OUF_DISCOVERY_PRIVILEGED_PREFLIGHT=BLOCKED READ_FAILED NO_RAW_OUTPUT=true")
        return 1
if __name__=="__main__":raise SystemExit(main())

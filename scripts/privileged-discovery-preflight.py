#!/usr/bin/python3 -I
"""Fixed root read-only preflight for the selected OUF discovery deployment."""
import sys
sys.dont_write_bytecode = True
import hashlib, json, os, stat, subprocess, tempfile
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
def read_receipt(path):
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
        return {"receiptName":path.name,"sha256":hashlib.sha256(raw).hexdigest(),"flags":{k:v[k] for k in FLAGS if type(v.get(k)) is bool}}
    finally:os.close(fd)
def command(args,limit=2097152):
    with tempfile.TemporaryFile() as out:
        p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.DEVNULL,timeout=15,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
        out.seek(0);raw=out.read(limit+1)
    if p.returncode or len(raw)>limit:raise ValueError("READ_COMMAND_FAILED")
    return json.loads(raw)
def collect():
    report={"schema":"ouf.discovery.privileged-preflight.v1","privilegedReadAvailable":True,"readOnly":True,"keyFilesRead":False,"configurationWrites":0,"containerLifecycleOperations":0,"firewallWrites":0,"releaseApplied":False,"startAuthorized":False,"secretValuesPrinted":False,"receipts":[],"mounts":[]}
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

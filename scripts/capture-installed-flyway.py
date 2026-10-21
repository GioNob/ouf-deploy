#!/usr/bin/env python3
"""Export only installed Java libraries/migrations for hosted compatibility tests.
No container exec, service operation, DB access, environment output or key read.
"""
import hashlib, json, os, subprocess, tempfile, zipfile
from pathlib import Path
IMAGE="sha256:f6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6"
CID="7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147"
def call(argv):
    p=subprocess.run(argv,capture_output=True,timeout=30)
    if p.returncode:raise RuntimeError("METADATA_OR_PACKAGE_COPY_FAILED")
    return p.stdout
def inspect():
    values=json.loads(call(["docker","inspect","--type","container",CID]))
    if len(values)!=1:raise RuntimeError("EXACT_CONTAINER_REQUIRED")
    c=values[0]
    if c["Id"]!=CID or c["Image"]!=IMAGE or not c["State"]["Running"]:
        raise RuntimeError("INSTALLED_APPLICATION_BINDING_CHANGED")
    return {k:c[k] for k in ("Id","Image","Config","HostConfig","Mounts","NetworkSettings")} | {
        "generation":{k:c["State"][k] for k in ("Pid","StartedAt","Running")}}
def main():
    os.umask(0o077)
    before=inspect()
    root=Path("old-flyway-package")
    root.mkdir(mode=0o700)
    (root/"lib").mkdir(mode=0o700);(root/"migrations").mkdir(mode=0o700)
    frozen=json.loads(Path("evidence/discovery-remediated-application-qualification-20261009.json").read_bytes())["migrationPlan"]["receipt"]["installedMigrationDigests"]
    libs={};migrations={}
    with tempfile.TemporaryDirectory(prefix="ouf-installed-java-read-") as tmp:
        jar=Path(tmp)/"application.jar"
        call(["docker","cp",CID+":/app/application.jar",str(jar)])
        if jar.stat().st_size>268435456:raise RuntimeError("PACKAGE_SIZE_UNBOUNDED")
        jar_hash=hashlib.sha256(jar.read_bytes()).hexdigest()
        with zipfile.ZipFile(jar) as z:
            names=z.namelist()
            if len(set(names))!=len(names):raise RuntimeError("DUPLICATE_PACKAGE_ENTRY")
            selected=[n for n in names if (n.startswith("BOOT-INF/lib/") and n.endswith(".jar")) or (n.startswith("BOOT-INF/classes/db/migration/") and n.endswith(".sql"))]
            if len(selected)>256 or sum(z.getinfo(n).file_size for n in selected)>268435456:
                raise RuntimeError("EXPORTED_PACKAGE_UNBOUNDED")
            for name in selected:
                leaf=Path(name).name
                if name.startswith("BOOT-INF/lib/"):
                    if name!="BOOT-INF/lib/"+leaf:raise RuntimeError("NESTED_LIBRARY_ENTRY")
                    target=root/"lib"/leaf;listing=libs
                else:
                    if name!="BOOT-INF/classes/db/migration/"+leaf:raise RuntimeError("NESTED_MIGRATION_ENTRY")
                    target=root/"migrations"/leaf;listing=migrations
                raw=z.read(name);target.write_bytes(raw)
                listing[leaf]=hashlib.sha256(raw).hexdigest()
        if migrations!=frozen or not any(n.startswith("flyway-core-") for n in libs):
            raise RuntimeError("INSTALLED_MIGRATION_OR_FLYWAY_INVENTORY_DRIFT")
    if inspect()!=before:raise RuntimeError("LIVE_BINDINGS_CHANGED_DURING_COPY")
    report={"schema":"ouf.discovery.installed-flyway-capture.v1","status":"INSTALLED_LIBRARY_BYTES_CAPTURED",
        "containerId":CID,"imageId":IMAGE,"applicationJarSha256":jar_hash,
        "libraries":libs,"migrations":migrations,"generation":before["generation"],
        "databaseAccesses":0,"containerLifecycleOperations":0,"dockerExecCalls":0,"privateKeysRead":0,
        "privateValuesPrinted":False,"commonLockAcquired":False,"releaseAcceptance":False}
    (root/"capture-receipt.json").write_text(json.dumps(report,indent=2)+"\n")
    print("OUF_INSTALLED_FLYWAY_CAPTURE="+json.dumps(report,sort_keys=True))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Read the exact installed application JAR for isolated full-runtime compatibility.
No DB access, container exec/lifecycle, private key read or environment output.
"""
import hashlib, json, os, subprocess, tempfile, zipfile
from pathlib import Path

CID = "7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147"
IMAGE = "sha256:f6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6"
JAR_HASH = "32df2976c0c240d093b4769e296a7411f02548e14ed17b542b6db00a78901bc2"

def call(args):
    result = subprocess.run(args, capture_output=True, timeout=30)
    if result.returncode: raise RuntimeError("EXACT_INSTALLED_PACKAGE_READ_FAILED")
    return result.stdout

def inspect():
    values = json.loads(call(["docker", "inspect", "--type", "container", CID]))
    if len(values) != 1: raise RuntimeError("EXACT_CONTAINER_REQUIRED")
    value = values[0]
    if value["Id"] != CID or value["Image"] != IMAGE or not value["State"]["Running"]:
        raise RuntimeError("INSTALLED_APPLICATION_BINDING_CHANGED")
    return {key: value[key] for key in ("Id", "Image", "Config", "HostConfig", "Mounts", "NetworkSettings")} | {
        "generation": {key: value["State"][key] for key in ("Pid", "StartedAt", "Running")}}

def main():
    os.umask(0o077)
    before = inspect()
    root = Path("old-application-package"); root.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="ouf-installed-application-read-") as directory:
        jar = Path(directory) / "application.jar"
        call(["docker", "cp", CID + ":/app/application.jar", str(jar)])
        if jar.stat().st_size > 268435456: raise RuntimeError("PACKAGE_SIZE_UNBOUNDED")
        raw = jar.read_bytes()
        if hashlib.sha256(raw).hexdigest() != JAR_HASH: raise RuntimeError("INSTALLED_JAR_BYTES_CHANGED")
        frozen = json.loads(Path("evidence/discovery-remediated-application-qualification-20261009.json").read_bytes())["migrationPlan"]["receipt"]["installedMigrationDigests"]
        with zipfile.ZipFile(jar) as archive:
            if len(set(archive.namelist())) != len(archive.namelist()): raise RuntimeError("DUPLICATE_PACKAGE_ENTRY")
            names = [name for name in archive.namelist() if name.startswith("BOOT-INF/classes/db/migration/") and name.endswith(".sql")]
            actual = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest() for name in names}
            if actual != frozen: raise RuntimeError("INSTALLED_MIGRATION_INVENTORY_CHANGED")
        if inspect() != before: raise RuntimeError("LIVE_BINDINGS_CHANGED_DURING_COPY")
        (root / "application.jar").write_bytes(raw)
    receipt = {"schema": "ouf.discovery.installed-application-capture.v1", "status": "EXACT_INSTALLED_APPLICATION_BYTES_CAPTURED", "containerId": CID,
               "imageId": IMAGE, "applicationJarSha256": JAR_HASH, "generation": before["generation"], "databaseAccesses": 0,
               "containerLifecycleOperations": 0, "dockerExecCalls": 0, "privateKeysRead": 0, "privateValuesPrinted": False,
               "commonLockAcquired": False, "releaseAcceptance": False}
    (root / "capture-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("OUF_INSTALLED_APPLICATION_CAPTURE=" + json.dumps(receipt))

if __name__ == "__main__": main()

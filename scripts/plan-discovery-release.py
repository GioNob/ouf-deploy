#!/usr/bin/env python3
"""Compare installed Semantic migrations with the exact discovery candidate; no target writes."""
import hashlib
import json
import subprocess
import tempfile
import zipfile
from pathlib import Path

REVISION = "3422a058bbfc45096f14ac7ea3243054ed437652"
def command(argv):
    p = subprocess.run(argv, capture_output=True, timeout=30)
    if p.returncode:
        raise RuntimeError("READ_COMMAND_FAILED")
    return p.stdout
def digest(data):
    return hashlib.sha256(data).hexdigest()

report = {"schema": "ouf.discovery.release-plan.v1", "candidateRevision": REVISION,
          "configurationWrites": 0, "containerLifecycleOperations": 0,
          "secretValuesPrinted": False, "releaseApplied": False}
try:
    if command(["git", "-C", "semantic-source", "rev-parse", "HEAD"]).decode().strip() != REVISION:
        raise RuntimeError("CANDIDATE_REVISION_MISMATCH")
    live = json.loads(command(["docker", "inspect", "ouf-semantic"]))[0]
    report["liveImageId"] = live["Image"]
    report["liveRunning"] = bool(live["State"]["Running"])
    report["liveUser"] = live["Config"].get("User")
    report["mounts"] = [{"destination": m["Destination"], "readOnly": not m["RW"], "type": m["Type"]} for m in live["Mounts"]]
    report["networks"] = sorted(live["NetworkSettings"]["Networks"])
    env = dict(x.split("=", 1) for x in live["Config"].get("Env", []) if "=" in x)
    report["configuredBindingNames"] = sorted(k for k in env if k.startswith("OUF_"))
    report["providerEnabledExplicitly"] = env.get("OUF_SCHEMA_GOV_ENABLED", "").lower() == "true"
    report["gatewayOriginExplicitlyConfigured"] = bool(env.get("OUF_SCHEMA_GOV_GATEWAY_BASE_URL"))
    report["providerWorkloadAuthExplicitlyEnabled"] = env.get("OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED", "").lower() == "true"
    with tempfile.TemporaryDirectory(prefix="ouf-discovery-plan-") as tmp:
        jar = Path(tmp) / "live.jar"
        command(["docker", "cp", "ouf-semantic:/app/application.jar", str(jar)])
        with zipfile.ZipFile(jar) as z:
            prefix = "BOOT-INF/classes/db/migration/"
            installed = {Path(n).name: digest(z.read(n)) for n in z.namelist() if n.startswith(prefix) and n.endswith(".sql")}
    candidate = {p.name: digest(p.read_bytes()) for p in Path("semantic-source/src/main/resources/db/migration").glob("*.sql")}
    if not installed or not candidate:
        raise RuntimeError("MIGRATION_INVENTORY_MISSING")
    changed = sorted(n for n in installed if candidate.get(n) != installed[n])
    additions = sorted(set(candidate) - set(installed))
    report["installedMigrationDigests"] = installed
    report["candidateMigrationDigests"] = candidate
    report["existingMigrationsChangedOrRemoved"] = changed
    report["additiveMigrations"] = additions
    report["migrationCompatibility"] = "BLOCKED" if changed or additions != ["V10__discovery_request_idempotency.sql"] else "EXISTING_BYTES_IDENTICAL_V10_ADDITIVE"
    report["status"] = "PLAN_ONLY"
except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired, zipfile.BadZipFile) as exc:
    report["status"] = "BLOCKED"
    report["reason"] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
print("OUF_DISCOVERY_RELEASE_PLAN=" + json.dumps(report, sort_keys=True))
if report["status"] == "BLOCKED":
    raise SystemExit(1)
